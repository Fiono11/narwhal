// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Definition of a MobileCoin transaction and a MobileCoin TxOut

use std::{fmt, array::TryFromSliceError};
use curve25519_dalek::traits::Identity;
use mc_account_keys::{PublicAddress, AccountKey, DEFAULT_SUBADDRESS_INDEX};
use mc_crypto_digestible::{Digestible, MerlinTranscript};
use mc_crypto_keys::{tx_hash::TxHash, CompressedRistrettoPublic, RistrettoPublic, RistrettoPrivate};
use mc_crypto_ring_signature::{KeyImage, get_tx_out_shared_secret, onetime_keys::{create_shared_secret, create_tx_out_public_key, create_tx_out_target_key, recover_onetime_private_key}, ReducedTxOut, CompressedCommitment, TriptychSignature, Sign, Scalar, KeyGen, RistrettoPoint};
use mc_transaction_types::{MaskedAmount, Amount, constants::RING_SIZE};
use mc_util_from_random::FromRandom;
use rand_core::{RngCore, CryptoRng};
use serde::{Deserialize, Serialize};
use prost::Message;
use zeroize::Zeroize;
use mc_common::Hash;

use crate::tx_error::{TxOutConversionError, ViewKeyMatchError, NewTxError};

/// A CryptoNote-style transaction.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Message, Digestible)]
pub struct Tx {
    /// The transaction contents.
    #[prost(message, required, tag = "1")]
    pub prefix: TxPrefix,

    /// The transaction signature.
    #[prost(message, required, tag = "2")]
    pub signature: TriptychSignature,
}

impl fmt::Display for Tx {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.tx_hash())
    }
}

impl Tx {
    /// Compute a 32-byte hash from all of the contents of a Tx
    pub fn tx_hash(&self) -> TxHash {
        TxHash::from(self.digest32::<MerlinTranscript>(b"mobilecoin-tx"))
    }

    /// Key image "spent" by this transaction.
    pub fn key_images(&self) -> KeyImage {
        self.signature.key_image()
    }
    
    /// Output public keys contained in this transaction.
    pub fn output_public_keys(&self) -> Vec<CompressedRistrettoPublic> {
        self.prefix
            .outputs
            .iter()
            .map(|tx_out| tx_out.public_key)
            .collect()
    }
}

/// TxPrefix is the Tx struct without the signature.  It is used to
/// calculate the prefix hash for signing and verifying.
///
/// Note: If you add something here, consider if it should be added to the
/// TxSummary also for hardware wallet visibility.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize, Message, Digestible)]
pub struct TxPrefix {
    /// List of inputs to the transaction.
    #[prost(message, repeated, tag = "1")]
    pub inputs: Vec<u64>,

    /// List of outputs from the transaction.
    #[prost(message, repeated, tag = "2")]
    pub outputs: Vec<TxOut>,
}

impl TxPrefix {
    /// Create a new TxPrefix.
    ///
    /// # Arguments:
    /// * `inputs` - Inputs spent by the transaction.
    /// * `outputs` - Outputs created by the transaction.
    pub fn new(
        inputs: Vec<u64>,
        outputs: Vec<TxOut>,
    ) -> TxPrefix {
        TxPrefix {
            inputs,
            outputs,
        }
    }

    /// Digestible-crate hash of `self` using Merlin
    pub fn hash(&self) -> TxHash {
        TxHash::from(self.digest32::<MerlinTranscript>(b"mobilecoin-tx-prefix"))
    }

    /// Get all output commitments.
    pub fn output_commitments(&self) -> Result<Vec<&CompressedCommitment>, TxOutConversionError> {
        self.outputs
            .iter()
            .map(|output| output.get_masked_amount().map(|ma| ma.commitment()))
            .collect()
    }
}

/// An "input" to a transaction.
#[derive(Clone, Deserialize, Digestible, Eq, PartialEq, Message, Serialize, Zeroize)]
pub struct TxIn {
    /// A "ring" of outputs containing the single output that is being spent.
    /// It would be nice to use [TxOut; RING_SIZE] here, but Prost only works
    /// with Vec.
    #[prost(message, repeated, tag = "1")]
    pub ring: Vec<u64>,
}

/// An output created by a transaction.
#[derive(Clone, Deserialize, Digestible, Eq, Hash, Message, PartialEq, Serialize, Zeroize)]
pub struct TxOut {
    /// The amount being sent.
    #[prost(oneof = "MaskedAmount", tags = "1, 6")]
    #[digestible(name = "amount")]
    pub masked_amount: Option<MaskedAmount>,

    /// The one-time public address of this output.
    #[prost(message, required, tag = "2")]
    pub target_key: CompressedRistrettoPublic,

    /// The per output tx public key
    #[prost(message, required, tag = "3")]
    pub public_key: CompressedRistrettoPublic,
}

impl TxOut {
    /// Creates a TxOut that sends `value` to `recipient`, with a custom memo
    /// attached. The memo is produced by a callback function which is
    /// passed the value and tx_public_key.
    ///
    /// # Arguments
    /// * `block_version` - Structural rules to target
    /// * `amount` - Amount contained within the TxOut
    /// * `recipient` - Recipient's address.
    /// * `tx_private_key` - The transaction's private key
    ///   MemoPayload, or a NewMemo error
    pub fn new(
        amount: Amount,
        recipient: &PublicAddress,
        tx_private_key: &RistrettoPrivate,
    ) -> Result<Self, NewTxError> {
        let target_key = create_tx_out_target_key(tx_private_key, recipient).into();
        let public_key = create_tx_out_public_key(tx_private_key, recipient.spend_public_key());

        let shared_secret = create_shared_secret(recipient.view_public_key(), tx_private_key);

        let masked_amount = Some(MaskedAmount::new(amount, &shared_secret)?);

        Ok(TxOut {
            masked_amount,
            target_key,
            public_key: public_key.into(),
        })
    }

    /// A merlin-based hash of this TxOut.
    pub fn hash(&self) -> Hash {
        self.digest32::<MerlinTranscript>(b"mobilecoin-txout")
    }

    /// Try to establish ownership of this TxOut, using the view private key.
    ///
    /// Arguments:
    /// * view_private_key: The account view private key for the (possible)
    ///   owner
    ///
    /// Returns:
    /// * An (unmasked) Amount
    /// * The shared secret
    /// Or, an error if recovery failed.
    pub fn view_key_match(
        &self,
        view_private_key: &RistrettoPrivate,
    ) -> Result<(Amount, RistrettoPublic), ViewKeyMatchError> {
        // Reconstruct compressed commitment based on our view key.
        // The first step is reconstructing the TxOut shared secret
        let public_key = RistrettoPublic::try_from(&self.public_key)?;

        let tx_out_shared_secret = get_tx_out_shared_secret(view_private_key, &public_key);

        let (amount, _scalar) = self
            .masked_amount
            .as_ref()
            .ok_or(ViewKeyMatchError::UnknownMaskedAmountVersion)?
            .get_value(&tx_out_shared_secret)?;

        Ok((amount, tx_out_shared_secret))
    }

    /// Get the masked amount field, which is expected to be present in some
    /// version. Maps to a conversion error if the masked amount field is
    /// missing
    pub fn get_masked_amount(&self) -> Result<&MaskedAmount, TxOutConversionError> {
        self.masked_amount
            .as_ref()
            .ok_or(TxOutConversionError::UnknownMaskedAmountVersion)
    }

    /// Get the masked amount field, which is expected to be present in some
    /// version. Maps to a conversion error if the masked amount field is
    /// missing
    pub fn get_masked_amount_mut(&mut self) -> Result<&mut MaskedAmount, TxOutConversionError> {
        self.masked_amount
            .as_mut()
            .ok_or(TxOutConversionError::UnknownMaskedAmountVersion)
    }

    /// Check if a TxOut is equal to another TxOut, except possibly in the
    /// masked_amount. This is used in MCIP #42 partial fills rules
    /// verification.
    pub fn eq_ignoring_amount(&self, other: &TxOut) -> bool {
        let mut this = self.clone();
        this.masked_amount = None;
        let mut other = other.clone();
        other.masked_amount = None;
        this == other
    }
}

impl TryFrom<&TxOut> for ReducedTxOut {
    type Error = TxOutConversionError;
    fn try_from(src: &TxOut) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: src.public_key,
            target_key: src.target_key,
            commitment: *src.get_masked_amount()?.commitment(),
        })
    }
}

/// Creates a transaction that sends the full value of `tx_out` to a single
/// recipient.
///
/// # Arguments:
/// * `tx_out` - The TxOut that will be spent.
/// * `sender` - The owner of `tx_out`.
/// * `recipient` - The recipient of the new transaction.
/// * `rng` - The randomness used by this function
pub fn create_transaction<R: RngCore + CryptoRng>(
    tx_out: &TxOut,
    sender: &AccountKey,
    recipient: &PublicAddress,
    amount: u64,
    rng: &mut R,
) -> Tx {
    // Get the output value.
    let tx_out_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
    let shared_secret = get_tx_out_shared_secret(sender.view_private_key(), &tx_out_public_key);
    let (amount, _blinding) = tx_out
        .get_masked_amount()
        .unwrap()
        .get_value(&shared_secret)
        .unwrap();

    let spend_private_key = sender.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX);
    let tx_out_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
    let onetime_private_key = recover_onetime_private_key(
        &tx_out_public_key,
        sender.view_private_key(),
        &spend_private_key,
    );

    let mut inputs = Vec::new();

    for i in 0..RING_SIZE {
        inputs.push(i as u64);
    }

    let tx_private_key = RistrettoPrivate::from_random(rng);

    let output = TxOut::new(amount, recipient, &tx_private_key).unwrap();

    let prefix = TxPrefix::new(inputs, vec![output]);

    let mut R: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); RING_SIZE];
    let mut x: Scalar = Scalar::one();

    for i in 0..RING_SIZE {
        let (sk, pk) = KeyGen();
        R[i] = pk;

        if i == 0 {
            x = sk;
        }
    }

    let signature = Sign(&x, "msg", &R);

    Tx { prefix, signature }
}

#[cfg(test)]
mod tests {
    use crate::{
        get_tx_out_shared_secret,
        memo::MemoPayload,
        ring_ct::SignatureRctBulletproofs,
        subaddress_matches_tx_out,
        tokens::Mob,
        tx::{Tx, TxIn, TxOut, TxPrefix},
        Amount, BlockVersion, Token,
    };
    use mc_account_keys::{
        AccountKey, PublicAddress, CHANGE_SUBADDRESS_INDEX, DEFAULT_SUBADDRESS_INDEX,
    };
    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
    use mc_util_from_random::FromRandom;
    use mc_util_test_helper::get_seeded_rng;
    use prost::Message;

    #[test]
    // Create a Tx, encode/decode it, and compare
    fn test_serialize_tx() {
        let mut rng = get_seeded_rng();
        for block_version in BlockVersion::iterator() {
            let recipient = PublicAddress::from_random(&mut rng);
            let amount = Amount::new(23, Mob::ID);
            let tx_private_key = RistrettoPrivate::from_random(&mut rng);
            let tx_out = TxOut::new(
                block_version,
                amount,
                &recipient,
                &tx_private_key,
                Default::default(),
            )
            .unwrap();

            // TxOut = decode(encode(TxOut))
            assert_eq!(tx_out, TxOut::decode(&tx_out.encode_to_vec()[..]).unwrap());

            let tx_in = TxIn {
                ring: vec![tx_out.clone()],
                proofs: vec![],
                input_rules: None,
            };

            // TxIn = decode(encode(TxIn))
            assert_eq!(tx_in, TxIn::decode(&tx_in.encode_to_vec()[..]).unwrap());

            let prefix = TxPrefix {
                inputs: vec![tx_in],
                outputs: vec![tx_out],
                fee: Mob::MINIMUM_FEE,
                fee_token_id: *Mob::ID,
                tombstone_block: 23,
            };

            assert_eq!(
                prefix,
                TxPrefix::decode(&prefix.encode_to_vec()[..]).unwrap()
            );

            // TODO: use a meaningful signature.
            let signature = SignatureRctBulletproofs::default();

            let tx = Tx {
                prefix,
                signature,
                fee_map_digest: vec![],
            };

            let recovered_tx: Tx = Tx::decode(&tx.encode_to_vec()[..]).unwrap();
            assert_eq!(tx, recovered_tx);
        }
    }

    // round trip memos from `TxOut` constructors through `decrypt_memo()`
    #[test]
    fn test_decrypt_memo() {
        let mut rng = get_seeded_rng();

        let bob = AccountKey::new(
            &RistrettoPrivate::from_random(&mut rng),
            &RistrettoPrivate::from_random(&mut rng),
        );
        let bob_addr = bob.default_subaddress();

        {
            let tx_private_key = RistrettoPrivate::from_random(&mut rng);

            // A tx out with an empty memo
            let mut tx_out = TxOut::new(
                BlockVersion::MAX,
                Amount {
                    value: 13,
                    token_id: Mob::ID,
                },
                &bob_addr,
                &tx_private_key,
                Default::default(),
            )
            .unwrap();
            assert!(
                tx_out.e_memo.is_some(),
                "All TxOut (except preexisting) should have a memo"
            );
            let ss = get_tx_out_shared_secret(
                bob.view_private_key(),
                &RistrettoPublic::try_from(&tx_out.public_key).unwrap(),
            );
            assert_eq!(
                tx_out.decrypt_memo(&ss),
                MemoPayload::default(),
                "TxOut::new should produce an empty memo"
            );

            // Now, modify TxOut to make it like old TxOut's with no memo
            tx_out.e_memo = None;
            assert_eq!(
                tx_out.decrypt_memo(&ss),
                MemoPayload::default(),
                "decrypt_memo should produce an empty memo on old TxOut's"
            );
            assert!(
                subaddress_matches_tx_out(&bob, DEFAULT_SUBADDRESS_INDEX, &tx_out).unwrap(),
                "TxOut didn't belong to default subaddress"
            );
        }

        {
            let tx_private_key = RistrettoPrivate::from_random(&mut rng);

            let memo_val = MemoPayload::new([2u8; 2], [4u8; 64]);
            // A tx out with a memo
            let tx_out = TxOut::new_with_memo(
                BlockVersion::MAX,
                Amount {
                    value: 13,
                    token_id: Mob::ID,
                },
                &bob_addr,
                &tx_private_key,
                Default::default(),
                |_| Ok(memo_val),
            )
            .unwrap();

            assert!(
                tx_out.e_memo.is_some(),
                "All TxOut (except preexisting) should have a memo"
            );
            let ss = get_tx_out_shared_secret(
                bob.view_private_key(),
                &RistrettoPublic::try_from(&tx_out.public_key).unwrap(),
            );
            assert_eq!(
                tx_out.decrypt_memo(&ss),
                memo_val,
                "memo did not round trip"
            );
            assert!(
                subaddress_matches_tx_out(&bob, DEFAULT_SUBADDRESS_INDEX, &tx_out).unwrap(),
                "TxOut didn't belong to default subaddress"
            );
        }

        {
            let tx_private_key = RistrettoPrivate::from_random(&mut rng);

            let memo_val = MemoPayload::new([4u8; 2], [9u8; 64]);
            // A tx out with a memo
            let tx_out = TxOut::new_with_memo(
                BlockVersion::MAX,
                Amount {
                    value: 13,
                    token_id: Mob::ID,
                },
                &bob.change_subaddress(),
                &tx_private_key,
                Default::default(),
                |_| Ok(memo_val),
            )
            .unwrap();

            assert!(
                tx_out.e_memo.is_some(),
                "All TxOut (except preexisting) should have a memo"
            );
            let ss = get_tx_out_shared_secret(
                bob.view_private_key(),
                &RistrettoPublic::try_from(&tx_out.public_key).unwrap(),
            );
            assert_eq!(
                tx_out.decrypt_memo(&ss),
                memo_val,
                "memo did not round trip"
            );
            assert!(
                subaddress_matches_tx_out(&bob, CHANGE_SUBADDRESS_INDEX, &tx_out).unwrap(),
                "TxOut didn't belong to change subaddress"
            );
        }
    }
}
