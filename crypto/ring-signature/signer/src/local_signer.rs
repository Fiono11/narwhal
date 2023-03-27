// Copyright (c) 2018-2022 The MobileCoin Foundation

use curve25519_dalek::ristretto::RistrettoPoint;
use super::{Error, OneTimeKeyDeriveData, RingSigner, SignableInputRing};
use mc_account_keys::AccountKey;
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_ring_signature::{onetime_keys::recover_onetime_private_key, TriptychSignature, Sign};
use log::{debug, info};

/// An implementation of RingSigner that holds private keys and derives one-time
/// private keys
#[derive(Clone, Debug)]
pub struct LocalRingSigner {
    key: AccountKey,
}

impl RingSigner for LocalRingSigner {
    fn sign(
        &self,
        message: &[u8],
        ring: &SignableInputRing,
        //pseudo_output_blinding: Scalar,
        //rng: &mut dyn CryptoRngCore,
    ) -> Result<TriptychSignature, Error> {
        let real_input = ring
            .members
            .get(ring.real_input_index)
            .ok_or(Error::RealInputIndexOutOfBounds)?;
        let target_key = RistrettoPublic::try_from(&real_input.target_key)?;

        //info!("target key: {:#?}", target_key);

        // First, compute the one-time private key
        let onetime_private_key = match ring.input_secret.onetime_key_derive_data {
            OneTimeKeyDeriveData::OneTimeKey(key) => {
                //info!("ADDRESS");
                key
            },
            OneTimeKeyDeriveData::SubaddressIndex(subaddress_index) => {
                //info!("SUBADDRESS");
                let public_key = RistrettoPublic::try_from(&real_input.public_key)?;

                recover_onetime_private_key(
                    &public_key,
                    self.key.view_private_key(),
                    &self.key.subaddress_spend_private(subaddress_index),
                )
            }
        };

        //info!("onetime private key: {:#?}", onetime_private_key);
        //info!("public from onetime private key: {:#?}", RistrettoPublic::from(&onetime_private_key));

        // Check if this is the correct one-time private key
        if RistrettoPublic::from(&onetime_private_key) != target_key {
            return Err(Error::TrueInputNotOwned);
        }

        let ring: Vec<RistrettoPoint> = ring.members.iter().map(|x| x.target_key.0.decompress().unwrap()).collect();

        let signature = Sign(&onetime_private_key.0, &String::from_utf8(message.to_vec()).unwrap(), &ring);

        // Sign the TriptychSiganture
        Ok(signature)
    }
}

impl From<&AccountKey> for LocalRingSigner {
    fn from(src: &AccountKey) -> Self {
        Self { key: src.clone() }
    }
}
