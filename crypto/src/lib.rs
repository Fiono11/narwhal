use bulletproofs::BulletproofGens;
use bulletproofs::PedersenGens;
use bulletproofs::ProofError;
use bulletproofs::RangeProof;
use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::traits::Identity;
use ed25519_dalek as dalek;
use ed25519_dalek::ed25519;
use ed25519_dalek::Signer as _;
use num_integer::Roots;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{de, ser, Deserialize, Serialize};
use zkp::CompactProof;
use zkp::Transcript;
use std::array::TryFromSliceError;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::oneshot;

#[macro_use]
extern crate zkp;

define_proof! {dleq, "DLEQ Proof", (x), (A, B), (H, G) : A = (x * B), H = (x * G)}

#[cfg(test)]
#[path = "tests/crypto_tests.rs"]
pub mod crypto_tests;

pub type CryptoError = ed25519::Error;

/// Represents a hash digest (32 bytes).
#[derive(Hash, PartialEq, Default, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", base64::encode(&self.0).get(0..16).unwrap())
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Digest(item.try_into()?))
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> Digest;
}

/// Represents a public key (in bytes).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Default)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn encode_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }

    pub fn encrypt_twisted(self, message: &Scalar, random: &Scalar) -> TwistedElGamal {
        let generators = PedersenGens::default();
        let c1 = (CompressedRistretto(self.0).decompress().unwrap() * random).compress();
        let c2 = (random * generators.B_blinding + message * generators.B).compress();

        TwistedElGamal {
            c1,
            c2,
        }
    }

    pub fn verify_correct_decryption_twisted(
        self,
        proof: &CompactProof,
        ciphertext: &TwistedElGamal,
        plaintext: &RistrettoPoint,
    ) -> bool {
        let mut transcript = Transcript::new(b"ProveCorrectDecryption");
        dleq::verify_compact(
            &proof,
            &mut transcript,
            dleq::VerifyAssignments {
                A: &(ciphertext.c1),
                B: &(ciphertext.c2.decompress().unwrap() - plaintext).compress(),
                H: &CompressedRistretto(self.0),
                G: &PedersenGens::default().B_blinding.compress(),
            },
        )
        .is_ok()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64().get(0..16).unwrap())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents a secret key (in bytes).
pub struct SecretKey([u8; 64]);

impl SecretKey {
    pub fn new<T: RngCore + CryptoRng>(csprng: &mut T) -> Self {
        let mut bytes = [0u8; 64];
        csprng.fill_bytes(&mut bytes);
        SecretKey(bytes)
    }

    pub fn encode_base64(&self) -> String {
        base64::encode(&self.0[..])
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        let array = bytes[..64]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength)?;
        Ok(Self(array))
    }

    pub fn decrypt_twisted(&self, ciphertext: &TwistedElGamal) -> RistrettoPoint {
        ciphertext.c2.decompress().unwrap()
            - ciphertext.c1.decompress().unwrap() * Scalar::from_bytes_mod_order_wide(&self.0).invert()
    }

    pub fn prove_correct_decryption_twisted(
        &self,
        ciphertext: &TwistedElGamal,
        message: &RistrettoPoint,
    ) -> CompactProof {
        let mut transcript = Transcript::new(b"ProveCorrectDecryption");
        let generators = PedersenGens::default();
        let scalar = Scalar::from_bytes_mod_order_wide(&self.0);
        let (proof, _) = dleq::prove_compact(
            &mut transcript,
            dleq::ProveAssignments {
                x: &&scalar,
                A: &(ciphertext.c1.decompress().unwrap()), // C1
                B: &(ciphertext.c2.decompress().unwrap() - message), // C2-M
                H: &(&scalar * &generators.B_blinding),       // xG
                G: &&generators.B_blinding,
            },
        );
        proof
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|x| *x = 0);
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(secret: &'a SecretKey) -> PublicKey {
        PublicKey(*(PedersenGens::default().B_blinding * Scalar::from_bytes_mod_order_wide(&secret.0)).compress().as_bytes())
    }
}

pub fn generate_production_keypair() -> (PublicKey, SecretKey) {
    generate_keypair(&mut OsRng)
}

pub fn generate_keypair<R>(csprng: &mut R) -> (PublicKey, SecretKey)
where
    R: CryptoRng + RngCore,
{
    let keypair = dalek::Keypair::generate(csprng);
    let public = PublicKey(keypair.public.to_bytes());
    let secret = SecretKey(keypair.to_bytes());
    (public, secret)
}

/// Represents an ed25519 signature.
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Signature {
    part1: [u8; 32],
    part2: [u8; 32],
}

impl Signature {
    pub fn new(digest: &Digest, secret: &SecretKey) -> Self {
        let keypair = dalek::Keypair::from_bytes(&secret.0).expect("Unable to load secret key");
        let sig = keypair.sign(&digest.0).to_bytes();
        let part1 = sig[..32].try_into().expect("Unexpected signature length");
        let part2 = sig[32..64].try_into().expect("Unexpected signature length");
        Signature { part1, part2 }
    }

    fn flatten(&self) -> [u8; 64] {
        [self.part1, self.part2]
            .concat()
            .try_into()
            .expect("Unexpected signature length")
    }

    pub fn verify(&self, digest: &Digest, public_key: &PublicKey) -> Result<(), CryptoError> {
        let signature = ed25519::signature::Signature::from_bytes(&self.flatten())?;
        let key = dalek::PublicKey::from_bytes(&public_key.0)?;
        key.verify_strict(&digest.0, &signature)
    }

    pub fn verify_batch<'a, I>(digest: &Digest, votes: I) -> Result<(), CryptoError>
    where
        I: IntoIterator<Item = &'a (PublicKey, Signature)>,
    {
        let mut messages: Vec<&[u8]> = Vec::new();
        let mut signatures: Vec<dalek::Signature> = Vec::new();
        let mut keys: Vec<dalek::PublicKey> = Vec::new();
        for (key, sig) in votes.into_iter() {
            messages.push(&digest.0[..]);
            signatures.push(ed25519::signature::Signature::from_bytes(&sig.flatten())?);
            keys.push(dalek::PublicKey::from_bytes(&key.0)?);
        }
        dalek::verify_batch(&messages[..], &signatures[..], &keys[..])
    }
}

/// This service holds the node's private key. It takes digests as input and returns a signature
/// over the digest (through a oneshot channel).
#[derive(Clone)]
pub struct SignatureService {
    channel: Sender<(Digest, oneshot::Sender<Signature>)>,
}

impl SignatureService {
    pub fn new(secret: SecretKey) -> Self {
        let (tx, mut rx): (Sender<(_, oneshot::Sender<_>)>, _) = channel(100);
        tokio::spawn(async move {
            while let Some((digest, sender)) = rx.recv().await {
                let signature = Signature::new(&digest, &secret);
                let _ = sender.send(signature);
            }
        });
        Self { channel: tx }
    }

    pub async fn request_signature(&mut self, digest: Digest) -> Signature {
        let (sender, receiver): (oneshot::Sender<_>, oneshot::Receiver<_>) = oneshot::channel();
        if let Err(e) = self.channel.send((digest, sender)).await {
            panic!("Failed to send message Signature Service: {}", e);
        }
        receiver
            .await
            .expect("Failed to receive signature from Signature Service")
    }
}

#[derive(Default, Clone, Deserialize, Serialize, Debug)]
pub struct TwistedElGamal {
    pub c1: CompressedRistretto,
    pub c2: CompressedRistretto,
}

impl TwistedElGamal {
    pub fn new(public_key: &RistrettoPoint, message: &Scalar, random: &Scalar) -> Self {
        let generators = PedersenGens::default();
        let c1 = (random * public_key).compress();
        let c2 = (random * generators.B_blinding + message * generators.B).compress();

        TwistedElGamal {
            c1,
            c2,
        }
    }
}

pub struct BSGSTable(pub HashMap<CompressedRistretto, u32>);

impl BSGSTable {
    // Q = xP
    pub fn create(generator: &RistrettoPoint) -> Self {
        let n = u32::MAX;
        let m = n.sqrt() + 1;
        let mut precomputed = HashMap::new();
        let mut R = RistrettoPoint::identity();

        // Compute the baby steps and store them in the 'precomputed' hash table.
        precomputed.insert(R.compress(), 0);
        for a in 1..m {
            R += generator;
            precomputed.insert(R.compress(), a);
        }
        BSGSTable(precomputed)
    }
}

pub fn baby_step_giant_step_elgamal(
    generator: &RistrettoPoint,
    point: &RistrettoPoint,
    precomputed: &HashMap<CompressedRistretto, u32>,
) -> Result<Scalar, &'static str> {
    let n = u32::MAX;
    let m = n.sqrt() + 1;
    let mut _r = RistrettoPoint::identity();

    _r = *point;
    let S = &Scalar::from(m) * &(-generator);
    let mut _x = Scalar::zero();

    for b in 0..m {
        match precomputed.get(&_r.compress()) {
            None => {
                //println!("key not found");
                _r += S;
            }
            Some(a) => {
                //println!("key found");
                _x = Scalar::from(a + m * b);
                return Ok(_x);
            }
        }
    }
    Err("not found")
}

pub struct ElGamalProof {
    a1: CompressedRistretto,
    a2: CompressedRistretto,
    b1: CompressedRistretto,
    b2: CompressedRistretto,
    z1: Scalar,
    z2: Scalar,
    z3: Scalar,
}

impl ElGamalProof {
    pub fn new(v: Scalar, r1: Scalar, r2: Scalar, pk1: RistrettoPoint, pk2: RistrettoPoint) -> Self {
        let mut rng = rand::rngs::OsRng;
        let generators = PedersenGens::default();
        let a1 = Scalar::random(&mut rng);
        let a2 = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let a1_point = a1 * pk1;
        let a2_point = a2 * pk2;
        let b_point1 = a1 * generators.B + b * generators.B_blinding;
        let b_point2 = a2 * generators.B + b * generators.B_blinding;
        let e = Scalar::zero();
        let z1 = a1 + e * r1;
        let z2 = a2 + e * r2;
        let z3 = b + e * v;
        Self {
            a1: a1_point.compress(),
            a2: a2_point.compress(),
            b1: b_point1.compress(),
            b2: b_point2.compress(),
            z1: z1,
            z2: z2,
            z3: z3,
        }
    }

    pub fn verify(
        &self,
        x1: RistrettoPoint,
        x2: RistrettoPoint,
        y1: RistrettoPoint,
        y2: RistrettoPoint,
        pk1: RistrettoPoint,
        pk2: RistrettoPoint,
    ) -> Result<(), ()> {
        let generators = PedersenGens::default();
        let e = Scalar::zero();
        if pk1 * self.z1 != self.a1.decompress().unwrap() + x1 * e
			|| pk2 * self.z2 != self.a2.decompress().unwrap() + x2 * e
			|| self.z1 * generators.B + self.z3 * generators.B_blinding != self.b1.decompress().unwrap() + y1 * e
            || self.z2 * generators.B + self.z3 * generators.B_blinding != self.b2.decompress().unwrap() + y2 * e
        {
            Err(())
        } else {
            Ok(())
        }
    }
}

#[derive(Default, Clone, Deserialize, Serialize, Debug)]
pub struct Transaction {
    id: u128,
    pub balance: TwistedElGamal,
    //pub range_proof: Vec<u8>, // balance > 0
    pub signature: Signature,
    pub representative: CompressedRistretto,
    pub public_key: PublicKey,
}

impl Transaction {
    pub fn random(id: u128, balance: TwistedElGamal, representative: CompressedRistretto, public_key: PublicKey, signature: Signature) -> Self {
        /*let mut rng = OsRng;
        let representative = RistrettoPoint::random(&mut rng);
        let balance = rand::thread_rng().gen_range(0, u64::MAX);
        let amount = rand::thread_rng().gen_range(0, balance);
        let random = Scalar::random(&mut rng);
        let random1 = Scalar::random(&mut rng);
        let generators = PedersenGens::default();
        
        let (range_proof, _commitment) = generate_range_proofs(
            &vec![balance - amount],
            &vec![random - &random1],
            &generators,
            &mut rng,
        )
        .unwrap();
    
        let range_proof = range_proof.to_bytes().to_vec();*/
    
        Self {
            id,
            balance,
            signature,
            //range_proof,
            representative,
            public_key,
        }
    }

    pub fn len(&self) -> usize {
        let bytes = bincode::serialize(&self).unwrap();
        bytes.len()
    }
}

pub fn generate_range_proofs<T: RngCore + CryptoRng>(
    values: &[u64],
    blindings: &[Scalar],
    pedersen_generators: &PedersenGens,
    rng: &mut T,
) -> Result<(RangeProof, Vec<CompressedRistretto>), ProofError> {
    // Most of this comes directly from the example at
    // https://doc-internal.dalek.rs/bulletproofs/struct.RangeProof.html#example-1

    // Aggregated rangeproofs operate on sets of `m` values, where `m` must be a
    // power of 2. If the number of inputs is not a power of 2, pad them.
    let values_padded: Vec<u64> = resize_slice_to_pow2::<u64>(values).unwrap();
    let blindings_padded: Vec<Scalar> = resize_slice_to_pow2::<Scalar>(blindings).unwrap();

    // Create a 64-bit RangeProof and corresponding commitments.
    RangeProof::prove_multiple_with_rng(
        &BulletproofGens::new(64, 512),
        pedersen_generators,
        &mut Transcript::new("BULLETPROOF_DOMAIN_TAG".as_ref()),
        &values_padded,
        &blindings_padded,
        64,
        rng,
    )
}

pub fn check_range_proof<T: RngCore + CryptoRng>(
    range_proof: &RangeProof,
    commitment: &CompressedRistretto,
    pedersen_generators: &PedersenGens,
    rng: &mut T,
) -> Result<(), ProofError> {
    range_proof
        .verify_single(
            &BulletproofGens::new(64, 64),
            pedersen_generators,
            &mut Transcript::new("BULLETPROOF_DOMAIN_TAG".as_ref()),
            &commitment,
            64,
        )
}

pub fn check_range_proofs<T: RngCore + CryptoRng>(
    range_proof: &RangeProof,
    commitments: &[CompressedRistretto],
    pedersen_generators: &PedersenGens,
    rng: &mut T,
) -> Result<(), ProofError> {
    // The length of `commitments` must be a power of 2. If not, resize it.
    let resized_commitments = resize_slice_to_pow2::<CompressedRistretto>(commitments).unwrap();
    range_proof
        .verify_multiple_with_rng(
            &BulletproofGens::new(64, 512),
            pedersen_generators,
            &mut Transcript::new("BULLETPROOF_DOMAIN_TAG".as_ref()),
            &resized_commitments,
            64,
            rng,
        )
}

fn resize_slice_to_pow2<T: Clone>(slice: &[T]) -> Result<Vec<T>, Error> {
    let len: usize = slice.len();
    if let Some(next_power_of_two) = len.checked_next_power_of_two() {
        let diff = next_power_of_two - len;
        let mut pow2_slice: Vec<T> = Vec::with_capacity(next_power_of_two);
        pow2_slice.extend_from_slice(slice);
        pow2_slice.resize(slice.len() + diff, slice[slice.len() - 1].clone());
        Ok(pow2_slice)
    } else {
        // The next power of two would exceed the maximum value of usize.
        Err(Error::ResizeError)
    }
}

#[derive(Debug)]
pub enum Error {
    /// Resize error
    ResizeError,
}

pub fn create_shared_secret(
    public_key: &RistrettoPoint,
    private_key: &Scalar,
) -> RistrettoPoint {
    private_key * public_key
}



