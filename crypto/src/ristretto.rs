use std::{convert::{TryFrom, TryInto}, cmp::Ordering, fmt::Formatter};
use crate::error::Error;
use curve25519_dalek_ng::{scalar::Scalar, constants::RISTRETTO_BASEPOINT_POINT, ristretto::{CompressedRistretto, RistrettoPoint}, digest::Update};
use schnorrkel::{signing_context, SIGNATURE_LENGTH, SignatureError};
use serde::{Deserialize, Serialize};
use signature::Signature;
use schnorrkel::Signature as SchnorrkelSignature;

/// A Ristretto-format private scalar
#[derive(Clone, Copy, Default)]
pub struct RistrettoPrivate(pub Scalar);

impl AsRef<[u8; 32]> for RistrettoPrivate {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8; 32]> for RistrettoPrivate {
    type Error = Error;

    fn try_from(src: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self(
            Scalar::from_canonical_bytes(*src).ok_or(Error::InvalidPrivateKey)?,
        ))
    }
}

impl AsRef<[u8]> for RistrettoPrivate {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for RistrettoPrivate {
    type Error = Error;
    fn try_from(src: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 32] = src
            .try_into()
            .map_err(|_| Error::LengthMismatch(src.len(), 32))?;
        Self::try_from(bytes)
    }
}

//derive_repr_bytes_from_as_ref_and_try_from!(RistrettoPrivate, U32);
//derive_into_vec_from_repr_bytes!(RistrettoPrivate);
//derive_serde_from_repr_bytes!(RistrettoPrivate);
//derive_prost_message_from_repr_bytes!(RistrettoPrivate);

impl RistrettoPrivate {
    /// This is used by some code that used to use ReprBytes32 API
    /// This is okay in code that is not generic over the key type.
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.0.as_bytes()
    }

    /// Sign the given bytes using a deterministic scheme based on Schnorrkel.
    pub fn sign_schnorrkel(&self, context: &[u8], message: &[u8]) -> RistrettoSignature {
        // Create a deterministic nonce using a merlin transcript. See this crate's
        // README for a security statement.
        let nonce = [0; 32];

        // Construct a Schnorrkel SecretKey object from ourselves, and our nonce value
        let mut secret_bytes = [0u8; 64];
        secret_bytes[0..32].copy_from_slice(&self.to_bytes());
        secret_bytes[32..64].copy_from_slice(&nonce);
        let secret_key = schnorrkel::SecretKey::from_bytes(&secret_bytes).unwrap();
        let keypair = secret_key.to_keypair();

        let ctx = signing_context(b"My Signing Context");
        let message: &[u8] = b"All I want is to pet all of the dogs.";
        let prehashed = sha3::Shake256::default().chain(message);
        RistrettoSignature::from(keypair.sign(ctx.xof(prehashed.clone())))
    }
}

impl AsRef<Scalar> for RistrettoPrivate {
    fn as_ref(&self) -> &Scalar {
        &self.0
    }
}

impl From<Scalar> for RistrettoPrivate {
    fn from(scalar: Scalar) -> Self {
        Self(scalar)
    }
}

/*impl Debug for RistrettoPrivate {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "RistrettoPrivate for pubkey: {:?}",
            RistrettoPublic::from(self)
        )
    }
}

impl<T: Digestible> DigestibleSigner<RistrettoSignature, T> for RistrettoPrivate {
    fn sign_digestible(&self, context: &'static [u8], message: &T) -> RistrettoSignature {
        let message = message.digest32::<MerlinTranscript>(context);
        self.sign_schnorrkel(context, &message)
    }

    fn try_sign_digestible(
        &self,
        context: &'static [u8],
        message: &T,
    ) -> Result<RistrettoSignature, SignatureError> {
        Ok(self.sign_digestible(context, message))
    }
}

impl FromRandom for RistrettoPrivate {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> RistrettoPrivate {
        Self(Scalar::random(csprng))
    }
}

impl KexEphemeralPrivate for RistrettoPrivate {
    fn key_exchange(
        self,
        their_public: &<Self as PrivateKey>::Public,
    ) -> <Self as KexPrivate>::Secret {
        RistrettoSecret((self.0 * their_public.0).compress().to_bytes())
    }
}

impl KexReusablePrivate for RistrettoPrivate {
    fn key_exchange(
        &self,
        their_public: &<Self as PrivateKey>::Public,
    ) -> <Self as KexPrivate>::Secret {
        RistrettoSecret((self.0 * their_public.0).compress().to_bytes())
    }
}

impl KexPrivate for RistrettoPrivate {
    type Secret = RistrettoSecret;
}

impl PrivateKey for RistrettoPrivate {
    type Public = RistrettoPublic;
}

impl ConstantTimeEq for RistrettoPrivate {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}*/

/// A private ristretto key which is ephemeral, should never be copied,
/// and should be zeroized
pub struct RistrettoEphemeralPrivate(Scalar);

/*impl PrivateKey for RistrettoEphemeralPrivate {
    type Public = RistrettoPublic;
}

impl KexPrivate for RistrettoEphemeralPrivate {
    type Secret = RistrettoSecret;
}

impl KexEphemeralPrivate for RistrettoEphemeralPrivate {
    fn key_exchange(
        self,
        their_public: &<Self as PrivateKey>::Public,
    ) -> <Self as KexPrivate>::Secret {
        RistrettoSecret((self.0 * their_public.0).compress().to_bytes())
    }
}

impl FromRandom for RistrettoEphemeralPrivate {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        Self(Scalar::random(csprng))
    }
}

impl Debug for RistrettoEphemeralPrivate {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(
            f,
            "RistrettoEphemeralPrivate for {:?}",
            RistrettoPublic::from(self)
        )
    }
}*/

/// A Ristretto-format curve point for use as a public key
#[derive(Clone, Copy, Default)]
pub struct RistrettoPublic(pub RistrettoPoint);

impl AsRef<RistrettoPoint> for RistrettoPublic {
    fn as_ref(&self) -> &RistrettoPoint {
        &self.0
    }
}

/*impl FromRandom for RistrettoPublic {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> RistrettoPublic {
        Self(RistrettoPoint::random(csprng))
    }
}*/

impl From<RistrettoPoint> for RistrettoPublic {
    fn from(point: RistrettoPoint) -> Self {
        Self(point)
    }
}

/*impl ReprBytes for RistrettoPublic {
    type Size = U32;
    type Error = KeyError;

    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, KeyError> {
        Ok(Self(
            CompressedRistretto::from_slice(src.as_slice())
                .decompress()
                .ok_or(KeyError::InvalidPublicKey)?,
        ))
    }

    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.0.compress().to_bytes().into()
    }
}*/

//derive_serde_from_repr_bytes!(RistrettoPublic);
//derive_prost_message_from_repr_bytes!(RistrettoPublic);
//derive_into_vec_from_repr_bytes!(RistrettoPublic);
//derive_try_from_slice_from_repr_bytes!(RistrettoPublic);

// Many historical APIs assumed TryFrom<&[u8;32]> existed for RistrettoPublic
// This will work fine in code that is not generic over the size of the key
/*impl TryFrom<&[u8; 32]> for RistrettoPublic {
    type Error = Error;
    fn try_from(src: &[u8; 32]) -> Result<Self, Error> {
        Self::try_from(&src[..])
    }
}*/

impl RistrettoPublic {
    // Many historical APIs based on ReprBytes32 in mobilecoin use to_bytes() ->
    // [u8;32]. This is okay in non-generic code
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Verify a deterministic Schnorrkel signature created with the
    /// corresponding [`RistrettoPrivate::sign_schnorrkel()`] method.
    pub fn verify_schnorrkel(
        &self,
        context: &'static [u8],
        message: &[u8],
        signature: &RistrettoSignature,
    ) -> Result<(), schnorrkel::errors::SignatureError> {
        let ctx = schnorrkel::signing_context(context);
        let pubkey = schnorrkel::PublicKey::from_point(*self.as_ref());
        pubkey.verify(ctx.bytes(message), &signature.try_into()?)
    }
}

impl PartialOrd for RistrettoPublic {
    fn partial_cmp(&self, other: &RistrettoPublic) -> Option<Ordering> {
        self.to_bytes().partial_cmp(&other.to_bytes())
    }
}

impl Ord for RistrettoPublic {
    fn cmp(&self, other: &RistrettoPublic) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

/*impl Hash for RistrettoPublic {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}*/

impl Eq for RistrettoPublic {}

impl PartialEq for RistrettoPublic {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

//impl PublicKeyTrait for RistrettoPublic {}

impl From<&RistrettoPrivate> for RistrettoPublic {
    fn from(private: &RistrettoPrivate) -> Self {
        let x = private.0;
        let G = RISTRETTO_BASEPOINT_POINT;
        let Y = x * G;

        Self(Y)
    }
}

impl From<&RistrettoEphemeralPrivate> for RistrettoPublic {
    fn from(private: &RistrettoEphemeralPrivate) -> Self {
        let x = private.0;
        let G = RISTRETTO_BASEPOINT_POINT;
        let Y = x * G;

        Self(Y)
    }
}

/*impl Debug for RistrettoPublic {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "RistrettoPublic({})", HexFmt(self.to_bytes()))
    }
}

impl<T: Digestible> DigestibleVerifier<RistrettoSignature, T> for RistrettoPublic {
    fn verify_digestible(
        &self,
        context: &'static [u8],
        message: &T,
        signature: &RistrettoSignature,
    ) -> Result<(), SignatureError> {
        let message = message.digest32::<MerlinTranscript>(context);
        self.verify_schnorrkel(context, &message, signature)
            .map_err(|_e| SignatureError::new())
    }
}

impl Display for RistrettoPublic {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", HexFmt(self.to_bytes()))
    }
}*/

impl From<&RistrettoPublic> for Vec<u8> {
    fn from(src: &RistrettoPublic) -> Vec<u8> {
        let compressed = src.as_ref().compress();
        Vec::from(&compressed.as_bytes()[..])
    }
}

//impl KexPublic for RistrettoPublic {
    //type KexEphemeralPrivate = RistrettoEphemeralPrivate;
//}

impl TryFrom<&CompressedRistrettoPublic> for RistrettoPublic {
    type Error = Error;
    fn try_from(src: &CompressedRistrettoPublic) -> Result<Self, Error> {
        Ok(Self(src.0.decompress().ok_or(Error::InvalidPublicKey)?))
    }
}

/// Shared Secret resulting from Key Exchange
///
/// This is a (compressed) curve point on the ristretto curve, but we make it a
/// different type from RistrettoPublic in order to avoid bugs where the secret
/// is publicized.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RistrettoSecret([u8; 32]);

impl Drop for RistrettoSecret {
    fn drop(&mut self) {
        //self.0.zeroize();
    }
}

impl AsRef<[u8]> for RistrettoSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsRef<[u8; 32]> for RistrettoSecret {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

//impl KexSecret for RistrettoSecret {}

/// This is a newtype wrapper around CompressedRistretto, which implements
/// From<RistrettoPublic>, and serialization / digest implementations.
///
/// This structure does not perform any validation that the bytes contained
/// within it represent a valid point, because compression/decompression of
/// ristretto-flavored points is a very expensive operation.
///
/// As a result, this does not implement the `PublicKey` interface, nor is it
/// usable in a key-exchange.
#[derive(Clone, Copy, Default)]
//#[digestible(never_omit)]
pub struct CompressedRistrettoPublic(pub CompressedRistretto);

impl CompressedRistrettoPublic {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl AsRef<[u8]> for CompressedRistrettoPublic {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for CompressedRistrettoPublic {
    type Error = Error;
    fn try_from(src: &[u8]) -> Result<Self, Error> {
        if src.len() != 32 {
            return Err(Error::LengthMismatch(src.len(), 32));
        }
        Ok(Self(CompressedRistretto::from_slice(src)))
    }
}

//derive_repr_bytes_from_as_ref_and_try_from!(CompressedRistrettoPublic, U32);
//derive_into_vec_from_repr_bytes!(CompressedRistrettoPublic);
//derive_serde_from_repr_bytes!(CompressedRistrettoPublic);
//derive_prost_message_from_repr_bytes!(CompressedRistrettoPublic);

impl From<&[u8; 32]> for CompressedRistrettoPublic {
    fn from(src: &[u8; 32]) -> Self {
        Self(CompressedRistretto::from_slice(&src[..]))
    }
}

impl AsRef<[u8; 32]> for CompressedRistrettoPublic {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

//derive_core_cmp_from_as_ref!(CompressedRistrettoPublic, [u8; 32]);

/*impl Debug for CompressedRistrettoPublic {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let bytes: &[u8] = self.as_ref();
        write!(f, "CompressedRistrettoPublic({})", HexFmt(bytes))
    }
}

impl Display for CompressedRistrettoPublic {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        let bytes: &[u8] = self.as_ref();
        write!(f, "{}", HexFmt(bytes))
    }
}*/

impl AsRef<CompressedRistretto> for CompressedRistrettoPublic {
    fn as_ref(&self) -> &CompressedRistretto {
        &self.0
    }
}

impl From<RistrettoPoint> for CompressedRistrettoPublic {
    fn from(src: RistrettoPoint) -> Self {
        Self(src.compress())
    }
}

impl From<&RistrettoPublic> for CompressedRistrettoPublic {
    fn from(src: &RistrettoPublic) -> Self {
        Self(src.0.compress())
    }
}

impl From<RistrettoPublic> for CompressedRistrettoPublic {
    fn from(src: RistrettoPublic) -> Self {
        Self(src.0.compress())
    }
}

impl From<CompressedRistretto> for CompressedRistrettoPublic {
    fn from(src: CompressedRistretto) -> Self {
        Self(src)
    }
}

/*impl FromRandom for CompressedRistrettoPublic {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> CompressedRistrettoPublic {
        Self::from(RistrettoPoint::random(csprng))
    }
}

impl PublicKeyTrait for CompressedRistrettoPublic {}*/

/// A zero-width type used to identify the Ristretto key exchange system.
pub struct Ristretto;

/// The implementation of the Ristretto key exchange system.
/*impl Kex for Ristretto {
    type Public = RistrettoPublic;
    type Private = RistrettoPrivate;
    type EphemeralPrivate = RistrettoEphemeralPrivate;
    type Secret = RistrettoSecret;
}*/

#[derive(Debug)]
pub struct RistrettoSignature([u8; SIGNATURE_LENGTH]);

impl AsRef<[u8]> for RistrettoSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; SIGNATURE_LENGTH]> for RistrettoSignature {
    fn as_ref(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.0
    }
}

/*impl Debug for RistrettoSignature {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{:?}", &self.0[..])
    }
}*/

impl Default for RistrettoSignature {
    fn default() -> RistrettoSignature {
        Self([0u8; 64])
    }
}

/*impl Display for RistrettoSignature {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", HexFmt(&self))
    }
}*/

//impl Eq for RistrettoSignature {}

impl From<schnorrkel::Signature> for RistrettoSignature {
    fn from(src: schnorrkel::Signature) -> RistrettoSignature {
        Self::from(&src)
    }
}

impl From<&schnorrkel::Signature> for RistrettoSignature {
    fn from(src: &schnorrkel::Signature) -> RistrettoSignature {
        Self(src.to_bytes())
    }
}

/*impl Signature for RistrettoSignature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        Self::try_from(bytes)
    }
}*/

impl TryFrom<&[u8]> for RistrettoSignature {
    type Error = signature::Error;

    fn try_from(src: &[u8]) -> Result<RistrettoSignature, signature::Error> {
        schnorrkel::Signature::from_bytes(src)
            .map(|sig| Self(sig.to_bytes()))
            .map_err(|_| signature::Error::new())
    }
}

impl TryFrom<&RistrettoSignature> for SchnorrkelSignature {
    type Error = schnorrkel::SignatureError;

    fn try_from(src: &RistrettoSignature) -> Result<SchnorrkelSignature, schnorrkel::SignatureError> {
        SchnorrkelSignature::from_bytes(&src.0)
    }
}

impl TryFrom<RistrettoSignature> for SchnorrkelSignature {
    type Error = schnorrkel::SignatureError;

    fn try_from(src: RistrettoSignature) -> Result<SchnorrkelSignature, schnorrkel::SignatureError> {
        SchnorrkelSignature::try_from(&src)
    }
}

//derive_core_cmp_from_as_ref!(RistrettoSignature, [u8]);
//derive_into_vec_from_repr_bytes!(RistrettoSignature);
//derive_repr_bytes_from_as_ref_and_try_from!(RistrettoSignature, U64);
//derive_serde_from_repr_bytes!(RistrettoSignature);
//derive_prost_message_from_repr_bytes!(RistrettoSignature);

