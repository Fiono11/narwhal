use core::fmt;
use bulletproofs::PedersenGens;
use curve25519_dalek_ng::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
//use mc_crypto_digestible::Digestible;
//use mc_util_repr_bytes::{
    //derive_core_cmp_from_as_ref, derive_prost_message_from_repr_bytes,
    //derive_try_from_slice_from_repr_bytes, typenum::U32, GenericArray, ReprBytes,
//};
use serde::{Deserialize, Serialize};

use crate::commitment::Commitment;

/// A Pedersen commitment in compressed Ristretto format.
#[derive(Copy, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct CompressedCommitment {
    /// A Pedersen commitment `v*H + b*G` to a quantity `v` with blinding `b`,
    pub point: CompressedRistretto,
}

impl CompressedCommitment {
    /// Create a new compressed commitment from value, blinding factor, and
    /// pedersen generators
    pub fn new(value: u64, blinding: Scalar, generator: &PedersenGens) -> Self {
        Self::from(&Commitment::new(value, blinding, generator))
    }

    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        CompressedCommitment {
            point: (Scalar::random(&mut rng) * RISTRETTO_BASEPOINT_POINT).compress(),
        }
    }
}

impl From<&Commitment> for CompressedCommitment {
    fn from(src: &Commitment) -> Self {
        Self {
            point: src.point.compress(),
        }
    }
}
impl From<&CompressedRistretto> for CompressedCommitment {
    fn from(source: &CompressedRistretto) -> Self {
        Self { point: *source }
    }
}

impl fmt::Debug for CompressedCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CompressedCommitment()",
            //hex_fmt::HexFmt(self.point.as_bytes())
        )
    }
}

impl AsRef<[u8; 32]> for CompressedCommitment {
    fn as_ref(&self) -> &[u8; 32] {
        self.point.as_bytes()
    }
}

impl From<&[u8; 32]> for CompressedCommitment {
    fn from(src: &[u8; 32]) -> Self {
        Self {
            point: CompressedRistretto::from_slice(src),
        }
    }
}

// Implements Ord, PartialOrd, PartialEq, Hash.
/*derive_core_cmp_from_as_ref!(CompressedCommitment, [u8; 32]);

impl ReprBytes for CompressedCommitment {
    type Error = Error;
    type Size = U32;
    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.point.to_bytes().into()
    }
    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, Error> {
        Ok(Self {
            point: CompressedRistretto::from_slice(src.as_slice()),
        })
    }
}

derive_try_from_slice_from_repr_bytes!(CompressedCommitment);*/
