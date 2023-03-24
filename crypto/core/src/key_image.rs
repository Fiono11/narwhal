use core::{convert::TryFrom, fmt};
use curve25519_dalek_ng::{ristretto::CompressedRistretto, scalar::Scalar, constants::RISTRETTO_BASEPOINT_POINT};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::ristretto::{RistrettoPrivate, RistrettoPublic};

#[derive(Copy, Clone, Default, Serialize, Deserialize)]
/// The "image" of a private key `x`: I = x * Hp(x * G) = x * Hp(P).
pub struct KeyImage {
    /// The curve point corresponding to the key image
    pub point: CompressedRistretto,
}

impl KeyImage {
    pub fn default() -> Self {
        let mut bytes = [0; 32];
        for i in 0..32 {
            bytes[i] = rand::thread_rng().gen_range(0, u8::MAX);
        }
        KeyImage {
            point: CompressedRistretto::from_slice(&bytes[..]),
        }
    }

    /// View the underlying `CompressedRistretto` as an array of bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.point.as_bytes()
    }

    /// Copies `self` into a new Vec.
    pub fn to_vec(&self) -> Vec<u8> {
        self.point.as_bytes().to_vec()
    }
}

impl fmt::Debug for KeyImage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyImage()")//, hex_fmt::HexFmt(self.as_bytes()))
    }
}

impl From<&RistrettoPrivate> for KeyImage {
    fn from(x: &RistrettoPrivate) -> Self {
        let P = RistrettoPublic::from(x);
        //let Hp = hash_to_point(&P);
        let Hp = RISTRETTO_BASEPOINT_POINT;
        let point = x.as_ref() * Hp;
        KeyImage {
            point: point.compress(),
        }
    }
}

// Many tests use this
impl From<u64> for KeyImage {
    fn from(n: u64) -> Self {
        let private_key = RistrettoPrivate::from(Scalar::from(n));
        Self::from(&private_key)
    }
}

impl From<[u8; 32]> for KeyImage {
    fn from(src: [u8; 32]) -> Self {
        Self {
            point: CompressedRistretto::from_slice(&src),
        }
    }
}

impl AsRef<CompressedRistretto> for KeyImage {
    fn as_ref(&self) -> &CompressedRistretto {
        &self.point
    }
}

impl AsRef<[u8; 32]> for KeyImage {
    fn as_ref(&self) -> &[u8; 32] {
        self.point.as_bytes()
    }
}

impl AsRef<[u8]> for KeyImage {
    fn as_ref(&self) -> &[u8] {
        &self.point.as_bytes()[..]
    }
}

impl TryFrom<&[u8]> for KeyImage {
    type Error = crate::error::Error;
    fn try_from(src: &[u8]) -> Result<Self, crate::error::Error> {
        if src.len() != 32 {
            return Err(crate::error::Error::from(crate::error::Error::LengthMismatch(
                32,
                src.len(),
            )));
        }
        Ok(Self {
            point: CompressedRistretto::from_slice(src),
        })
    }
}

//derive_repr_bytes_from_as_ref_and_try_from!(KeyImage, U32);
//derive_prost_message_from_repr_bytes!(KeyImage);
//derive_core_cmp_from_as_ref!(KeyImage, [u8; 32]);
