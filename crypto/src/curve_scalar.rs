use curve25519_dalek_ng::scalar::Scalar;
use serde::{Serialize, Deserialize};

/// A curve scalar
#[derive(Copy, Clone, Default, Serialize, Deserialize, Debug)]
pub struct CurveScalar {
    /// The scalar value
    pub scalar: Scalar,
}

impl CurveScalar {
    /// Construct a `CurveScalar` by reducing a 256-bit little-endian integer
    /// modulo the group order \\( \ell \\).
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        Self {
            scalar: Scalar::from_bytes_mod_order(bytes),
        }
    }

    /// The little-endian byte encoding of the integer representing this Scalar.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.scalar.as_bytes()
    }
}

/*impl FromRandom for CurveScalar {
    fn from_random<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        Self {
            scalar: Scalar::random(csprng),
        }
    }
}*/

impl From<Scalar> for CurveScalar {
    #[inline]
    fn from(scalar: Scalar) -> Self {
        Self { scalar }
    }
}

impl From<u64> for CurveScalar {
    #[inline]
    fn from(val: u64) -> Self {
        Self {
            scalar: Scalar::from(val),
        }
    }
}

impl AsRef<[u8; 32]> for CurveScalar {
    #[inline]
    fn as_ref(&self) -> &[u8; 32] {
        self.scalar.as_bytes()
    }
}

impl From<&[u8; 32]> for CurveScalar {
    #[inline]
    fn from(src: &[u8; 32]) -> Self {
        Self {
            scalar: Scalar::from_bytes_mod_order(*src),
        }
    }
}

// Implements Ord, PartialOrd, PartialEq, Hash.
//derive_core_cmp_from_as_ref!(CurveScalar, [u8; 32]);

impl AsRef<[u8]> for CurveScalar {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.scalar.as_bytes()
    }
}

impl AsRef<Scalar> for CurveScalar {
    #[inline]
    fn as_ref(&self) -> &Scalar {
        &self.scalar
    }
}

impl From<CurveScalar> for Scalar {
    fn from(src: CurveScalar) -> Scalar {
        src.scalar
    }
}

/*impl ReprBytes for CurveScalar {
    type Error = Error;
    type Size = U32;
    fn to_bytes(&self) -> GenericArray<u8, U32> {
        self.scalar.to_bytes().into()
    }
    fn from_bytes(src: &GenericArray<u8, U32>) -> Result<Self, Error> {
        Ok(Self::from(&(*src).into()))
    }
}

impl fmt::Debug for CurveScalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CurveScalar({})", hex_fmt::HexFmt(self.as_bytes()))
    }
}

// Implements prost::Message. Requires Debug and ReprBytes32.
derive_prost_message_from_repr_bytes!(CurveScalar);
derive_try_from_slice_from_repr_bytes!(CurveScalar);*/

