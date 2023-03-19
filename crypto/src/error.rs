// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Errors which can occur in connection to RingMLSAG signatures

use serde::{Deserialize, Serialize};

/// An error which can occur when signing or verifying an MLSAG
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Error {
    /// Incorrect length for array copy, provided `{0}`, required `{1}`.
    LengthMismatch(usize, usize),

    /// Index out of bounds
    IndexOutOfBounds,

    /// Invalid curve point
    InvalidCurvePoint,

    /// Invalid curve scalar
    InvalidCurveScalar,

    /// The signature was not able to be validated
    InvalidSignature,

    /// Failed to compress/decompress a KeyImage
    InvalidKeyImage,

    /// Value not conserved
    ValueNotConserved,

    ResizeError,
    
    /// The specified algorithm does not match what was expected
    AlgorithmMismatch,
    /// The provided public key is invalid
    InvalidPublicKey,
    /// The provided private key is invalid
    InvalidPrivateKey,
    /// The signature was not able to be validated
    SignatureMismatch,
    /// There was an opaque error returned by another crate or library
    InternalError,
}

/*impl From<mc_util_repr_bytes::LengthMismatch> for Error {
    fn from(src: mc_util_repr_bytes::LengthMismatch) -> Self {
        Self::LengthMismatch(src.found, src.expected)
    }
}*/
