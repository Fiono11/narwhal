// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A commitment to an output's amount, denominated in picoMOB.
//!
//! Amounts are implemented as Pedersen commitments. The associated private keys
//! are "masked" using a shared secret.

use crate::{
    amount::{Amount, AmountError},
    BlockVersion,
};

use mc_crypto_digestible::Digestible;
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_ring_signature::{CompressedCommitment, Scalar};

use prost::Message;
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

//mod v1;
//pub use v1::MaskedAmountV1;

mod v2;
pub use v2::MaskedAmount;
