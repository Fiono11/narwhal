// Copyright (c) 2018-2022 The MobileCoin Foundation

pub use mc_crypto_ring_signature::{proptest_fixtures::*, CurveScalar, Scalar};

use crate::{amount::Amount, MaskedAmount};
use mc_crypto_keys::RistrettoPublic;
use proptest::prelude::*;

prop_compose! {
    /// Generates an arbitrary masked_amount with value in [0,max_value].
    /// Of token_id = 0
    pub fn arbitrary_masked_amount(max_value: u64, shared_secret: RistrettoPublic)
                (value in 0..=max_value) -> MaskedAmount {
            let amount = Amount {
                value,
            };
            MaskedAmount::new(amount, &shared_secret).unwrap()
    }
}
