// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Validation routines for a MobileCoin transaction

mod error;
mod validate;

pub use self::{
    error::{TransactionValidationError, TransactionValidationResult},
    validate::{
        validate, validate_number_of_inputs,
        validate_number_of_outputs, validate_ring_sizes, validate_signature,
    },
};
