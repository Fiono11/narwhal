// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A simple generator cache

use super::{generators, PedersenGens};
use alloc::collections::BTreeMap;

/// GeneratorCache is a simple object which caches computations of
/// generator: TokenId -> PedersenGens
///
/// This is intended just to be used in the scope of constructing or validating
/// a single transaction, and we therefore don't require it to be constant-time.
#[derive(Default, Clone)]
pub struct GeneratorCache {
    cache: PedersenGens,
}

impl GeneratorCache {
    /// Get (and if necessary, cache) the Pedersen Generators corresponding to
    /// a particular token id.
    pub fn get(&mut self) -> &PedersenGens {
        &self.cache
    }
}
