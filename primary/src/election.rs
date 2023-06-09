use std::collections::BTreeSet;
use crypto::{PublicKey as PublicAddress, Digest};

use crate::{Round, Header, constants::{QUORUM, SEMI_QUORUM}};

#[derive(Debug, Clone)]
pub struct Election {
    pub votes: BTreeSet<PublicAddress>,
    pub commits: BTreeSet<PublicAddress>,
    pub decided: bool,
    pub own_commit: Option<Digest>,
    pub highest: Option<Digest>,
    pub proof_round: Option<Round>,
    pub round: Round,
    pub own_vote: Option<Digest>,
}

impl Election {
    pub fn new() -> Self {
        Self {
            votes: BTreeSet::new(),
            commits: BTreeSet::new(),
            decided: false,
            own_commit: None,
            highest: None,
            proof_round: None,
            round: 0,
            own_vote:None,
        }
    }
}