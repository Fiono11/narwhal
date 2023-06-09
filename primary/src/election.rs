use std::collections::{BTreeSet, HashMap};
use crypto::{PublicKey as PublicAddress, Digest};

use crate::{Round, Header, constants::{QUORUM, SEMI_QUORUM}};

pub struct Election {
    pub current_round: Round,
    pub tallies: HashMap<Round, Tally>,
    pub decided: bool,
    pub own_commit: Option<Digest>,
    pub highest: Option<Digest>,
    pub proof_round: Option<Round>,
    pub own_vote: Option<Digest>,
}

impl Election {
    pub fn new() -> Self {
        Self {
            current_round: 0,
            tallies: HashMap::new(),
            decided: false,
            own_commit: None,
            highest: None,
            proof_round: None,
            own_vote: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Tally {
    pub votes: BTreeSet<PublicAddress>,
    pub commits: BTreeSet<PublicAddress>,
}

impl Tally {
    pub fn new() -> Self {
        Self {
            votes: BTreeSet::new(),
            commits: BTreeSet::new(),
        }
    }
}