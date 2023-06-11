use std::collections::{BTreeSet, HashMap};
use crypto::{PublicKey as PublicAddress, Digest};

use crate::{Round, Header, constants::{QUORUM, SEMI_QUORUM}, core::TxHash};

pub type ElectionId = Digest;

#[derive(Debug)]
pub struct Election {
    pub round: Round,
    pub tallies: HashMap<Round, Tally>,
    pub decided: bool,
    pub commit: Option<Digest>,
    pub highest: Option<Digest>,
    pub proof_round: Option<Round>,
    pub voted: bool,
    pub committed: bool,
}

impl Election {
    pub fn new() -> Self {
        Self {
            round: 0,
            tallies: HashMap::new(),
            decided: false,
            commit: None,
            highest: None,
            proof_round: None,
            voted: false,
            committed: false,
        }
    }

    pub fn insert_vote(&mut self, tx_hash: Digest, commit: bool, round: Round, author: PublicAddress) {
        if !commit {
            let tally = self.tallies.get_mut(&round).unwrap();
            if let Some(highest) = self.highest.clone() {
                if tx_hash > highest {
                    self.highest = Some(tx_hash.clone());
                }
            }
            match tally.votes.get_mut(&tx_hash) {
                Some(btreeset) => {
                    btreeset.insert(author);
                }
                None => {
                    let mut btreeset = BTreeSet::new();
                    btreeset.insert(author);
                    tally.votes.insert(tx_hash, btreeset);
                }
            }
        }
        else {
            let tally = self.tallies.get_mut(&round).unwrap();
            match tally.commits.get_mut(&tx_hash) {
                Some(btreeset) => {
                    btreeset.insert(author);
                }
                None => {
                    let mut btreeset = BTreeSet::new();
                    btreeset.insert(author);
                    tally.votes.insert(tx_hash, btreeset);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Tally {
    pub votes: HashMap<TxHash, BTreeSet<PublicAddress>>,
    pub commits: HashMap<TxHash, BTreeSet<PublicAddress>>,
}

impl Tally {
    pub fn new() -> Self {
        Self {
            votes: HashMap::new(),
            commits: HashMap::new(),
        }
    }

    pub fn find_quorum_of_votes(&self) -> Option<&TxHash> {
        for (tx_hash, vote_set) in &self.votes {
            if vote_set.len() >= QUORUM {
                return Some(tx_hash);
            }
        }
        None
    }

    pub fn find_quorum_of_commits(&self) -> Option<&TxHash> {
        for (tx_hash, commit_set) in &self.commits {
            if commit_set.len() >= QUORUM {
                return Some(tx_hash);
            }
        }
        None
    }
}