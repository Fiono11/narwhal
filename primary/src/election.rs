use std::collections::BTreeSet;
use crypto::PublicKey as PublicAddress;

#[derive(Debug)]
pub struct Election {
    pub votes: BTreeSet<PublicAddress>,
    pub commits: BTreeSet<PublicAddress>,
    //pub voted: bool,
    //pub committed: bool,
    pub decided: bool,
}

impl Election {
    pub fn new() -> Self {
        Self {
            votes: BTreeSet::new(),
            commits: BTreeSet::new(),
            //voted: false,
            //committed: false,
            decided: false,
        }
    }
}