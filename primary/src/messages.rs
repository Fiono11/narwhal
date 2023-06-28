use crate::election::ElectionId;
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::primary::Round;
use crate::proposer::TxHash;
use config::Committee;
use crypto::{Digest, PublicKey as PublicAddress, Signature, SignatureService};
use ed25519_dalek::{Digest as _, Sha512};
use serde::{Deserialize, Serialize};

use std::collections::BTreeSet;
use std::convert::TryInto;
use std::fmt;

pub type ProposalId = Digest;

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> TxHash;
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Proposal {
    pub author: PublicAddress,
    pub votes: BTreeSet<(TxHash, ElectionId)>,
    pub signature: Signature,
    pub id: ProposalId,
    pub round: Round,
}

impl Proposal {
    pub async fn new(
        round: Round,
        author: PublicAddress,
        votes: BTreeSet<(Digest, ElectionId)>,
        signature_service: &mut SignatureService,
    ) -> Self {
        let header = Self {
            round,
            author,
            votes,
            signature: Signature::default(),
            id: Digest::default(),
        };
        let id = header.digest();
        let signature = signature_service.request_signature(Digest::default()).await;
        Self {
            id,
            signature,
            ..header
        }
    }

    pub fn verify(&self, _committee: &Committee) -> DagResult<()> {
        // Ensure the header id is well formed.
        ensure!(self.digest() == self.id, DagError::InvalidHeaderId);

        // Check the signature.
        self.signature
            .verify(&Digest::default(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for Proposal {
    fn digest(&self) -> TxHash {
        let mut hasher = Sha512::new();
        hasher.update(self.author);
        for vote in &self.votes {
            hasher.update(vote.0.clone());
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProposalVote {
    pub election_round: Round,
    pub proposals: BTreeSet<ProposalId>,
    pub proposals_round: Round,
    pub commit: bool,
    pub author: PublicAddress,
    pub signature: Signature,
    pub id: Digest,
}

impl ProposalVote {
    pub async fn new(
        election_round: Round,
        proposals: BTreeSet<ProposalId>,
        proposals_round: Round,
        commit: bool,
        author: PublicAddress,
        signature_service: &mut SignatureService,
        //exceptions: BTreeSet<ElectionId>,
    ) -> Self {
        let vote = Self {
            election_round,
            proposals,
            proposals_round,
            signature: Signature::default(),
            commit,
            author,
            id: Digest::default(),
            //exceptions,
        };
        let id = vote.digest();
        let signature = signature_service.request_signature(Digest::default()).await;
        Self {
            id,
            signature,
            ..vote
        }
    }

    pub fn verify(&self, _committee: &Committee) -> DagResult<()> {
        // Ensure the header id is well formed.
        ensure!(self.digest() == self.id, DagError::InvalidHeaderId);

        // Check the signature.
        self.signature
            .verify(&Digest::default(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for ProposalVote {
    fn digest(&self) -> TxHash {
        let mut hasher = Sha512::new();
        hasher.update(self.election_round.to_le_bytes());
        for proposal in &self.proposals {
            hasher.update(proposal.0.clone());
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for ProposalVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.digest(),
            self.proposals_round,
            self.election_round,
            self.author,
        )
    }
}

impl fmt::Display for ProposalVote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.proposals_round, self.digest())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vote {
    pub round: Round,
    pub value: Digest,
    pub election_id: ElectionId,
    pub proposal_round: Round,
    pub commit: bool,
    pub author: PublicAddress,
    pub signature: Signature,
    pub vote_id: Digest,
    pub proposal_id: ProposalId,
}

impl Vote {
    pub async fn new(
        round: Round,
        value: Digest,
        election_id: ElectionId,
        proposal_round: Round,
        commit: bool,
        author: PublicAddress,
        proposal_id: ProposalId,
        signature_service: &mut SignatureService,
    ) -> Self {
        let vote = Self {
            round,
            author,
            value,
            proposal_round,
            election_id,
            signature: Signature::default(),
            vote_id: Digest::default(),
            commit,
            proposal_id,
        };
        let vote_id = vote.digest();
        let signature = signature_service.request_signature(Digest::default()).await;
        Self {
            vote_id,
            signature,
            ..vote
        }
    }

    pub fn verify(&self, _committee: &Committee) -> DagResult<()> {
        // Ensure the header id is well formed.
        ensure!(self.digest() == self.vote_id, DagError::InvalidHeaderId);

        // Check the signature.
        self.signature
            .verify(&Digest::default(), &self.author)
            .map_err(DagError::from)
    }
}

impl Hash for Vote {
    fn digest(&self) -> TxHash {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.value);
        hasher.update(self.election_id.clone());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.digest(),
            self.round,
            self.value,
            self.election_id,
        )
    }
}

impl fmt::Display for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.digest())
    }
}
