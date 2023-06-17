use crate::election::ElectionId;
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::primary::Round;
use crate::proposer::TxHash;
use config::Committee;
use crypto::{Digest, PublicKey as PublicAddress, Signature, SignatureService};
use ed25519_dalek::{Digest as _, Sha512};
use serde::{Deserialize, Serialize};

use std::convert::TryInto;
use std::fmt;

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> TxHash;
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Header {
    pub author: PublicAddress,
    pub votes: Vec<(TxHash, ElectionId)>,
    pub signature: Signature,
    pub id: Digest,
    pub round: Round,
}

impl Header {
    pub async fn new(
        round: Round,
        author: PublicAddress,
        votes: Vec<(Digest, ElectionId)>,
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

impl Hash for Header {
    fn digest(&self) -> TxHash {
        let mut hasher = Sha512::new();
        hasher.update(self.author);
        //hasher.update(self.round.to_le_bytes());
        for vote in &self.votes {
            hasher.update(vote.0.clone());
        }
        //for x in &self.parents {
        //hasher.update(x);
        //}
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

/*impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({}, {})",
            self.payload.1,
            self.round,
            self.author,
            self.payload.0,
        )
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.id)
    }
}*/

/*#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HeaderVote {
    pub round: Round,
    pub tx_hash: Digest,
    pub commit: bool,
    pub election_id: Round,
}

impl HeaderVote {
    pub async fn new(
        round: Round,
        header_id: Digest,
        commit: bool,
        exceptions: Vec<TxHash>,
    ) -> Self {
        Self {
            round, commit, tx_hash: header_id, exceptions,
        }
    }
}*/

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Vote {
    pub round: Round,
    pub header_id: Digest,
    pub election_id: Round,
    pub commit: bool,
    pub author: PublicAddress,
    pub signature: Signature,
    pub vote_id: Digest,
}

impl Vote {
    pub async fn new(
        round: Round,
        header_id: Digest,
        election_id: Round,
        commit: bool,
        author: PublicAddress,
        signature_service: &mut SignatureService,
    ) -> Self {
        let vote = Self {
            round,
            author,
            header_id,
            election_id,
            signature: Signature::default(),
            vote_id: Digest::default(),
            commit,
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
        hasher.update(&self.header_id);
        hasher.update(self.election_id.to_le_bytes());
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
            self.header_id,
            self.election_id,
        )
    }
}

impl fmt::Display for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.digest())
    }
}
