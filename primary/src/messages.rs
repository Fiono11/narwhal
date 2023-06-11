use crate::core::TxHash;
use crate::election::ElectionId;
// Copyright(C) Facebook, Inc. and its affiliates.
use crate::error::{DagError, DagResult};
use crate::primary::Round;
use config::{Committee, WorkerId};
use ed25519_dalek::{Digest as _, Sha512};
use crypto::{Digest, PublicKey as PublicAddress, Signature, SignatureService};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::{TryInto, TryFrom};
use std::fmt;

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> TxHash;
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Header {
    pub author: PublicAddress,
    pub round: Round,
    //pub payload: BTreeMap<TxHash, WorkerId>,
    //pub parents: BTreeSet<TxHash>,
    pub payload: (TxHash, ElectionId),
    pub id: TxHash,
    pub signature: Signature,
    pub commit: bool,
}

impl Header {
    pub async fn new(
        author: PublicAddress,
        round: Round,        
        payload: (TxHash, ElectionId),
        //payload: BTreeMap<TxHash, WorkerId>,
        //parents: BTreeSet<TxHash>,
        signature_service: &mut SignatureService,
        commit: bool,
    ) -> Self {
        let header = Self {
            author,
            round,
            payload,
            //parents,
            id: TxHash::default(),
            signature: Signature::default(),
            commit,
        };
        let id = header.digest();
        let signature = signature_service.request_signature(id.clone()).await;
        Self {
            id,
            signature,
            ..header
        }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the header id is well formed.
        ensure!(self.digest() == self.id, DagError::InvalidHeaderId);

        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(voting_rights > 0, DagError::UnknownAuthority(self.author.clone()));

        // Ensure all worker ids are correct.
        /*for worker_id in self.payload.values() {
            committee
                .worker(&PK(self.author.to_bytes()), &worker_id)
                .map_err(|_| DagError::MalformedHeader(self.id.clone()))?;
        }*/

        Ok(())

        // Check the signature.
        //self.signature
            //.verify(&self.id, &self.author)
            //.map_err(DagError::from)
    }
}

impl Hash for Header {
    fn digest(&self) -> TxHash {
        let mut hasher = Sha512::new();
        hasher.update(self.author);
        //hasher.update(self.round.to_le_bytes());
        //for (x, y) in &self.payload {
            hasher.update(self.payload.0.clone());
            hasher.update(self.payload.1.clone());
            //hasher.update(y.to_le_bytes());
        //}
        //for x in &self.parents {
            //hasher.update(x);
        //}
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B{}({}, {})",
            self.id,
            self.round,
            self.author,
            self.payload.0.size(),
        )
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}({})", self.round, self.id)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub id: TxHash,
    pub round: Round,
    pub origin: PublicAddress,
    pub author: PublicAddress,
    pub signature: Signature,
}

impl Vote {
    pub async fn new(
        header: &Header,
        author: &PublicAddress,
        signature_service: &mut SignatureService,
    ) -> Self {
        let vote = Self {
            id: header.id.clone(),
            round: header.round,
            origin: header.author.clone(),
            author: author.clone(),
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            DagError::UnknownAuthority(self.author.clone())
        );

        // Check the signature.
        //self.signature
            //.verify(&self.digest(), &self.author)
            //.map_err(DagError::from)
        
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> TxHash {
        let mut hasher = Sha512::new();
        hasher.update(&self.id);
        hasher.update(self.round.to_le_bytes());
        hasher.update(&self.origin);
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
            self.author,
            self.id
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Certificate {
    pub header: Header,
    pub votes: Vec<(PublicAddress, Signature)>,
}

impl Certificate {
    pub fn genesis(committee: &Committee) -> Vec<Self> {
        committee
            .authorities
            .keys()
            .map(|name| Self {
                header: Header {
                    author: name.clone(),
                    ..Header::default()
                },
                ..Self::default()
            })
            .collect()
    }

    pub fn verify(&self, committee: &Committee) -> DagResult<()> {
        // Genesis certificates are always valid.
        if Self::genesis(committee).contains(self) {
            return Ok(());
        }

        // Check the embedded header.
        self.header.verify(committee)?;

        // Ensure the certificate has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), DagError::AuthorityReuse(name.clone()));
            let voting_rights = committee.stake(&name);
            ensure!(voting_rights > 0, DagError::UnknownAuthority(name.clone()));
            used.insert(name.clone());
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            DagError::CertificateRequiresQuorum
        );

        // Check the signatures.
        //Ed25519Signature::verify_batch(&self.digest(), &self.votes).map_err(DagError::from)
        Ok(())
    }

    pub fn round(&self) -> Round {
        self.header.round
    }

    pub fn origin(&self) -> PublicAddress {
        self.header.author.clone()
    }
}

impl Hash for Certificate {
    fn digest(&self) -> TxHash {
        let mut hasher = Sha512::new();
        hasher.update(&self.header.id);
        hasher.update(self.round().to_le_bytes());
        hasher.update(&self.origin());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: C{}({}, {})",
            self.digest(),
            self.round(),
            self.origin(),
            self.header.id
        )
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        let mut ret = self.header.id == other.header.id;
        ret &= self.round() == other.round();
        ret &= self.origin() == other.origin();
        ret
    }
}
