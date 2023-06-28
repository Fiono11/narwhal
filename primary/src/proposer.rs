use async_recursion::async_recursion;
use bytes::Bytes;
use std::collections::{BTreeSet, HashMap};
use std::convert::TryInto;
use std::pin::Pin;

use std::net::SocketAddr;
use ed25519_dalek::{Digest as _, Sha512};
use crate::constants::{NUMBER_OF_NODES, QUORUM, NUMBER_OF_CORRECT_NODES};
use crate::election::{Election, ElectionId, Timer, self};
use crate::error::DagResult;
use crate::messages::{Proposal, Vote, ProposalVote, ProposalId};
use crate::primary::{PrimaryMessage, Round};
use config::Committee;
use crypto::{Digest, PublicKey, SignatureService};
use log::info;
use network::SimpleSender;

//#[cfg(feature = "benchmark")]
//use log::info;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};
// Trait for creating a seeded RNG
// Trait for shuffling a slice
// An RNG with a fixed size seed

pub type TxHash = Digest;

/// The proposer creates new headers and send them to the core for broadcasting and further processing.
pub struct Proposer {
    /// The public key of this primary.
    name: PublicKey,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// The size of the headers' payload.
    header_size: usize,
    /// The maximum delay to wait for batches' digests.
    max_header_delay: u64,

    /// Receives the parents to include in the next header (along with their round number).
    rx_core: Receiver<(Vec<Digest>, Round)>,
    /// Receives the batches' digests from our workers.
    rx_workers: Receiver<(TxHash, ElectionId)>,
    /// Sends newly created headers to the `Core`.
    tx_core: Sender<Proposal>,

    /// The current round of the dag.
    round: Round,
    /// Holds the batches' digests waiting to be included in the next header.
    digests: Vec<(TxHash, ElectionId)>,
    /// Keeps track of the size (in bytes) of batches' digests that we received so far.
    payload_size: usize,
    elections: HashMap<Round, HashMap<ElectionId, Election>>,
    addresses: Vec<SocketAddr>,
    byzantine: bool,
    payloads: HashMap<Round, BTreeSet<Digest>>,
    proposals: Vec<(TxHash, ElectionId)>,
    votes: HashMap<ProposalId, BTreeSet<(TxHash, ElectionId)>>,
    all_votes: HashMap<ProposalId, BTreeSet<ElectionId>>,
    network: SimpleSender,
    rx_primaries: Receiver<PrimaryMessage>,
    other_primaries: Vec<SocketAddr>,
    pending_votes: HashMap<Round, BTreeSet<Vote>>,
    committee: Committee,
    //leader: PublicKey,
    decided: BTreeSet<ElectionId>,
    active_elections: BTreeSet<ElectionId>,
    decided_elections: HashMap<Digest, bool>,
    own_proposals: Vec<Round>,
    all_proposals: HashMap<ProposalId, BTreeSet<ElectionId>>,
    decided_headers: HashMap<Round, BTreeSet<Digest>>,
    active_headers: BTreeSet<Digest>,
    proposals_per_round: HashMap<Round, BTreeSet<ProposalId>>,
    the_proposals: HashMap<Round, HashMap<ProposalId, BTreeSet<(TxHash, ElectionId)>>>,
    proposals_sent: HashMap<Round, bool>,
    unique_elections: HashMap<ProposalId, u64>,
    pending_commits: BTreeSet<ProposalId>,
}

impl Proposer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        header_size: usize,
        max_header_delay: u64,
        rx_core: Receiver<(Vec<Digest>, Round)>,
        rx_workers: Receiver<(TxHash, ElectionId)>,
        tx_core: Sender<Proposal>,
        addresses: Vec<SocketAddr>,
        byzantine: bool,
        rx_primaries: Receiver<PrimaryMessage>,
        other_primaries: Vec<SocketAddr>,
        leader: PublicKey,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                signature_service,
                header_size,
                max_header_delay,
                rx_core,
                rx_workers,
                tx_core,
                round: 0,
                digests: Vec::with_capacity(2 * header_size),
                payload_size: 0,
                proposals: Vec::new(),
                elections: HashMap::new(),
                addresses,
                byzantine,
                payloads: HashMap::new(),
                network: SimpleSender::new(),
                rx_primaries,
                votes: HashMap::new(),
                all_votes: HashMap::new(),
                other_primaries,
                pending_votes: HashMap::new(),
                committee,
                //leader,
                decided: BTreeSet::new(),
                active_elections: BTreeSet::new(),
                decided_elections: HashMap::new(),
                own_proposals: Vec::new(),
                all_proposals: HashMap::new(),
                decided_headers: HashMap::new(),
                active_headers: BTreeSet::new(),
                proposals_per_round: HashMap::new(),
                the_proposals: HashMap::new(),
                proposals_sent: HashMap::new(),
                unique_elections: HashMap::new(),
                pending_commits: BTreeSet::new(),
            }
            .run()
            .await;
        });
    }

    #[async_recursion]
    async fn process_proposal(
        &mut self,
        proposal: &Proposal,
        timer: &mut Pin<&mut tokio::time::Sleep>,
    ) -> DagResult<()> {

        if !self.byzantine {
            proposal.verify(&self.committee).unwrap();
        //info!("Received proposal from {} with {} votes in round {} with id {}", proposal.author, proposal.votes.len() ,proposal.round, proposal.id);

        self.votes.insert(proposal.id.clone(), proposal.votes.clone());

        //info!("Inserted {:?} in {:?}", proposal.votes.clone(), proposal.id.clone());

        // insert the proposal
        match self.the_proposals.get_mut(&proposal.round) {
            Some(proposals_ids) => {
                match proposals_ids.get_mut(&proposal.id) {
                    Some(p) => {
                        for (tx_hash, election_id) in &proposal.votes {
                            //self.active_elections.insert(election_id.clone());
                            p.insert((tx_hash.clone(), election_id.clone()));
                        }
                    }
                    None => {
                        proposals_ids.insert(proposal.id.clone(), proposal.votes.clone());
                        //for (_, election_id) in &proposal.votes {
                            //self.active_elections.insert(election_id.clone());
                        //}
                    }
                }
            }
            None => {
                self.proposals_sent.insert(proposal.round, false);
                let mut proposals_ids = HashMap::new();
                proposals_ids.insert(proposal.id.clone(), proposal.votes.clone());
                self.the_proposals.insert(proposal.round, proposals_ids);
            }
        }

        match self.proposals_per_round.get_mut(&proposal.round) {
            Some(proposals) => {
                proposals.insert(proposal.id.clone());
            }
            None => {
                let mut proposals_ids = BTreeSet::new();
                proposals_ids.insert(proposal.id.clone());
                self.proposals_per_round.insert(proposal.round, proposals_ids);
            }
        }

        // vote on proposals if received at least 2f + 1
        let proposals = self.proposals_per_round.get(&proposal.round).unwrap();

        //info!("PROPOSALS of round {}: {:?}", proposal.round, self.the_proposals.get(&proposal.round).unwrap());
        
        let sent = self.proposals_sent.get_mut(&proposal.round).unwrap();

        if proposals.len() == NUMBER_OF_CORRECT_NODES && !*sent {//&& timer.is_elapsed() {
            let mut hasher = Sha512::new();

            for id in proposals {
                hasher.update(id);
            }
            let proposal_id = Digest(hasher.finalize()[..32].try_into().unwrap());
            //let mut proposal_ids = BTreeSet::new();
            //for proposal_id in proposals.keys() {
                //proposal_ids.insert(proposal_id.clone());
            //}
            let proposal_vote = Vote::new(0, proposal_id.clone(), proposal_id.clone(), proposal.round, false, self.name, proposal.id.clone(), &mut self.signature_service).await;
            // broadcast the proposal vote
            let bytes = bincode::serialize(&PrimaryMessage::Vote(proposal_vote.clone()))
                .expect("Failed to serialize our own header");
            let _handlers = self
                .network
                .broadcast(self.addresses.clone(), Bytes::from(bytes))
                .await;

            *sent = true;

            let mut unique_election_ids = BTreeSet::new();

            if let Some(proposals) = self.the_proposals.get(&proposal.round) {
                for proposal_id in proposals.keys() {
                    if let Some(set) = proposals.get(&proposal_id) {
                        for (_, election_id) in set {
                            if !self.active_elections.contains(&election_id) {
                                unique_election_ids.insert(election_id.clone());
                                self.active_elections.insert(election_id.clone());
                            }
                        }
                    }
                }
            }

            //info!("Created {} -> {:?}", unique_election_ids.len(), proposal_id);

            self.unique_elections.insert(proposal_id.clone(), unique_election_ids.len() as u64);
        }

        /*match self.proposals_per_round.get_mut(&proposal.round) {
            Some(proposals) => {
                proposals.insert(proposal.id.clone());
            }
            None => {
                let mut proposals = BTreeSet::new();
                proposals.insert(proposal.id.clone());
                self.proposals_per_round.insert(proposal.round, proposals);
            }
        }

        let election_ids: Vec<ElectionId> = proposal.votes.iter().map(|(_, election_id)| election_id.clone()).collect();
        let mut exceptions = BTreeSet::new();

        for election_id in &election_ids {
            for (proposal_id, proposal_election_ids) in &self.all_proposals {
                if proposal_election_ids.contains(election_id) {
                    for (round, proposal_ids) in &self.proposals_per_round {
                        if proposal_ids.contains(&proposal_id) {
                            if let Some(round_elections) = self.elections.get_mut(&round) {
                                if let Some(election) = round_elections.get_mut(election_id) {
                                    election.exceptions.insert(election_id.clone());
                                    exceptions.insert(election_id.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        // election.insert(exceptions)

        if !self.byzantine {
            self.decided_elections.insert(proposal.id.clone(), false);

        if let None = self.elections.get(&proposal.round) {
            self.elections.insert(proposal.round, HashMap::new());
        }
        let elections = self.elections.get_mut(&proposal.round).unwrap();
        self.votes.insert(proposal.id.clone(), proposal.votes.clone());
            //info!(
                //"Received proposal {} from {} in round {}",
                //proposal.id, proposal.author, self.round
            //);

        let mut proposals = BTreeSet::new();
        proposals.insert(proposal.id.clone());
        
                    //for (tx_hash, election_id) in &proposal.votes {
                        let vote = Vote::new(
                            0, 
                            proposal.id.clone(),
                            proposal.id.clone(),
                            proposal.round,
                            false,
                            proposal.author,
                            &mut self.signature_service,
                        )
                        .await;
                        
                        //self.proposals.retain(|&(_, ref p_election_id)| p_election_id != election_id);
               
                        match elections.get_mut(&proposal.id) {
                            Some(election) => {
                                election.insert_vote(&vote);
                                election.exceptions = exceptions.clone();
                            }
                            None => {
                                let mut election = Election::new();
                                election.insert_vote(&vote);
                                election.exceptions = exceptions.clone();
                                //elections.insert(header.round, elections);

                                if !self.active_headers.contains(&proposal.id) {
                                    info!("Created {} -> {:?}", proposal.votes.len(), proposal.id);
                                    self.active_headers.insert(proposal.id.clone());
                                }

                                elections.insert(proposal.id.clone(), election);

                                let mut elections_ids = BTreeSet::new();

                                //#[cfg(feature = "benchmark")]
                                //for (_tx_hash, election_id) in &header.votes {
                                    //info!("Created1 {} -> {:?}", tx_hash, election_id);
                                    elections_ids.insert(proposal.id.clone());
                                    if !self.active_elections.contains(&proposal.id)
                                        && !self.decided.contains(&proposal.id)
                                    {
                                        // NOTE: This log entry is used to compute performance.
                                        self.active_elections.push(proposal.id.clone());
                                    }
                                //}
                            }
                        }
            
                        // insert vote
                        //election.insert_vote(&vote);
                    //}
            let proposals = self.proposals_per_round.get(&proposal.round).unwrap();
            if proposals.len() >= QUORUM {
                let proposal_vote = ProposalVote::new(0, proposals.clone(), proposal.round, false, self.name, &mut self.signature_service, exceptions).await;
                let bytes = bincode::serialize(&PrimaryMessage::ProposalVote(proposal_vote.clone()))
                    .expect("Failed to serialize our own header");
                let _handlers = self
                    .network
                    .broadcast(self.addresses.clone(), Bytes::from(bytes))
                    .await;
            }
                    /*if self.pending_votes.contains_key(&proposal.round) {
                        if let Some(votes) = self.pending_votes.remove(&proposal.round) {
                            for vote in votes {
                                //info!("Inserting pending vote {}", &vote);
                                self.process_vote(&vote, timer).await;
                            }
                        }
                    }*/
                }*/
            }
        Ok(())
    }

    /*#[async_recursion]
    async fn process_proposal_vote(
        &mut self,
        proposal_vote: &ProposalVote,
        timer: &mut Pin<&mut tokio::time::Sleep>,
    ) -> DagResult<()> {

        //info!("Received proposal vote from {} in round {} with {} proposals", proposal_vote.author, proposal_vote.proposals_round, proposal_vote.proposals.len());

        if let None = self.elections.get(&proposal_vote.proposals_round) {
            self.elections.insert(proposal_vote.proposals_round, HashMap::new());
        }

        let mut hasher = Sha512::new();

        // BTreeSet maintains order, so simply iterating over it will give us the proposals in order.
        let ordered_proposals = proposal_vote.proposals.iter();

        let mut votes = BTreeSet::new();

        // Update hasher with each proposal digest bytes
        for proposal in ordered_proposals {
            if let Some(v) = self.votes.get(&proposal) {
                //info!("proposal: {:?} has {} votes", proposal, self.votes.get(&proposal).unwrap().len());
                for (_, election_id) in v {
                    //info!("election id: {:?}", election_id.clone());
                    if !self.active_elections.contains(election_id) {
                        votes.insert(election_id.clone());
                    }
                }
            }
            hasher.update(proposal);
        }

        // Finalize the hash and take the first 32 bytes as Digest
        let hash_result = hasher.finalize();
        let proposal_id = Digest(hash_result[..32].try_into().unwrap());

        //info!("inserted {} votes of proposal {}", votes.len(), proposal_id.clone());

        //self.all_votes.insert(proposal_id.clone(), votes);

        let elections = self.elections.get_mut(&proposal_vote.proposals_round).unwrap();

        if let None = elections.get_mut(&proposal_id) {

            //info!("Created {} -> {:?}", proposal_vote.proposals.len(), proposal_id);   

            elections.insert(proposal_id.clone(), Election::new());
        
            let vote: Vote = Vote::new(0, proposal_id.clone(), proposal_id.clone(), proposal_vote.proposals_round, false, self.name, &mut self.signature_service).await;
            let bytes = bincode::serialize(&PrimaryMessage::Vote(vote.clone()))
                .expect("Failed to serialize our own header");
            let _handlers = self
                .network
                .broadcast(self.addresses.clone(), Bytes::from(bytes))
                .await;
        }

        Ok(())
    }*/

        /*for proposal in &proposal_vote.proposals {
            let vote = Vote::new(proposal_vote.election_round, proposal.clone(), proposal.clone(), proposal_vote.proposals_round, proposal_vote.commit, proposal_vote.author, &mut self.signature_service).await;
            let mut election = Election::new();
            election.exceptions = proposal_vote.exceptions.clone();
            let mut hp = HashMap::new();
            hp.insert(proposal_vote.id.clone(), election);
            self.elections.insert(proposal_vote.proposals_round, hp);
            self.process_vote(&vote, timer);
        }

        for exception in &proposal_vote.exceptions {
            let mut proposal_id = Digest::default();
            for (proposal, proposal_election_ids) in &self.all_proposals {
                if proposal_election_ids.contains(exception) {
                    proposal_id = proposal.clone();
                }
            }
            let votes = self.votes.get(&proposal_id).unwrap();
            let mut value = Digest::default();
            for (tx_hash, id) in votes {
                if id == exception {
                    value = tx_hash.clone();
                }
            }

            match self.elections.get_mut(&proposal_vote.proposals_round) {
                Some(elections) => {
                    match elections.get_mut(&exception) {
                        Some(election) => {
                            if !election.voted_or_committed(&self.name, 0) {
                                let vote: Vote = Vote::new(0, value.clone(), exception.clone(), proposal_vote.proposals_round, false, self.name, &mut self.signature_service).await;
                                let bytes = bincode::serialize(&PrimaryMessage::Vote(vote.clone()))
                                    .expect("Failed to serialize our own header");
                                let _handlers = self
                                    .network
                                    .broadcast(self.addresses.clone(), Bytes::from(bytes))
                                    .await;
                            }
                        }
                        None => {
                            let vote: Vote = Vote::new(0, value.clone(), exception.clone(), proposal_vote.proposals_round, false, self.name, &mut self.signature_service).await;
                            let bytes = bincode::serialize(&PrimaryMessage::Vote(vote.clone()))
                                .expect("Failed to serialize our own header");
                            let _handlers = self
                                .network
                                .broadcast(self.addresses.clone(), Bytes::from(bytes))
                                .await;
                        }
                    }
                }
                None => {
                    let vote: Vote = Vote::new(0, value.clone(), exception.clone(), proposal_vote.proposals_round, false, self.name, &mut self.signature_service).await;
                    let bytes = bincode::serialize(&PrimaryMessage::Vote(vote.clone()))
                        .expect("Failed to serialize our own header");
                    let _handlers = self
                        .network
                        .broadcast(self.addresses.clone(), Bytes::from(bytes))
                        .await;
                }
            }
        }

        Ok(())
    }*/

    #[async_recursion]
    async fn process_vote(
        &mut self,
        vote: &Vote,
        timer: &mut Pin<&mut tokio::time::Sleep>,
    ) -> DagResult<()> {
        vote.verify(&self.committee).unwrap();
        /*if !vote.commit {
            info!(
                "Received a vote from {} for value {} in round {} of election {}",
                vote.author, vote.value, vote.round, vote.election_id
            );
        } else {
            info!(
                "Received a commit from {} for value {} in round {} of election {}",
                vote.author, vote.value, vote.round, vote.election_id
            );
        }*/
        let (tx_hash, election_id) = (vote.value.clone(), vote.election_id.clone());
        if !self.byzantine {
            match self.elections.get_mut(&vote.proposal_round) {
                Some(elections) => {
                        match elections.get_mut(&election_id) {
                            Some(election) => {
                                if !election.decided {
                                    election.insert_vote(&vote);
                                    if let Some(tally) = election.proposal_tallies.get(&vote.round) {
                                        if let Some(tx_hash) = election.find_quorum_of_commits() {

                                            if let Some(len) = self.unique_elections.get(&vote.election_id) {
                                                //if !self.decided.contains(&vote.election_id) {
                                                    info!(
                                                        "Committed {} -> {:?}",
                                                        len,
                                                        vote.election_id
                                                    );
                                                //}
                                                //self.decided.insert(vote.election_id.clone());

                                                self.round += 1;

                                                let deadline = Instant::now()
                                                    + Duration::from_millis(self.max_header_delay);
                                                timer.as_mut().reset(deadline);
                        
                                                election.decided = true;

                                            }

                                            //info!("ALL VOTES: {:?}", self.all_votes);

                                            /*match self.decided_headers.get_mut(&vote.proposal_round) {
                                                Some(headers) => {
                                                    for commit in &self.pending_commits {
                                                        if let Some(len) = self.unique_elections.get(&commit) {
                                                            headers.insert(commit.clone());
                                                            //self.pending_commits.remove(&commit);
                                                        }
                                                    }
                                                    if headers.len() == NUMBER_OF_NODES {
                                                        let mut len = 0;
                                                        for header in headers.iter() {
                                                            len += self.unique_elections.get(&header).unwrap();
                                                        }
                                                        info!(
                                                            "Committed {} -> {:?}",
                                                            len,
                                                            vote.election_id
                                                        );
                                                        self.decided_headers.remove(&vote.proposal_round);
                                                        self.round += 1;

                                                        let deadline = Instant::now()
                                                                + Duration::from_millis(self.max_header_delay);
                                                            timer.as_mut().reset(deadline);
                        
                                                            election.decided = true;
                                                    }*/
                                                    /*if !headers.contains(&vote.election_id) {
                                                            info!(
                                                                "Committed {} -> {:?}",
                                                                self.unique_elections.get(&vote.election_id).unwrap(),
                                                                vote.election_id
                                                            );
                            

                                                        headers.insert(vote.election_id.clone());
                                                    }*/

                                                //}
                                                /*None => {
                                                    match self.unique_elections.get(&vote.election_id) {
                                                        Some(len) => {
                                                            
                                                            match self.decided_headers.get_mut(&vote.proposal_round) {
                                                                Some(headers) => {
                                                                    headers.insert(vote.election_id.clone());
                                                                    for commit in &self.pending_commits {
                                                                        if let Some(len) = self.unique_elections.get(&commit) {
                                                                            headers.insert(commit.clone());
                                                                            //self.pending_commits.remove(&commit);
                                                                        }
                                                                    }
                                                                }   
                                                                None => {
                                                                    let mut btreeset = BTreeSet::new();
                                                                    btreeset.insert(vote.election_id.clone());
                                                                    for commit in &self.pending_commits {
                                                                        if let Some(len) = self.unique_elections.get(&commit) {
                                                                            btreeset.insert(commit.clone());
                                                                        }
                                                                    }
                                                                    self.decided_headers.insert(vote.proposal_round, btreeset);
                                                                }
                                                            }

                                                        }
                                                        None => {
                                                            info!("Vote from {} in round {} on proposal {} is pending!", vote.author, vote.proposal_round, vote.proposal_id);
                                                            self.pending_commits.insert(vote.proposal_id.clone());
                                                        }
                                                    }
                                                    
                                                }*/
                                            //}

                                            /*for commit in &self.pending_commits {
                                                if let Some(len) = self.unique_elections.get(&commit) {
                                                    info!(
                                                        "Committed {} -> {:?}",
                                                        len,
                                                        vote.election_id
                                                    );
                                                }
                                            }*/

                                            //self.all_votes.drain();

                                            //info!("ALL VOTES2: {:?}", self.all_votes);

                                            

                                            //for (tx_hash, election_id) in self.votes.get(&header_id).unwrap().iter() {
                                            //self.proposals.retain(|(_, id)| id != election_id);
            
                                            //self.decided.insert(election_id.clone());
            
                                            //#[cfg(not(feature = "benchmark"))]
                                            //info!("Committed {}", tx_hash);
                                            //election.decided = true;
                                            //info!("Committed1 {} -> {:?}", tx_hash, election_id);
                                            //}
                                            
        
                                            /*if self.decided_elections.get(&election_id).unwrap() == &false {
                                                #[cfg(feature = "benchmark")]
                                                // NOTE: This log entry is used to compute performance.
                                                //info!(
                                                    //"Committed {} -> {:?}",
                                                    //self.votes.get(&header_id).unwrap().len(),
                                                    //header_id
                                                //);
                                                //self.decided_elections.insert(election_id.clone(), true);
            
                                                info!("Round {} is decided!", election_id);
            
                                                self.round += 1;
                                                //self.leader = self.committee.leader(self.round as usize);
            
                                                let deadline = Instant::now()
                                                    + Duration::from_millis(self.max_header_delay);
                                                timer.as_mut().reset(deadline);
            
                                                election.decided = true;
            
                                            }
            
                                            return Ok(());*/
                                        }
                                        //if !election.committed {
                                        //own_header = header.clone();
                                        if let Some(tx_hash) = tally.find_quorum_of_votes() {
                                            if !election.voted_or_committed(&self.name, vote.round + 1) {
                                                election.commit = Some(tx_hash.clone());
                                                election.proof_round = Some(vote.round);
                                                let own_vote = Vote::new(
                                                    vote.round + 1,
                                                    tx_hash.clone(),
                                                    election_id,
                                                    vote.proposal_round,
                                                    true,
                                                    self.name,
                                                    vote.proposal_id.clone(),
                                                    &mut self.signature_service,
                                                )
                                                .await;
                                                election.insert_vote(&own_vote);
            
                                                // broadcast vote
                                                let bytes =
                                                    bincode::serialize(&PrimaryMessage::Vote(own_vote.clone()))
                                                        .expect("Failed to serialize our own header");
                                                let _handlers = self
                                                    .network
                                                    .broadcast(self.other_primaries.clone(), Bytes::from(bytes))
                                                    .await;
                                                //info!("Sending commit: {:?}", &own_vote);
                                            }
                                        } else if election.voted_or_committed(&self.name, vote.round)
                                            && ((tally.total_votes() >= QUORUM
                                                && *tally.timer.0.lock().unwrap() == Timer::Expired)
                                                || tally.total_votes() == NUMBER_OF_NODES)
                                            && !election.voted_or_committed(&self.name, vote.round + 1)
                                        {
                                            let mut highest = election.highest.clone().unwrap();
                                            let mut committed = false;
            
                                            if let Some(commit) = &election.commit {
                                                highest = commit.clone();
                                                committed = true;
                                            }
                                            let own_vote = Vote::new(
                                                vote.round + 1,
                                                highest,
                                                election_id,
                                                vote.proposal_round,
                                                committed,
                                                self.name,
                                                vote.proposal_id.clone(),
                                                &mut self.signature_service,
                                            )
                                            .await;
                                            election.insert_vote(&own_vote);
            
                                            // broadcast vote
                                            let bytes =
                                                bincode::serialize(&PrimaryMessage::Vote(own_vote.clone()))
                                                    .expect("Failed to serialize our own header");
                                            let _handlers = self
                                                .network
                                                .broadcast(self.other_primaries.clone(), Bytes::from(bytes))
                                                .await;
                                            //info!("Changing vote: {:?}", &own_vote);
                                        } else if !election.voted_or_committed(&self.name, vote.round) {
                                            let mut tx_hash = tx_hash;
                                            if let Some(highest) = &election.highest {
                                                tx_hash = highest.clone();
                                            }
                                            if let Some(commit) = &election.commit {
                                                tx_hash = commit.clone();
                                            }
            
                                            let own_vote = Vote::new(
                                                vote.round,
                                                tx_hash,
                                                election_id,
                                                vote.proposal_round,
                                                vote.commit,
                                                self.name,
                                                vote.proposal_id.clone(),
                                                &mut self.signature_service,
                                            )
                                            .await;
                                            election.insert_vote(&own_vote);
            
                                            // broadcast vote
                                            let bytes =
                                                bincode::serialize(&PrimaryMessage::Vote(own_vote.clone()))
                                                    .expect("Failed to serialize our own header");
                                            let _handlers = self
                                                .network
                                                .broadcast(self.other_primaries.clone(), Bytes::from(bytes))
                                                .await;
            
                                            //info!("Sending vote: {:?}", &own_vote);
                                        }
                                    }
                                }
                                //info!(
                                    //"Election of {:?}: {:?}",
                                    //&election_id,
                                    //self.elections.get(&vote.proposal_round).unwrap()
                                //);
                            }
                            None => match self.pending_votes.get_mut(&vote.proposal_round) {
                                Some(btreeset) => {
                                    //info!("Inserted vote {} into pending votes", &vote);
                                    btreeset.insert(vote.clone());
                                }
                                None => {
                                    //info!("Inserted vote {} into pending votes", &vote);
                                    let mut btreeset = BTreeSet::new();
                                    btreeset.insert(vote.clone());
                                    self.pending_votes.insert(vote.proposal_round, btreeset);
                                }
                            },
                        } 

                        //info!("ALL PROPOSALS: {:?}", self.all_proposals);
                        //info!("DECIDED HEADERS: {:?}", self.decided_headers);

                        let mut header_decided = true;
                            if let Some(e) = self.proposals_per_round.get(&vote.proposal_round) {
                                for election_id in e {
                                    match elections.get(&election_id) {
                                        Some(election) => {
                                            if !election.decided {
                                                header_decided = false;
                                                break;
                                            }
                                        }
                                        None => {
                                            header_decided = false;
                                            break;
                                        }
                                    }
                                }
                            }
                            else {
                                header_decided = false;
                            }

                        /*if header_decided {
                            match self.decided_headers.get_mut(&vote.proposal_round) {
                                Some(headers) => {
                                    if !headers.contains(&vote.election_id) {
                                        info!(
                                            "Committed {} -> {:?}",
                                            self.votes.get(&vote.election_id).unwrap().len(),
                                            vote.election_id
                                        );
                                        headers.insert(vote.election_id.clone());
                                    }
                                }
                                None => {
                                    info!(
                                        "Committed {} -> {:?}",
                                        self.votes.get(&vote.election_id).unwrap().len(),
                                        vote.election_id
                                    );
                                    let mut headers = BTreeSet::new();
                                    headers.insert(vote.election_id.clone());
                                    self.decided_headers.insert(vote.proposal_round, headers);
                                }
                            }
                        }*/

                        if let Some(headers) = self.decided_headers.get(&vote.proposal_round) {
                            if !headers.len() >= QUORUM && vote.proposal_round == self.round {
                                self.round += 1;

                                //info!("ADVANCED TO ROUND {}", self.round);
            
                                let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                                timer.as_mut().reset(deadline);
                            }
                        }
                    }
                None => {
                    let mut hp = HashMap::new();
                    let mut election = Election::new();
                    election.insert_vote(vote);
                    hp.insert(vote.election_id.clone(), election);
                    self.elections.insert(vote.proposal_round, hp);
                }
            }
        }
        Ok(())
    }

    async fn make_proposal(&mut self) {
        if !self.byzantine {
            let decided = &self.decided;
            let active_elections = &self.active_elections;

            //info!("PROPOSALS2: {}", self.proposals.len());

            self.proposals
                .retain(|(_, election_id)| !decided.contains(&election_id));
            self.proposals
                .retain(|(_, election_id)| !active_elections.contains(&election_id));

            //info!("PROPOSALS3: {}", self.proposals.len());

            let proposals = self.proposals.len();

            for i in 0..self.proposals.len() {
                if self.active_elections.contains(&self.proposals[i].1) {
                    self.proposals.remove(i);
                }
            }

            //info!("PROPOSALS: {}", self.proposals.len());

            // Make a new proposal.
            let proposal = Proposal::new(
                self.round,
                self.name.clone(),
                self.proposals.drain(..).collect(), // only drain if committed
                &mut self.signature_service,
            )
            .await;

            self.own_proposals.push(self.round);

            //info!(
                //"Making a new proposal {} from {} in round {} with {} proposals",
                //proposal.id, self.name, self.round, proposals
            //);

            //info!("PROPOSALS4: {}", self.proposals.len());

            let bytes = bincode::serialize(&PrimaryMessage::Proposal(proposal.clone()))
                .expect("Failed to serialize our own header");
            let _handlers = self
                .network
                .broadcast(self.addresses.clone(), Bytes::from(bytes))
                .await;
        }
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        let timer: tokio::time::Sleep = sleep(Duration::from_millis(self.max_header_delay));
        tokio::pin!(timer);
        let mut counter = 0;

        loop {
            tokio::select! {
                Some((tx_hash, election_id)) = self.rx_workers.recv() => {
                    if !self.byzantine {
                        //info!("Received tx hash {} and election id {}", tx_hash, election_id);
                        self.proposals.push((tx_hash, election_id));
                    }

                    //info!("TXS RECEIVED: {}", counter);
                    //info!("PROPOSALS: {}", self.proposals.len());

                    //info!("own proposals: {:?}", self.own_proposals);

                    if self.proposals.len() >= self.header_size && !self.own_proposals.contains(&self.round) {
                        self.make_proposal().await;
                    }

                    counter += 1;
                },

                () = &mut timer => {
                    //info!("PROPOSALS: {}", self.proposals.len());
                    //info!("EXPIRED!");
                    if self.proposals.len() > 0 && !self.own_proposals.contains(&self.round) {
                        self.make_proposal().await;
                    }

                    let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                    timer.as_mut().reset(deadline);
                },

                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    let _ = match message {
                        PrimaryMessage::Proposal(header) => self.process_proposal(&header, &mut timer).await,
                        PrimaryMessage::Vote(vote) => self.process_vote(&vote, &mut timer).await,
                        //PrimaryMessage::ProposalVote(proposal_vote) => self.process_proposal_vote(&proposal_vote, &mut timer).await,
                        _ => Ok(())
                    };
                },
            };
        }
    }
}
