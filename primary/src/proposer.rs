use async_recursion::async_recursion;
use bytes::Bytes;
use std::collections::{BTreeSet, HashMap};
use std::convert::TryInto;
use std::pin::Pin;
use crate::constants::{NUMBER_OF_CORRECT_NODES, NUMBER_OF_NODES, QUORUM};
use crate::election::{Election, ElectionId, Timer};
use crate::error::DagResult;
use crate::messages::{Proposal, ProposalId, Vote};
use crate::primary::{PrimaryMessage, Round};
use config::Committee;
use crypto::{Digest, PublicKey, SignatureService};
use ed25519_dalek::{Digest as _, Sha512};
use log::info;
use network::SimpleSender;
use std::net::SocketAddr;
use tokio::sync::mpsc::Receiver;
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
    /// Receives the batches' digests from our workers.
    rx_workers: Receiver<(TxHash, ElectionId)>,
    /// The current round of the dag.
    round: Round,
    elections: HashMap<Round, HashMap<ElectionId, Election>>,
    addresses: Vec<SocketAddr>,
    byzantine: bool,
    proposals: Vec<(TxHash, ElectionId)>,
    votes: HashMap<ProposalId, BTreeSet<(TxHash, ElectionId)>>,
    network: SimpleSender,
    rx_primaries: Receiver<PrimaryMessage>,
    other_primaries: Vec<SocketAddr>,
    pending_votes: HashMap<Round, BTreeSet<Vote>>,
    committee: Committee,
    decided: BTreeSet<ElectionId>,
    active_elections: BTreeSet<ElectionId>,
    own_proposals: Vec<Round>,
    decided_headers: HashMap<Round, BTreeSet<Digest>>,
    proposals_per_round: HashMap<Round, BTreeSet<ProposalId>>,
    the_proposals: HashMap<Round, HashMap<ProposalId, BTreeSet<(TxHash, ElectionId)>>>,
    proposals_sent: HashMap<Round, bool>,
    unique_elections: HashMap<ProposalId, u64>,
}

impl Proposer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        header_size: usize,
        max_header_delay: u64,
        rx_workers: Receiver<(TxHash, ElectionId)>,
        addresses: Vec<SocketAddr>,
        byzantine: bool,
        rx_primaries: Receiver<PrimaryMessage>,
        other_primaries: Vec<SocketAddr>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                signature_service,
                header_size,
                max_header_delay,
                rx_workers,
                round: 0,
                elections: HashMap::new(),
                addresses,
                byzantine,
                proposals: Vec::new(),
                votes: HashMap::new(),
                network: SimpleSender::new(),
                rx_primaries,
                other_primaries,
                pending_votes: HashMap::new(),
                committee,
                decided: BTreeSet::new(),
                active_elections: BTreeSet::new(),
                own_proposals: Vec::new(),
                decided_headers: HashMap::new(),
                proposals_per_round: HashMap::new(),
                the_proposals: HashMap::new(),
                proposals_sent: HashMap::new(),
                unique_elections: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    #[async_recursion]
    async fn process_proposal(
        &mut self,
        proposal: &Proposal,
    ) -> DagResult<()> {
        if !self.byzantine {
            proposal.verify(&self.committee).unwrap();

            self.votes
                .insert(proposal.id.clone(), proposal.votes.clone());

            // insert the proposal
            match self.the_proposals.get_mut(&proposal.round) {
                Some(proposals_ids) => {
                    match proposals_ids.get_mut(&proposal.id) {
                        Some(p) => {
                            for (tx_hash, election_id) in &proposal.votes {
                                p.insert((tx_hash.clone(), election_id.clone()));
                            }
                        }
                        None => {
                            proposals_ids.insert(proposal.id.clone(), proposal.votes.clone());
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
                    self.proposals_per_round
                        .insert(proposal.round, proposals_ids);
                }
            }

            // vote on proposals if received at least 2f + 1
            let proposals = self.proposals_per_round.get(&proposal.round).unwrap();

            let sent = self.proposals_sent.get_mut(&proposal.round).unwrap();

            if proposals.len() == NUMBER_OF_CORRECT_NODES && !*sent {
                let mut hasher = Sha512::new();

                for id in proposals {
                    hasher.update(id);
                }
                let proposal_id = Digest(hasher.finalize()[..32].try_into().unwrap());

                let proposal_vote = Vote::new(
                    0,
                    proposal_id.clone(),
                    proposal_id.clone(),
                    proposal.round,
                    false,
                    self.name,
                    proposal.id.clone(),
                    &mut self.signature_service,
                )
                .await;

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

                self.unique_elections
                    .insert(proposal_id.clone(), unique_election_ids.len() as u64);
            } 
        }
        Ok(())
    }

    #[async_recursion]
    async fn process_vote(
        &mut self,
        vote: &Vote,
        timer: &mut Pin<&mut tokio::time::Sleep>,
    ) -> DagResult<()> {
        vote.verify(&self.committee).unwrap();
        let (tx_hash, election_id) = (vote.value.clone(), vote.election_id.clone());
        if !self.byzantine {
            match self.elections.get_mut(&vote.proposal_round) {
                Some(elections) => {
                    match elections.get_mut(&election_id) {
                        Some(election) => {
                            if !election.decided {
                                election.insert_vote(&vote);
                                if let Some(tally) = election.proposal_tallies.get(&vote.round) {
                                    if let Some(_tx_hash) = election.find_quorum_of_commits() {
                                        if let Some(len) =
                                            self.unique_elections.get(&vote.election_id)
                                        {
                                            info!("Committed {} -> {:?}", len, vote.election_id);

                                            self.round += 1;

                                            let deadline = Instant::now()
                                                + Duration::from_millis(self.max_header_delay);
                                            timer.as_mut().reset(deadline);

                                            election.decided = true;
                                        }
                                    }

                                    if let Some(tx_hash) = tally.find_quorum_of_votes() {
                                        if !election.voted_or_committed(&self.name, vote.round + 1)
                                        {
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
                                            let bytes = bincode::serialize(&PrimaryMessage::Vote(
                                                own_vote.clone(),
                                            ))
                                            .expect("Failed to serialize our own header");
                                            let _handlers = self
                                                .network
                                                .broadcast(
                                                    self.other_primaries.clone(),
                                                    Bytes::from(bytes),
                                                )
                                                .await;
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
                                        let bytes = bincode::serialize(&PrimaryMessage::Vote(
                                            own_vote.clone(),
                                        ))
                                        .expect("Failed to serialize our own header");
                                        let _handlers = self
                                            .network
                                            .broadcast(
                                                self.other_primaries.clone(),
                                                Bytes::from(bytes),
                                            )
                                            .await;
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
                                        let bytes = bincode::serialize(&PrimaryMessage::Vote(
                                            own_vote.clone(),
                                        ))
                                        .expect("Failed to serialize our own header");
                                        let _handlers = self
                                            .network
                                            .broadcast(
                                                self.other_primaries.clone(),
                                                Bytes::from(bytes),
                                            )
                                            .await;
                                    }
                                }
                            }
                        }
                        None => match self.pending_votes.get_mut(&vote.proposal_round) {
                            Some(btreeset) => {
                                btreeset.insert(vote.clone());
                            }
                            None => {
                                let mut btreeset = BTreeSet::new();
                                btreeset.insert(vote.clone());
                                self.pending_votes.insert(vote.proposal_round, btreeset);
                            }
                        },
                    }

                    let mut _header_decided = true;
                    if let Some(e) = self.proposals_per_round.get(&vote.proposal_round) {
                        for election_id in e {
                            match elections.get(&election_id) {
                                Some(election) => {
                                    if !election.decided {
                                        _header_decided = false;
                                        break;
                                    }
                                }
                                None => {
                                    _header_decided = false;
                                    break;
                                }
                            }
                        }
                    } else {
                        _header_decided = false;
                    }

                    if let Some(headers) = self.decided_headers.get(&vote.proposal_round) {
                        if !headers.len() >= QUORUM && vote.proposal_round == self.round {
                            self.round += 1;

                            let deadline =
                                Instant::now() + Duration::from_millis(self.max_header_delay);
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

            self.proposals
                .retain(|(_, election_id)| !decided.contains(&election_id));
            self.proposals
                .retain(|(_, election_id)| !active_elections.contains(&election_id));

            for i in 0..self.proposals.len() {
                if self.active_elections.contains(&self.proposals[i].1) {
                    self.proposals.remove(i);
                }
            }

            // Make a new proposal.
            let proposal = Proposal::new(
                self.round,
                self.name.clone(),
                self.proposals.drain(..).collect(), // only drain if committed
                &mut self.signature_service,
            )
            .await;

            self.own_proposals.push(self.round);

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
        loop {
            tokio::select! {
                Some((tx_hash, election_id)) = self.rx_workers.recv() => {
                    if !self.byzantine {
                        self.proposals.push((tx_hash, election_id));
                    }

                    if self.proposals.len() >= self.header_size && !self.own_proposals.contains(&self.round) {
                        self.make_proposal().await;
                    }
                },

                () = &mut timer => {
                    if self.proposals.len() > 0 && !self.own_proposals.contains(&self.round) {
                        self.make_proposal().await;
                    }

                    let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                    timer.as_mut().reset(deadline);
                },

                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    let _ = match message {
                        PrimaryMessage::Proposal(header) => self.process_proposal(&header).await,
                        PrimaryMessage::Vote(vote) => self.process_vote(&vote, &mut timer).await,
                    };
                },
            };
        }
    }
}
