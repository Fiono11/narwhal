use async_recursion::async_recursion;
use bytes::Bytes;
use std::collections::{BTreeSet, HashMap};
use std::pin::Pin;

use std::net::SocketAddr;

use crate::constants::{NUMBER_OF_NODES, QUORUM};
use crate::election::{Election, ElectionId, Timer};
use crate::error::DagResult;
use crate::messages::{Header, Vote};
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
    tx_core: Sender<Header>,

    /// The current round of the dag.
    round: Round,
    /// Holds the batches' digests waiting to be included in the next header.
    digests: Vec<(TxHash, ElectionId)>,
    /// Keeps track of the size (in bytes) of batches' digests that we received so far.
    payload_size: usize,
    elections: HashMap<Round, Election>,
    addresses: Vec<SocketAddr>,
    byzantine: bool,
    payloads: HashMap<Round, BTreeSet<Digest>>,
    proposals: Vec<(TxHash, ElectionId)>,
    votes: HashMap<Digest, BTreeSet<(TxHash, ElectionId)>>,
    network: SimpleSender,
    rx_primaries: Receiver<PrimaryMessage>,
    other_primaries: Vec<SocketAddr>,
    pending_votes: HashMap<Round, BTreeSet<Vote>>,
    committee: Committee,
    leader: PublicKey,
    decided: BTreeSet<ElectionId>,
    active_elections: BTreeSet<ElectionId>,
    decided_elections: HashMap<Digest, bool>,
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
        tx_core: Sender<Header>,
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
                other_primaries,
                pending_votes: HashMap::new(),
                committee,
                leader,
                decided: BTreeSet::new(),
                active_elections: BTreeSet::new(),
                decided_elections: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    #[async_recursion]
    async fn process_header(
        &mut self,
        header: &Header,
        timer: &mut Pin<&mut tokio::time::Sleep>,
    ) -> DagResult<()> {
        header.verify(&self.committee).unwrap();

        self.decided_elections.insert(header.id.clone(), false);

        if !self.byzantine {
            //info!(
                //"Received header {} from {} in round {}",
                //header.id, header.author, self.round
            //);

            self.votes.insert(header.id.clone(), header.votes.clone());
            let vote = Vote::new(
                0,
                header.id.clone(),
                header.round,
                false,
                header.author,
                &mut self.signature_service,
            )
            .await;

            //for (_, election_id) in &header.votes {
                //self.proposals
                    //.retain(|&(_, ref p_election_id)| p_election_id != election_id);
            //}

            match self.elections.get_mut(&header.round) {
                Some(election) => {
                    election.insert_vote(&vote);
                }
                None => {
                    // create election
                    let election = Election::new();
                    self.elections.insert(header.round, election);

                    //info!("Created {} -> {:?} in round {}", header.votes.len(), header.id, header.round);

                    //let mut elections_ids = BTreeSet::new();

                    //#[cfg(feature = "benchmark")]
                    for (_tx_hash, election_id) in &header.votes {
                        //info!("Created1 {} -> {:?}", tx_hash, election_id);
                        //elections_ids.insert(election_id.clone());
                        //if !self.active_elections.contains(&election_id)
                            //&& !self.decided.contains(&election_id)
                        //{
                            // NOTE: This log entry is used to compute performance.
                            self.active_elections.insert(election_id.clone());
                            info!("Added {} to active elections2", election_id.clone());
                        //}
                    }
                }
            }

            let election = self.elections.get_mut(&header.round).unwrap();
            // insert vote
            election.insert_vote(&vote);

            if vote.author != self.name {
                // broadcast vote
                let mut own_vote = vote.clone();
                own_vote.author = self.name;
                //info!("Sending vote1: {:?}", &own_vote);
                election.insert_vote(&own_vote.clone());
                let bytes = bincode::serialize(&PrimaryMessage::Vote(own_vote.clone()))
                    .expect("Failed to serialize our own header");
                let _handlers = self
                    .network
                    .broadcast(self.addresses.clone(), Bytes::from(bytes))
                    .await;
            }

            if self.pending_votes.contains_key(&header.round) {
                if let Some(votes) = self.pending_votes.remove(&header.round) {
                    for vote in votes {
                        //info!("Inserting pending vote {}", &vote);
                        self.process_vote(&vote, timer).await;
                    }
                }
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
        /*if !vote.commit {
            info!(
                "Received a vote from {} for header {} in round {} of election {}",
                vote.author, vote.header_id, vote.round, vote.election_id
            );
        } else {
            info!(
                "Received a commit from {} for header {} in round {} of election {}",
                vote.author, vote.header_id, vote.round, vote.election_id
            );
        }*/
        let (tx_hash, election_id) = (vote.header_id.clone(), vote.election_id);
        if !self.byzantine {
            match self.elections.get_mut(&election_id) {
                Some(election) => {
                    if !election.decided {
                        election.insert_vote(&vote);
                        if let Some(tally) = election.tallies.get(&vote.round) {
                            if let Some(header_id) = election.find_quorum_of_commits() {
                                for (tx_hash, election_id) in self.votes.get(&header_id).unwrap().iter() {
                                    //if let Some(pos) = self.proposals.iter().position(|x| *x == (tx_hash.clone(), election_id.clone())) {
                                        //self.proposals.remove(pos);
                                    //}
                                    info!("Added {} to decided", election_id.clone());
                                    self.decided.insert(election_id.clone());
                                }
                                //self.proposals.retain(|(_, id)| id != election_id);

                                //self.decided.insert(election_id.clone());

                                //#[cfg(not(feature = "benchmark"))]
                                //info!("Committed {}", tx_hash);
                                //election.decided = true;
                                //info!("Committed1 {} -> {:?}", tx_hash, election_id);
                                //}

                                if self.decided_elections.get(&header_id).unwrap() == &false {
                                    #[cfg(feature = "benchmark")]
                                    // NOTE: This log entry is used to compute performance.
                                    info!(
                                        "Committed {} -> {:?}",
                                        self.votes.get(&header_id).unwrap().len(),
                                        header_id
                                    );
                                    self.decided_elections.insert(header_id.clone(), true);

                            
                                    //info!("Round {} is decided with {}!", election_id, header_id.clone());

                                    self.round += 1;
                                    self.leader = self.committee.leader(self.round as usize);

                                    //info!("LEADER1 of round {} is {}", self.round, self.leader);


                                    let deadline = Instant::now()
                                        + Duration::from_millis(self.max_header_delay);
                                    timer.as_mut().reset(deadline);

                                    election.decided = true;
                                }

                                return Ok(());
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
                                        true,
                                        self.name,
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
                                    committed,
                                    self.name,
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
                                    vote.commit,
                                    self.name,
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
                    /*info!(
                        "Election of {:?}: {:?}",
                        &election_id,
                        self.elections.get(&election_id).unwrap()
                    );*/
                }
                None => match self.pending_votes.get_mut(&election_id) {
                    Some(btreeset) => {
                        //info!("Inserted vote {} into pending votes", &vote);
                        btreeset.insert(vote.clone());
                    }
                    None => {
                        //info!("Inserted vote {} into pending votes", &vote);
                        let mut btreeset = BTreeSet::new();
                        btreeset.insert(vote.clone());
                        self.pending_votes.insert(election_id, btreeset);
                    }
                },
            }
        }
        Ok(())
    }

    async fn make_header(&mut self) {
        if !self.byzantine {
            let decided = &self.decided;
            let active_elections = &self.active_elections;

            //info!("PROPOSALS2: {}", self.proposals.len());

            //info!("DECIDED: {:?}", decided.len());

            self.proposals
                .retain(|(_, election_id)| !decided.contains(&election_id));
            self.proposals
                .retain(|(_, election_id)| !active_elections.contains(&election_id));

            //info!("PROPOSALS3: {}", self.proposals.len());

            //let mut proposals = self.proposals.clone();

            //proposals
                //.retain(|(_, election_id)| !active_elections.contains(&election_id));

            if self.proposals.len() > 0 {

                self.elections.insert(self.round, Election::new());

            // Make a new header.
            let header = Header::new(
                self.round,
                self.name.clone(),
                self.proposals.drain(..).collect(), 
                &mut self.signature_service,
            )
            .await;

            for (_tx_hash, election_id) in &header.votes {
                self.active_elections.insert(election_id.clone());
                info!("Added {} to active elections", election_id.clone());
            }

            //info!(
                //"Making a new header {} from {} in round {} with {} proposals",
                //header.id, self.name, self.round, proposals.len()
            //);

            //info!("PROPOSALS4: {}", self.proposals.len());

            let bytes = bincode::serialize(&PrimaryMessage::Header(header.clone()))
                .expect("Failed to serialize our own header");
            let _handlers = self
                .network
                .broadcast(self.addresses.clone(), Bytes::from(bytes))
                .await;
        }
        }
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        let timer: tokio::time::Sleep = sleep(Duration::from_millis(self.max_header_delay));
        tokio::pin!(timer);
        let mut counter = 0;
        let mut counter2 = 0;

        loop {
            tokio::select! {
                Some((tx_hash, election_id)) = self.rx_workers.recv() => {
                    //info!("{}", counter2);
                    counter2 += 1;
                    if !self.byzantine {
                        //info!("Received tx hash {} and election id {}", tx_hash, election_id);
                        self.proposals.push((tx_hash, election_id));
                    }

                    //info!("PROPOSALS1: {}", self.proposals.len());

                    if self.committee.is_byzantine(&self.leader) {
                        let mut next_round = self.round + 1;
                        let mut next_leader = self.committee.leader(next_round as usize);

                        while self.committee.is_byzantine(&next_leader) {
                            //sleep(Duration::from_millis(self.max_header_delay)).await;
                            next_round += 1;
                            next_leader = self.committee.leader(next_round as usize);
                        }

                        self.leader = next_leader;

                        //info!("LEADER2 of round {} is {}", self.round, self.leader);
                    }

                    if self.proposals.len() >= self.header_size && self.leader == self.name && self.elections.get(&self.round).is_none() {
                
                        self.make_header().await;
                    }

                },

                () = &mut timer => {

                    let mut next_round = self.round + 1;

                    if self.committee.is_byzantine(&self.leader) {
                        let mut next_leader = self.committee.leader(next_round as usize);

                        while self.committee.is_byzantine(&next_leader) {
                            //sleep(Duration::from_millis(self.max_header_delay)).await;
                            next_round += 1;
                            next_leader = self.committee.leader(next_round as usize);
                        }

                        self.leader = next_leader;

                        //info!("LEADER3 of round {} is {}", self.round, self.leader);

                    }

                    self.leader = self.committee.leader(next_round as usize + counter);


                    if self.proposals.len() > 0 && self.leader == self.name && self.elections.get(&self.round).is_none() {
                        //self.elections.insert(self.round, Election::new());
                        self.make_header().await;
                    }

                    counter += 1;

                    //info!("LEADER in round {}: {}", self.round, self.leader);
                    //info!("PROPOSALS: {}", self.proposals.len());

                    let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                    timer.as_mut().reset(deadline);
                },

                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    let _ = match message {
                        PrimaryMessage::Header(header) => self.process_header(&header, &mut timer).await,
                        PrimaryMessage::Vote(vote) => self.process_vote(&vote, &mut timer).await,
                        _ => Ok(())
                    };
                },
            };
        }
    }
}
