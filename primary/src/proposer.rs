use std::collections::{BTreeSet, HashMap};
use std::pin::Pin;
use async_recursion::async_recursion;
use bytes::Bytes;
use rand::seq::IteratorRandom;
use std::net::SocketAddr;
use std::thread;

use crate::constants::{QUORUM, NUMBER_OF_NODES};
use crate::election::{ElectionId, Timer, Election};
use crate::error::{DagError, DagResult};
use crate::messages::{Header, Hash, Vote};
use crate::primary::{Round, PrimaryMessage};
use config::{Committee, WorkerId};
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, info, error, warn};
use network::SimpleSender;
use rand::Rng;
use rand::rngs::OsRng;
//#[cfg(feature = "benchmark")]
//use log::info;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

pub type TxHash = Digest;

#[cfg(test)]
#[path = "tests/proposer_tests.rs"]
pub mod proposer_tests;

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
    votes: HashMap<Digest, Vec<(TxHash, ElectionId)>>,
    network: SimpleSender,
    rx_primaries: Receiver<PrimaryMessage>,
    other_primaries: Vec<SocketAddr>,
    pending_votes: HashMap<Round, BTreeSet<Vote>>,
}

impl Proposer {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: &Committee,
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
                proposals: Vec::with_capacity(header_size),
                elections: HashMap::new(),
                addresses,
                byzantine,
                payloads: HashMap::new(),
                network: SimpleSender::new(),
                rx_primaries,
                votes: HashMap::new(),
                other_primaries,
                pending_votes: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    #[async_recursion]
    async fn process_header(&mut self, header: &Header, timer: &mut Pin<&mut tokio::time::Sleep>) -> DagResult<()> {
        info!("Received header {} from {} in round {}", header.id, header.author, self.round);

        let mut rng = OsRng;

        let duration_ms = rng.gen_range(0..=1000);

        info!("timer set to {:?} ms", duration_ms);
        
        let deadline = Instant::now() + Duration::from_millis(duration_ms);
        timer.as_mut().reset(deadline);
        
        self.round += 1;

        self.votes.insert(header.id.clone(), header.votes.clone());
        let vote = Vote::new(0, header.id.clone(), header.round, false, header.author, &mut self.signature_service).await;

        for (_, election_id) in &header.votes {
            self.proposals.retain(|&(_, ref p_election_id)| p_election_id != election_id);
        }
        
        match self.elections.get_mut(&header.round) {
            Some(election) => {
                election.insert_vote(&vote, vote.author);
            }
            None => {
                // create election
                let election = Election::new();
                self.elections.insert(header.round, election);

                #[cfg(feature = "benchmark")]
                for (tx_hash, election_id) in &header.votes {
                    // NOTE: This log entry is used to compute performance.
                    info!("Created {} -> {:?}", tx_hash, election_id);
                }
                    
                let election = self.elections.get_mut(&header.round).unwrap();
                // insert vote
                election.insert_vote(&vote, vote.author);

                if vote.author != self.name {
                    // broadcast vote
                    let bytes = bincode::serialize(&PrimaryMessage::Vote(vote.clone()))
                        .expect("Failed to serialize our own header");
                    let handlers = self.network.broadcast(self.other_primaries.clone(), Bytes::from(bytes)).await;
                }
            }
        }

        let election = self.elections.get_mut(&header.round).unwrap();
        if self.pending_votes.contains_key(&header.round) {
            if let Some(votes) = self.pending_votes.remove(&header.round) {
                for vote in votes {
                    election.insert_vote(&vote, vote.author);
                }
            }
        }

        Ok(())
    }

    #[async_recursion]
    async fn process_vote(&mut self, vote: &Vote) -> DagResult<()> {
        info!("Received a vote from {} for header {} in election {}", vote.author, vote.header_id, vote.election_id);

        //for vote in &header.votes {
            if !vote.commit {
                //info!("Received vote {:?} from {}", vote, header.author);
            }
            else {
                //info!("Received commit {:?} from {}", vote, header.author);
            }
            let (tx_hash, election_id) = (vote.header_id.clone(), vote.election_id); 
            if !self.byzantine {
            //for (tx_hash, election_id) in &header.payload {
                
                //let mut own_header = Header::default();
                // decide vote
                match self.elections.get_mut(&election_id) {
                    Some(election) => {
                    if let Some(tally) = election.tallies.get(&vote.round) {
                        if let Some(header_id) = tally.find_quorum_of_commits() {
                            if !election.decided {
                                for (tx_hash, election_id) in self.votes.get(&header_id).unwrap().iter() {
                                    #[cfg(not(feature = "benchmark"))]
                                    info!("Committed {}", tx_hash);
                                                        
                                    #[cfg(feature = "benchmark")]
                                    // NOTE: This log entry is used to compute performance.
                                    info!("Committed {} -> {:?}", tx_hash, election_id);
                                    election.decided = true;
                                }
                            }
                            return Ok(());
                        }
                        //if !election.committed {
                            //own_header = header.clone();
                            if let Some(tx_hash) = tally.find_quorum_of_votes() {
                                if !election.voted_or_committed(&self.name, vote.round+1) {
                                    election.commit = Some(tx_hash.clone());
                                    election.proof_round = Some(vote.round);
                                    let vote = Vote::new(vote.round + 1, tx_hash.clone(), election_id, true, self.name, &mut self.signature_service).await;
                                    election.insert_vote(&vote, self.name);

                                    //self.proposals.push(vote.clone());
                                    //own_header.payload = (tx_hash.clone(), election_id.clone());
                                    //own_header.round = header.round + 1;
                                    //own_header.author = self.name;
                                    //own_header.commit = true;
                                    //election.committed = true;


                                    // broadcast vote
                                    let bytes = bincode::serialize(&PrimaryMessage::Vote(vote.clone()))
                                        .expect("Failed to serialize our own header");
                                    let handlers = self.network.broadcast(self.other_primaries.clone(), Bytes::from(bytes)).await;
                                    /*self.cancel_handlers
                                        .entry(own_header.round)
                                        .or_insert_with(Vec::new)
                                        .extend(handlers);*/
                                    //info!("Sending commit: {:?}", own_header);
                                }
                            }
                            else if election.voted_or_committed(&self.name, vote.round) && ((tally.total_votes() >= QUORUM && *tally.timer.0.lock().unwrap() == Timer::Expired) || tally.total_votes() == NUMBER_OF_NODES)
                            && !election.voted_or_committed(&self.name, vote.round + 1) {
                                let highest = election.highest.clone().unwrap();
                                //own_header.payload = (highest.clone(), election_id.clone());
                                //own_header.round = header.round + 1;
                                //own_header.author = self.name;
                                let vote = Vote::new(vote.round+1, highest, election_id, false,  self.name, &mut self.signature_service).await;
                                //self.proposals.push(vote.clone());
                                //election.round = header.round + 1;
                                election.insert_vote(&vote, self.name);

                                // broadcast vote
                                let bytes = bincode::serialize(&PrimaryMessage::Vote(vote.clone()))
                                    .expect("Failed to serialize our own header");
                                let handlers = self.network.broadcast(self.other_primaries.clone(), Bytes::from(bytes)).await;
                                /*self.cancel_handlers
                                    .entry(own_header.round)
                                    .or_insert_with(Vec::new)
                                    .extend(handlers);*/
                                info!("Changing vote: {:?}", vote);
                            }
                            else if !election.voted_or_committed(&self.name, vote.round) {
                                    let mut tx_hash = tx_hash;
                                    if let Some(highest) = &election.highest {
                                        tx_hash = highest.clone();
                                    }
                                    //election.voted = true;
                                    //election.round = header.round + 1;
                                    //own_header.author = self.name;
                                    let vote = Vote::new(vote.round, tx_hash, election_id, vote.commit, self.name, &mut self.signature_service).await;
                                    election.insert_vote(&vote, self.name);
                                    //self.proposals.push(vote.clone());

                                    // broadcast vote
                                    let bytes = bincode::serialize(&PrimaryMessage::Vote(vote.clone()))
                                        .expect("Failed to serialize our own header");
                                    let handlers = self.network.broadcast(self.other_primaries.clone(), Bytes::from(bytes)).await;
                                    /*self.cancel_handlers
                                        .entry(own_header.round)
                                        .or_insert_with(Vec::new)
                                        .extend(handlers);*/
                                    info!("Sending vote: {:?}", vote);                            
                            }
                        }               
                    }
                    None => {
                        match self.pending_votes.get_mut(&election_id) {
                            Some(btreeset) => {
                                btreeset.insert(vote.clone());
                            }
                            None => {
                                let mut btreeset = BTreeSet::new();
                                btreeset.insert(vote.clone());
                                self.pending_votes.insert(election_id, btreeset);
                            }
                        }
                    }
                }
                //info!("Election of {:?}: {:?}", &election_id, self.elections.get(&election_id).unwrap());
            }
            else {
                match self.payloads.get_mut(&election_id) {
                    Some(txs) => {
                        txs.insert(tx_hash.clone());
                    }
                    None => {
                        let mut txs = BTreeSet::new();
                        txs.insert(tx_hash.clone());
                        self.payloads.insert(election_id.clone(), txs);
                    }
                }
                let mut rng = OsRng;
                let digest = self.payloads.get(&election_id).unwrap().iter().choose(&mut rng).unwrap().clone();
                //let digest = Digest::random();
                let vote = Vote::new(vote.round, digest, election_id, rand::random(), self.name, &mut self.signature_service).await;
                //self.proposals.push(vote.clone());
                //let own_header = Header::new(self.name, header.round, payload, &mut self.signature_service, rand::random()).await;
                // broadcast vote
                let bytes = bincode::serialize(&PrimaryMessage::Vote(vote.clone()))
                    .expect("Failed to serialize our own header");
                let handlers = self.network.broadcast(self.other_primaries.clone(), Bytes::from(bytes)).await;
                /*self.cancel_handlers
                    .entry(own_header.round)
                    .or_insert_with(Vec::new)
                    .extend(handlers);*/
                //info!("Sending vote: {:?}", own_header);
            }

            //if self.votes.len() >= self.header_size {
                // broadcast votes
                //let own_header = Header::new(self.round, self.name, self.votes.drain(..).collect(), &mut self.signature_service).await;
                //let bytes = bincode::serialize(&PrimaryMessage::Header(own_header.clone()))
                    //.expect("Failed to serialize our own header");
                //let handlers = self.network.broadcast(self.addresses.clone(), Bytes::from(bytes)).await;
            //}
        //}
        Ok(())
    }

    async fn make_header(&mut self) {
        info!("Making a new header in round {}", self.round);
        // Make a new header.
        let header = Header::new(
            self.round,
            self.name.clone(),
            self.proposals.drain(..).collect(), // only drain if committed
            &mut self.signature_service,
        )
        .await;
        //debug!("Created {:?}", header);

        let bytes = bincode::serialize(&PrimaryMessage::Header(header.clone()))
            .expect("Failed to serialize our own header");
        let handlers = self.network.broadcast(self.addresses.clone(), Bytes::from(bytes)).await;

        //#[cfg(feature = "benchmark")]
        //for vote in &header.votes {
            // NOTE: This log entry is used to compute performance.
            //info!("Created {} -> {:?}", &vote, vote.election_id);
        //}

        // Send the new header to the `Core` that will broadcast and process it.
        /*self.tx_core
            .send(header)
            .await
            .expect("Failed to send header");*/
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        //debug!("Dag starting at round {}", self.round);

        let mut rng = OsRng;

        let duration_ms = rng.gen_range(0..=1000);

        info!("timer set to {:?} ms", duration_ms);

        let timer: tokio::time::Sleep = sleep(Duration::from_millis(duration_ms));
        tokio::pin!(timer);

        loop {
            // Check if we can propose a new header. We propose a new header when one of the following
            // conditions is met:
            // 1. We have a quorum of certificates from the previous round and enough batches' digests;
            // 2. We have a quorum of certificates from the previous round and the specified maximum
            // inter-header delay has passed.
            //let enough_parents = !self.last_parents.is_empty();
            //let enough_digests = self.payload_size >= self.header_size;
            //let enough_digests = self.digests.len() == 1;
            let timer_expired = timer.is_elapsed();
            let enough_proposals = self.proposals.len() >= self.header_size;
            //info!("Digests: {:?}", self.digests);

            /*if enough_votes {
                let mut rng = OsRng;

                // Generate a random duration between 0 and 1000 milliseconds
                let duration_ms = rng.gen_range(0..=1000);

                // Convert the duration to the appropriate type
                let duration = Duration::from_millis(duration_ms);

                //info!("Sleeping during {} ms", duration_ms);

                //info!("timer: {:?}", timer);

                // Sleep for the random duration
                //tokio::time::sleep(duration).await;

                //info!("timer: {:?}", timer);

                //if !timer_expired {
                    //break;
                //}
            
                // Make a new header.
                //self.make_header().await;
                //self.payload_size = 0;

                // Reschedule the timer.
                //let deadline = Instant::now() + Duration::from_millis(self.max_header_delay);
                //timer.as_mut().reset(deadline);

                //self.round += 1;
            }*/

            tokio::select! {
                Some((tx_hash, election_id)) = self.rx_workers.recv() => {
                    info!("received tx {} of election {}", tx_hash, election_id);
                    //if let None = self.elections.get(&election_id) {
                        //let vote = Vote::new(0, tx_hash, election_id, false, self.name, &mut self.signature_service).await;
                        //info!("inserted vote {}", &vote);
                        self.proposals.push((tx_hash, election_id));
                    //}
                    //self.make_header(tx_hash, election_id).await;
                    //info!("Received digest {:?}", digest);
                    //self.payload_size += tx_hash.size();
                    //self.digests.push((tx_hash, election_id));
                    //self.make_header().await;
                    //info!("Size: {:?}", self.payload_size);
                    //info!("Digests: {:?}", self.digests);
                },

                () = &mut timer => {
                    // Nothing to do.
                    if enough_proposals {
                        self.make_header().await;
                    }
                },

                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    let _ = match message {
                        PrimaryMessage::Header(header) => self.process_header(&header, &mut timer).await,
                        PrimaryMessage::Vote(vote) => self.process_vote(&vote).await,
                        _ => Ok(())
                    };
                },

                // We also receive here our new headers created by the `Proposer`.
                //Some(header) = self.rx_proposer.recv() => self.process_header(&header).await,
            };
        }
    }
}