// Copyright(C) Facebook, Inc. and its affiliates.
use crate::constants::QUORUM;
use crate::error::{DagError, DagResult};
use crate::messages::{Certificate, Header, Vote, Hash};
use crate::primary::{PrimaryMessage, Round};
use async_recursion::async_recursion;
use bytes::Bytes;
use config::{Committee, PK};
use log::{debug, error, warn};
use mc_account_keys::PublicAddress;
use mc_crypto_keys::SignatureService;
use mc_crypto_keys::tx_hash::TxHash;
use network::{CancelHandler, ReliableSender, SimpleSender};
use std::collections::{HashMap, HashSet, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use log::info;

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub struct Core {
    /// The public key of this primary.
    name: PublicAddress,
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Service to sign headers.
    signature_service: SignatureService,
    /// The current consensus round (used for cleanup).
    consensus_round: Arc<AtomicU64>,
    /// The depth of the garbage collector.
    gc_depth: Round,

    /// Receiver for dag messages (headers, votes, certificates).
    rx_primaries: Receiver<PrimaryMessage>,
    /// Receives our newly created headers from the `Proposer`.
    rx_proposer: Receiver<Header>,
    /// Send valid a quorum of certificates' ids to the `Proposer` (along with their round).
    tx_proposer: Sender<(Vec<TxHash>, Round)>,

    /// The last garbage collected round.
    gc_round: Round,
    /// The authors of the last voted headers.
    last_voted: HashMap<Round, HashSet<PublicAddress>>,
    /// The set of headers we are currently processing.
    processing: HashMap<Round, HashSet<TxHash>>,
    /// The last header we proposed (for which we are waiting votes).
    current_header: Header,
    /// A network sender to send the batches to the other workers.
    network: SimpleSender,
    /// Keeps the cancel handlers of the messages we sent.
    cancel_handlers: HashMap<Round, Vec<CancelHandler>>,
    elections: HashMap<TxHash, (BTreeSet<PublicAddress>, bool)>,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicAddress,
        committee: Committee,
        store: Store,
        signature_service: SignatureService,
        consensus_round: Arc<AtomicU64>,
        gc_depth: Round,
        rx_primaries: Receiver<PrimaryMessage>,
        rx_proposer: Receiver<Header>,
        tx_proposer: Sender<(Vec<TxHash>, Round)>,
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                store,
                signature_service,
                consensus_round,
                gc_depth,
                rx_primaries,
                rx_proposer,
                tx_proposer,
                gc_round: 0,
                last_voted: HashMap::with_capacity(2 * gc_depth as usize),
                processing: HashMap::with_capacity(2 * gc_depth as usize),
                current_header: Header::default(),
                network: SimpleSender::new(),
                cancel_handlers: HashMap::with_capacity(2 * gc_depth as usize),
                elections: HashMap::new(),
            }
            .run()
            .await;
        });
    }

    #[async_recursion]
    async fn process_header(&mut self, header: &Header) -> DagResult<()> {
        //info!("name: {:?}", self.name);
        //info!("Received {:?} from {:?}", header, header.author);
            match self.elections.get_mut(&header.id) {
                Some((votes, committed)) => {
                    if !votes.contains(&self.name) {
                        let mut own_header = header.clone();
                        own_header.author = self.name.clone();
                        // Broadcast the new header in a reliable manner.
                        let addresses = self
                            .committee
                            .others_primaries(&PK(self.name.to_bytes()))
                            .iter()
                            .map(|(_, x)| x.primary_to_primary)
                            .collect();
                        let bytes = bincode::serialize(&PrimaryMessage::Header(own_header))
                            .expect("Failed to serialize our own header");
                        self.network.broadcast(addresses, Bytes::from(bytes)).await;
                    }
                    //info!("1");
                    votes.insert(header.author.clone());

                    //info!("votes: {:?}", votes);

                    if votes.len() >= QUORUM && !*committed {
                        #[cfg(not(feature = "benchmark"))]
                        info!("Committed {}", header);

                        for tx in &header.payload {
                            #[cfg(feature = "benchmark")]
                            // NOTE: This log entry is used to compute performance.
                            info!("Committed {} -> {:?}", header, header.id);
                        }
                        *committed = true;
                    }
                },
                None => {
                    if header.author != self.name {
                        #[cfg(feature = "benchmark")]
                        for digest in &header.payload {
                            // NOTE: This log entry is used to compute performance.
                            info!("Created {} -> {:?}", header, header.id);
                        }
                    }
                    //info!("3");
                    let mut votes = BTreeSet::new();
                    votes.insert(header.author.clone());
                    self.elections.insert(header.id.clone(), (votes, false));

                    let mut own_header = header.clone();
                    own_header.author = self.name.clone();
                    // Broadcast the new header in a reliable manner.
                    let addresses = self
                        .committee
                        .others_primaries(&PK(self.name.to_bytes()))
                        .iter()
                        .map(|(_, x)| x.primary_to_primary)
                        .collect();
                    let bytes = bincode::serialize(&PrimaryMessage::Header(own_header))
                        .expect("Failed to serialize our own header");
                    self.network.broadcast(addresses, Bytes::from(bytes)).await;
                }
            }
            //info!("Election of {:?}: {:?}", &header, self.elections.get(&header.id).unwrap());
        Ok(())
    }

    // Main loop listening to incoming messages.
    pub async fn run(&mut self) {
        loop {
            let result = tokio::select! {
                // We receive here messages from other primaries.
                Some(message) = self.rx_primaries.recv() => {
                    match message {
                        PrimaryMessage::Header(header) => self.process_header(&header).await,
                        _ => panic!("Unexpected core message")
                    }
                },

                // We also receive here our new headers created by the `Proposer`.
                Some(header) = self.rx_proposer.recv() => self.process_header(&header).await,
            };
            match result {
                Ok(()) => (),
                Err(DagError::StoreError(e)) => {
                    error!("{}", e);
                    panic!("Storage failure: killing node.");
                }
                Err(e @ DagError::TooOld(..)) => debug!("{}", e),
                Err(e) => warn!("{}", e),
            }

            // Cleanup internal state.
            let round = self.consensus_round.load(Ordering::Relaxed);
            if round > self.gc_depth {
                let gc_round = round - self.gc_depth;
                self.last_voted.retain(|k, _| k >= &gc_round);
                self.processing.retain(|k, _| k >= &gc_round);
                self.cancel_handlers.retain(|k, _| k >= &gc_round);
                self.gc_round = gc_round;
            }
        }
    }
}
