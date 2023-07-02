// Copyright(C) Facebook, Inc. and its affiliates.
use crate::processor::SerializedBatchMessage;
use crate::Block;
use crate::worker::WorkerMessage;
use bytes::Bytes;
use crypto::{Digest, PublicKey};
#[cfg(feature = "benchmark")]
use ed25519_dalek::{Digest as _, Sha512};
use network::SimpleSender;
use primary::Transaction;
#[cfg(feature = "benchmark")]
use std::convert::TryInto as _;
use std::net::SocketAddr;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

//pub type Transaction = Vec<u8>;
pub type Batch = Vec<Transaction>;

/// Assemble clients transactions into batches.
pub struct BatchMaker {
    /// The preferred batch size (in bytes).
    batch_size: usize,
    /// The maximum delay after which to seal the batch (in ms).
    max_batch_delay: u64,
    /// Channel to receive transactions from the network.
    rx_transaction: Receiver<Transaction>,
    /// The network addresses of the other workers that share our worker id.
    workers_addresses: Vec<(PublicKey, SocketAddr)>,
    /// Holds the current batch.
    current_batch: Batch,
    /// Holds the size of the current batch (in bytes).
    current_batch_size: usize,
    /// A network sender to broadcast the batches to the other workers.
    network: SimpleSender,
    /// Channel to deliver batches for which we have enough acknowledgements.
    tx_batch: Sender<(SerializedBatchMessage, Digest)>,
}

impl BatchMaker {
    pub fn spawn(
        batch_size: usize,
        max_batch_delay: u64,
        rx_transaction: Receiver<Transaction>,
        workers_addresses: Vec<(PublicKey, SocketAddr)>,
        tx_batch: Sender<(SerializedBatchMessage, Digest)>,
    ) {
        tokio::spawn(async move {
            Self {
                batch_size,
                max_batch_delay,
                rx_transaction,
                workers_addresses,
                current_batch: Batch::with_capacity(batch_size * 2),
                current_batch_size: 0,
                network: SimpleSender::new(),
                tx_batch,
            }
            .run()
            .await;
        });
    }

    /// Main loop receiving incoming transactions and creating batches.
    async fn run(&mut self) {
        let timer = sleep(Duration::from_millis(self.max_batch_delay));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                // Assemble client transactions into batches of preset size.
                Some(transaction) = self.rx_transaction.recv() => {
                    self.current_batch_size += transaction.data.len() + 32;
                    self.current_batch.push(transaction);
                    if self.current_batch_size >= self.batch_size {
                        self.seal().await;
                        timer.as_mut().reset(Instant::now() + Duration::from_millis(self.max_batch_delay));
                    }
                },

                // If the timer triggers, seal the batch even if it contains few transactions.
                () = &mut timer => {
                    if !self.current_batch.is_empty() {
                        self.seal().await;
                    }
                    timer.as_mut().reset(Instant::now() + Duration::from_millis(self.max_batch_delay));
                }
            }

            // Give the change to schedule other tasks.
            tokio::task::yield_now().await;
        }
    }

    /// Seal and broadcast the current batch.
    async fn seal(&mut self) {
        // Serialize the batch.
        self.current_batch_size = 0;
        let batch: Vec<Transaction> = self.current_batch.drain(..).collect();

        let block = Block {
            txs: batch.clone(),
        };
        let message = WorkerMessage::Batch(block);
        let serialized = bincode::serialize(&message).expect("Failed to serialize our own batch");

        let mut array: [u8; 32] = [0; 32];

        let vec = batch[0].id.clone();

        let vec_len = vec.len();

        if vec_len < 32 {
            array[..vec_len].clone_from_slice(&vec[..vec_len]);
        } else {
            array.clone_from_slice(&vec[..32]);
        }

        // Broadcast the batch through the network.
        let (_names, addresses): (Vec<_>, _) = self.workers_addresses.iter().cloned().unzip();
        let bytes = Bytes::from(serialized.clone());
        self.network.broadcast(addresses, bytes).await;

        self.tx_batch
            .send((serialized, Digest(array)))
            .await
            .expect("Failed to deliver batch");
    }
}
