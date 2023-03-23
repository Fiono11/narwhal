// Copyright(C) Facebook, Inc. and its affiliates.
use anyhow::{Context, Result};
use bulletproofs::PedersenGens;
use bulletproofs::RangeProof;
use bytes::BufMut as _;
use bytes::BytesMut;
use clap::{crate_name, crate_version, App, AppSettings};
use crypto::Digest;
use crypto::Hash;
use crypto::PublicKey;
use crypto::Signature;
use crypto::Transaction;
use crypto::TwistedElGamal;
use crypto::check_range_proofs;
use crypto::generate_keypair;
use crypto::generate_range_proofs;
use crypto::triptych::KeyGen;
use crypto::triptych::Sign;
use crypto::triptych::TriptychSignature;
use crypto::triptych::Verify;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::traits::Identity;
use ed25519_dalek::{Sha512, Digest as _};
use env_logger::Env;
use futures::future::join_all;
use futures::sink::SinkExt as _;
use log::debug;
use log::{info, warn};
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use worker::Block;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::time::{interval, sleep, Duration, Instant};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use bytes::Bytes;
use rand::thread_rng;
use std::convert::TryInto;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .about("Benchmark client for Narwhal and Tusk.")
        .args_from_usage("<ADDR> 'The network address of the node where to send txs'")
        .args_from_usage("--size=<INT> 'The size of each transaction in bytes'")
        .args_from_usage("--rate=<INT> 'The rate (txs/s) at which to send the transactions'")
        .args_from_usage("--nodes=[ADDR]... 'Network addresses that must be reachable before starting the benchmark.'")
        .setting(AppSettings::ArgRequiredElseHelp)
        .get_matches();

    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let target = matches
        .value_of("ADDR")
        .unwrap()
        .parse::<SocketAddr>()
        .context("Invalid socket address format")?;
    let size = matches
        .value_of("size")
        .unwrap()
        .parse::<usize>()
        .context("The size of transactions must be a non-negative integer")?;
    let rate = matches
        .value_of("rate")
        .unwrap()
        .parse::<u64>()
        .context("The rate of transactions must be a non-negative integer")?;
    let nodes = matches
        .values_of("nodes")
        .unwrap_or_default()
        .into_iter()
        .map(|x| x.parse::<SocketAddr>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid socket address format")?;

    info!("Node address: {}", target);

    // NOTE: This log entry is used to compute performance.
    info!("Transactions size: {} B", size);

    // NOTE: This log entry is used to compute performance.
    info!("Transactions rate: {} tx/s", rate);

    let client = Client {
        target,
        size,
        rate,
        nodes,
    };

    // Wait for all nodes to be online and synchronized.
    client.wait().await;

    // Start the benchmark.
    client.send().await.context("Failed to submit transactions")
}

struct Client {
    target: SocketAddr,
    size: usize,
    rate: u64,
    nodes: Vec<SocketAddr>,
}

impl Client {
    pub async fn send(&self) -> Result<()> {
        const PRECISION: u64 = 1; // Sample precision.
        const BURST_DURATION: u64 = 2000 / PRECISION;

        // The transaction size must be at least 16 bytes to ensure all txs are different.
        if self.size < 9 {
            return Err(anyhow::Error::msg(
                "Transaction size must be at least 9 bytes",
            ));
        }

        // Connect to the mempool.
        let stream = TcpStream::connect(self.target)
            .await
            .context(format!("failed to connect to {}", self.target))?;

        // Submit all transactions.
        //let burst = self.rate / PRECISION;
        let burst = 512;
        info!("BURST: {}", self.rate / PRECISION);
        //let mut tx = BytesMut::with_capacity(self.size);
        let mut counter = 0;
        //let mut r = rand::thread_rng().gen();
        let mut transport = Framed::new(stream, LengthDelimitedCodec::new());
        let interval = interval(Duration::from_millis(BURST_DURATION));
        tokio::pin!(interval);

        // NOTE: This log entry is used to compute performance.
        info!("Start sending transactions");

        /*for i in 0..500 {
            let mut tx = Transaction::random();
            txs.push(tx.clone());
        }*/

        let mut rng = rand::rngs::OsRng;
        let representative = RistrettoPoint::random(&mut rng);
        let balance = rand::thread_rng().gen_range(0, u64::MAX);
        let random = Scalar::random(&mut rng);
        let generators = PedersenGens::default();
        
        let (range_proof, _commitment) = generate_range_proofs(
            &vec![balance; burst as usize],
            &vec![random; burst as usize],
            &generators,
            &mut rng,
        )
        .unwrap();
    
        let range_proof_bytes = range_proof.to_bytes().to_vec();

        let balance = TwistedElGamal::new(&representative, &Scalar::from(balance), &random);

        let mut rng = StdRng::from_seed([0; 32]);
        let (public_key, secret_key) = generate_keypair(&mut rng);
        let message: &[u8] = b"Hello, world!";
        let digest = Digest(Sha512::digest(message).as_slice()[..32].try_into().unwrap());
        //let signature = Signature::new(&digest, &secret_key);
        
        let size = 64;
        let mut R: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); size];
        let mut x: Scalar = Scalar::one();
        let index = 0;

        for i in 0..size {
            let (sk, pk) = KeyGen();
            R[i] = pk;

            if i == index {
                x = sk;
            }
        }
        let M = "This is a triptych signature test, lets see if it works or not";

        let signature = Sign(&x, &M, &R);

        let a = Scalar::from(1u8);
        let A = a * RISTRETTO_BASEPOINT_POINT;

        let b = Scalar::from(2u8);
        let B = b * RISTRETTO_BASEPOINT_POINT;

        let c = Scalar::from(3u8);
        let C = c * RISTRETTO_BASEPOINT_POINT;

        let aB = create_shared_secret(&B, &a);
        let aC = create_shared_secret(&C, &a);

        let bA = create_shared_secret(&A, &b);
        let cA = create_shared_secret(&A, &c);

        assert_eq!(aB, bA);
        assert_eq!(aC, cA);

        let shared_secret = Scalar::from(4u8);

        let aB_bytes = bA.compress();
        let key1 = Key::from_slice(aB_bytes.as_bytes());
        let cipher1 = ChaCha20Poly1305::new(&key1);
        let nonce1 = ChaCha20Poly1305::generate_nonce(&mut OsRng); 
        let ciphertext1 = cipher1.encrypt(&nonce1, shared_secret.as_bytes().as_ref()).unwrap();

        let aC_bytes = cA.compress();
        let key2 = Key::from_slice(aC_bytes.as_bytes());
        let cipher2 = ChaCha20Poly1305::new(&key2);
        let nonce2 = ChaCha20Poly1305::generate_nonce(&mut OsRng); 
        let ciphertext2 = cipher2.encrypt(&nonce2, shared_secret.as_bytes().as_ref()).unwrap();
            
        'main: loop {
            let mut txs = Vec::new();

            interval.as_mut().tick().await;
            let now = Instant::now();

            for x in 0..burst {
                let id = thread_rng().gen_range(0, u128::MAX);
                let tx = Transaction::random(id, balance.clone(), representative.compress(), public_key.clone(), signature.clone(), (ciphertext1, ciphertext2));
                txs.push(tx);
            }
    
            let block = Block {
                txs, range_proof_bytes: range_proof_bytes.clone(),
            };
            let message = bincode::serialize(&block).unwrap();

            let bytes = Bytes::from(message);
            if let Err(e) = transport.send(bytes).await {
                warn!("Failed to send transaction: {}", e);
                break 'main;
            }
            if now.elapsed().as_millis() > BURST_DURATION as u128 {
                // NOTE: This log entry is used to compute performance.
                warn!("Transaction rate too high for this client");
            }
            counter += 1;
        }
        Ok(())
    }

    pub async fn wait(&self) {
        // Wait for all nodes to be online.
        info!("Waiting for all nodes to be online...");
        join_all(self.nodes.iter().cloned().map(|address| {
            tokio::spawn(async move {
                while TcpStream::connect(address).await.is_err() {
                    sleep(Duration::from_millis(10)).await;
                }
            })
        }))
        .await;
    }
}

