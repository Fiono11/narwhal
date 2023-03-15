// Copyright(C) Facebook, Inc. and its affiliates.
use super::*;
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng as _;

impl Hash for &[u8] {
    fn digest(&self) -> Digest {
        Digest(Sha512::digest(self).as_slice()[..32].try_into().unwrap())
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.encode_base64())
    }
}

pub fn keys() -> Vec<(PublicKey, SecretKey)> {
    let mut rng = StdRng::from_seed([0; 32]);
    (0..4).map(|_| generate_keypair(&mut rng)).collect()
}

#[test]
fn import_export_public_key() {
    let (public_key, _) = keys().pop().unwrap();
    let export = public_key.encode_base64();
    let import = PublicKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap(), public_key);
}

#[test]
fn import_export_secret_key() {
    let (_, secret_key) = keys().pop().unwrap();
    let export = secret_key.encode_base64();
    let import = SecretKey::decode_base64(&export);
    assert!(import.is_ok());
    assert_eq!(import.unwrap(), secret_key);
}

#[test]
fn verify_valid_signature() {
    // Get a keypair.
    let (public_key, secret_key) = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let signature = Signature::new(&digest, &secret_key);

    // Verify the signature.
    assert!(signature.verify(&digest, &public_key).is_ok());
}

#[test]
fn verify_invalid_signature() {
    // Get a keypair.
    let (public_key, secret_key) = keys().pop().unwrap();

    // Make signature.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let signature = Signature::new(&digest, &secret_key);

    // Verify the signature.
    let bad_message: &[u8] = b"Bad message!";
    let digest = bad_message.digest();
    assert!(signature.verify(&digest, &public_key).is_err());
}

#[test]
fn verify_valid_batch() {
    // Make signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let mut keys = keys();
    let signatures: Vec<_> = (0..3)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&digest, &secret_key))
        })
        .collect();

    // Verify the batch.
    assert!(Signature::verify_batch(&digest, &signatures).is_ok());
}

#[test]
fn verify_invalid_batch() {
    // Make 2 valid signatures.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let mut keys = keys();
    let mut signatures: Vec<_> = (0..2)
        .map(|_| {
            let (public_key, secret_key) = keys.pop().unwrap();
            (public_key, Signature::new(&digest, &secret_key))
        })
        .collect();

    // Add an invalid signature.
    let (public_key, _) = keys.pop().unwrap();
    signatures.push((public_key, Signature::default()));

    // Verify the batch.
    assert!(Signature::verify_batch(&digest, &signatures).is_err());
}

#[tokio::test]
async fn signature_service() {
    // Get a keypair.
    let (public_key, secret_key) = keys().pop().unwrap();

    // Spawn the signature service.
    let mut service = SignatureService::new(secret_key);

    // Request signature from the service.
    let message: &[u8] = b"Hello, world!";
    let digest = message.digest();
    let signature = service.request_signature(digest.clone()).await;

    // Verify the signature we received.
    assert!(signature.verify(&digest, &public_key).is_ok());
}

#[test]
fn decrypt_twisted() {
    let mut csprng = rand::rngs::OsRng;
    let mut rng = rand::rngs::OsRng;

    let sk = SecretKey::new(&mut csprng);
    let pk = PublicKey::from(&sk);

    let message = Scalar::random(&mut rng);
    let ciphertext = pk.encrypt_twisted(&message, &Scalar::random(&mut rng));

    let decryption = sk.decrypt_twisted(&ciphertext);

    assert_eq!(decryption, message * PedersenGens::default().B);
}

#[test]
fn equal_proof() {
    let mut rng = rand::rngs::OsRng;
    let generators = PedersenGens::default();
    let sk = Scalar::random(&mut rng);
    let v = Scalar::from(10u64);
    let r1 = Scalar::random(&mut rng);
    let r2 = Scalar::random(&mut rng);
    let PK1 = RistrettoPoint::random(&mut rng);
    let PK2 = RistrettoPoint::random(&mut rng);
    let proof = ElGamalProof::new(v, r1, r2, PK1, PK2);
    proof.verify(r1 * PK1, r2 * PK2, r1 * generators.B + v * generators.B_blinding, r2 * generators.B + v * generators.B_blinding, PK1, PK2).unwrap();
}

#[test]
fn test_baby_step_giant_step_elgamal() {
    let generators = PedersenGens::default();
    let mut rng = rand::thread_rng();
    let precomputed = BSGSTable::create(&generators.B_blinding);
    for _i in 0..1 {
        let scalar = Scalar::from(rng.gen::<u32>());
        let point = scalar * generators.B_blinding;
        let s = baby_step_giant_step_elgamal(&generators.B_blinding, &point, &precomputed.0)
            .unwrap();
        assert_eq!(s, scalar);
    }
}

#[test]
fn prove_correct_decryption_twisted() {
    let mut csprng = OsRng;
    let sk = SecretKey::new(&mut csprng);
    let pk = PublicKey::from(&sk);

    let message = Scalar::random(&mut csprng);
    let ciphertext = pk.encrypt_twisted(&message, &Scalar::random(&mut csprng));

    let decryption = sk.decrypt_twisted(&ciphertext);
    let proof = sk.prove_correct_decryption_twisted(&ciphertext, &decryption);

    assert!(pk.verify_correct_decryption_twisted(&proof, &ciphertext, &decryption));
}

#[test]
fn range_proof() {
    let mut rng = OsRng;
    let balance = rand::thread_rng().gen_range(0, u64::MAX);
    let random = Scalar::random(&mut rng);
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from(&sk);
    //let twisted_elgamal = pk.encrypt_twisted(&Scalar::from(balance), &random);
    let twisted_elgamal = TwistedElGamal::new(&CompressedRistretto(pk.0).decompress().unwrap(), &Scalar::from(balance), &random);
    let generators = PedersenGens::default();
    let (rp, c) = generate_range_proofs(
        &vec![balance],
        &vec![random],
        &generators,
        &mut rng,
    )
    .unwrap();
    check_range_proofs(
        &rp,
        &[twisted_elgamal.c2],
        &generators,
        &mut rng,
    )
    .unwrap();
}

#[test]
fn generate_and_check() {
    let mut rng = rand::rngs::OsRng;
    let values: Vec<u64> = vec![rand::thread_rng().gen_range(0, u64::MAX)];
    let blindings: Vec<Scalar> = vec![Scalar::random(&mut rng)];
    let generators = PedersenGens::default();
    let (proof, commitments) =
        generate_range_proofs(&values, &blindings, &generators, &mut rng).unwrap();

    match check_range_proofs(&proof, &commitments, &generators, &mut rng) {
        Ok(_) => {} // This is expected.
        Err(e) => panic!("{:?}", e),
    }
}

