pub struct SpendTransaction {
    //pub tx_hash: TxHash,
    //pub parent_hash: ParentHash,
    //pub balance: TwistedElGamal,
    //pub amount: TwistedElGamal,
    pub range_proof: Vec<u8>, // balance > 0
    //pub signature: Signature,
    //pub representative: PublicKey,
    // vecs to allow multiple txs in one
    // encryption proof
}