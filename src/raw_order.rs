use ark_bn254::Fr as Fq;

// F_q is the scalar field of curve bn128
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TransparentStructure {
    pub phi: Fq,     // 0 for bid, 1 for ask
    pub chi: String, // Token address for the target project
    pub d: String,   // Denomination token address, set to "0x1" for USDC or ETH
}
#[derive(Debug, Copy, Clone)]
pub struct ShieldedStructure {
    pub p: Fq,     // Price, scaled by 10^9 with 10^7 precision
    pub v: Fq,     // Volume, scaled by 10^9
    pub alpha: Fq, // Access key, randomly sampled from Fq
}
#[derive(Debug, Clone)]
pub struct Order {
    pub t: TransparentStructure,
    pub s: ShieldedStructure,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Commitment {
    public: TransparentStructure,
    private: Fq, /* the private part of the commitment
                 of an order O is defined as H(O.s), where
                  H is a hash function */
}
