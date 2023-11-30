use halo2curves::bn256::Fr as Fq;
use serde::{Deserialize, Serialize};

// F_q is the scalar field of curve bn128
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TransparentStructure {
    pub phi: Fq,     // 0 for bid, 1 for ask
    pub chi: String, // Token address for the target project
    pub d: String,   // Denomination token address, set to "0x1" for USDC or ETH
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct TransparentStructureReturn {
    pub phi: [u8; 32], // 0 for bid, 1 for ask
    pub chi: String,   // Token address for the target project
    pub d: String,     // Denomination token address, set to "0x1" for USDC or ETH
}

#[derive(Debug, Copy, Clone)]
pub struct ShieldedStructure {
    pub p: Fq,     // Price, scaled by 10^9 with 10^7 precision
    pub v: Fq,     // Volume, scaled by 10^9
    pub alpha: Fq, // Access key, randomly sampled from Fq
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct ShieldedStructureReturn {
    pub p: [u8; 32],     // Price, scaled by 10^9 with 10^7 precision
    pub v: [u8; 32],     // Volume, scaled by 10^9
    pub alpha: [u8; 32], // Access key, randomly sampled from Fq
}

#[derive(Debug, Clone)]
pub struct Order {
    pub t: TransparentStructure,
    pub s: ShieldedStructure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderReturn {
    pub t: TransparentStructureReturn,
    pub s: ShieldedStructureReturn,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Commitment {
    pub public: TransparentStructure,
    pub private: Fq, /* the private part of the commitment
                     of an order O is defined as H(O.s), where
                      H is a hash function */
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct CommitmentReturn {
    pub public: TransparentStructureReturn,
    pub private: [u8; 32], /* the private part of the commitment
                           of an order O is defined as H(O.s), where
                            H is a hash function */
}
