use crate::raw_order::{Commitment, Order};
use ethnum::U256;
use halo2curves::bn256::Fr as Fq;
use std::collections::HashMap;
pub struct StagingOrder {
    pub pubkey: U256,
    pub order: Order,
    pub timestamp: u32,
}

pub struct StagingQueue {
    pub stagingorders: HashMap<U256, HashMap<Fq, StagingOrder>>,
}

impl StagingQueue {
    pub fn add_order(&mut self, order: StagingOrder, hash: Fq) {
        let entry = self
            .stagingorders
            .entry(order.pubkey)
            .or_insert_with(HashMap::new);
        entry.insert(hash, order);
    }

    pub fn remove_order(&mut self, pubkey: U256, hash: Fq) {
        if let Some(orders) = self.stagingorders.get_mut(&pubkey) {
            orders.remove(&hash);
        }
    }
}
