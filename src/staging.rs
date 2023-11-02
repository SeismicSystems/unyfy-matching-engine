use crate::raw_order::{Commitment, Order};
use std::collections::HashMap;
pub struct StagingOrder {
    pub pubkey: u32,
    pub order: Order,
    pub timestamp: u32,
}

pub struct StagingQueue {
    stagingorders: HashMap<u32, Vec<HashMap<Commitment, StagingOrder>>>,
}

impl StagingQueue {
    pub fn add_order(&mut self, order: StagingOrder, commitment: Commitment) {
        let entry = self
            .stagingorders
            .entry(order.pubkey)
            .or_insert_with(Vec::new);
        let order_map = entry.iter_mut().find(|x| x.contains_key(&commitment));
        if let Some(order_map) = order_map {
            order_map.insert(commitment, order);
        } else {
            let mut new_map = HashMap::new();
            new_map.insert(commitment, order);
            entry.push(new_map);
        }
    }

    pub fn remove_order(&mut self, pubkey: u32, commitment: Commitment) {
        if let Some(orders) = self.stagingorders.get_mut(&pubkey) {
            orders.retain(|x| !x.contains_key(&commitment));
        }
    }
}
