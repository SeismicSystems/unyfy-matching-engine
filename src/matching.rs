// use ark_bn254::Fr as Fq;
use crate::models::RBTree;
use crate::models::{LimitNodePtr, Node};
use crate::raw_order::Order;
use crate::raw_order::ShieldedStructure;
use async_recursion::async_recursion;
use ethnum::U256;
use halo2curves::bn256::Fr as Fq;
use halo2curves::ff::Field;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::RwLock;

pub async fn match_bid<T>(
    order: Order,
    pubkey: U256,
    ask_tree: Arc<RwLock<RBTree<T>>>,
) -> Option<Vec<Order>>
where
    T: Ord + Clone + Debug + Copy,
{
    let three = Fq::from(3);
    let total_volume = order.s.v * order.s.p;
    let mut volume_cutoff = three * total_volume;
    println!("target volume is: {:?}", volume_cutoff);
    let opposite_side = ask_tree.read().await;

    let ask_tree: Vec<Node<T>> = inorder_traverse(&opposite_side).await;

    let mut matched_orders: Vec<Order> = Vec::new();

    for node in ask_tree.iter() {
        if node.price <= order.s.p && volume_cutoff > Fq::from(0) {
            println!("node price is: {:?}", node.price);
            if node.value_sum <= volume_cutoff {
                for (_, order_map) in &node.orders {
                    for (_, order_tuple) in order_map {
                        if order_tuple.1 != pubkey {
                            println!("matched order is: {:?}", order_tuple.0);
                            matched_orders.push(order_tuple.0.clone());
                        }
                    }
                }
                volume_cutoff = volume_cutoff - node.value_sum;
            } else {
                for (_, order_map) in &node.orders {
                    for (_, order_tuple) in order_map {
                        if order_tuple.1 != pubkey {
                            if (order_tuple.0.s.p * order_tuple.0.s.v) <= volume_cutoff {
                                println!("matched order is: {:?}", order_tuple.0);
                                matched_orders.push(order_tuple.0.clone());
                                volume_cutoff = volume_cutoff - (order_tuple.0.s.v * order_tuple.0.s.p);
                            } else {
                                println!("matched order is: {:?}", order_tuple.0);
                                let order_clone_volume = (volume_cutoff
                                    * order_tuple.0.s.p.invert().unwrap())
                                    + Fq::from(1000000000);
                                let order_clone = Order {
                                    t: order_tuple.0.t.clone(),
                                    s: ShieldedStructure {
                                        p: order_tuple.0.s.p,
                                        v: order_clone_volume,
                                        alpha: order_tuple.0.s.alpha,
                                    },
                                };
                                matched_orders.push(order_clone);
                                volume_cutoff = Fq::from(0);
                            }
                        }
                    }
                }
            }
        }
        println!("Target volume is: {:?}", volume_cutoff);
    }

    if !matched_orders.is_empty() {
        Some(matched_orders)
    } else {
        None
    }
}

pub async fn match_ask<T>(
    order: Order,
    pubkey: U256,
    bid_tree: Arc<RwLock<RBTree<T>>>,
) -> Option<Vec<Order>>
where
    T: Ord + Clone + Debug + Copy,
{
    let three = Fq::from(3);
    let total_volume = order.s.v * order.s.p;
    let mut volume_cutoff = three * total_volume;
    let opposite_side = bid_tree.read().await;

    let bid_tree: Vec<Node<T>> = inorder_traverse(&opposite_side).await;

    // println!("bid tree is: {:?}", bid_tree);

    let mut matched_orders: Vec<Order> = Vec::new();

    for node in bid_tree.iter().rev() {
        println!("node price is: {:?}", node.price);
        if node.price >= order.s.p && volume_cutoff > Fq::from(0) {
            println!("node price is: {:?}", node.price);
            if node.value_sum <= volume_cutoff {
                for (_, order_map) in &node.orders {
                    for (_, order_tuple) in order_map {
                        if order_tuple.1 != pubkey {
                            println!("matched order is: {:?}", order_tuple.0);
                            matched_orders.push(order_tuple.0.clone());
                        }
                    }
                }
                volume_cutoff = volume_cutoff - node.value_sum;
            } else {
                for (_, order_map) in &node.orders {
                    for (_, order_tuple) in order_map {
                        if order_tuple.1 != pubkey {
                            if (order_tuple.0.s.p * order_tuple.0.s.v) <= volume_cutoff {
                                println!("matched order is: {:?}", order_tuple.0);
                                matched_orders.push(order_tuple.0.clone());
                                volume_cutoff = volume_cutoff - (order_tuple.0.s.v * order_tuple.0.s.p);
                            } else {
                                println!("matched order is: {:?}", order_tuple.0);
                                let order_clone_volume = (volume_cutoff
                                    * order_tuple.0.s.p.invert().unwrap())
                                    + Fq::from(1000000000);
                                let order_clone = Order {
                                    t: order_tuple.0.t.clone(),
                                    s: ShieldedStructure {
                                        p: order_tuple.0.s.p,
                                        v: order_clone_volume,
                                        alpha: order_tuple.0.s.alpha,
                                    },
                                };
                                matched_orders.push(order_clone);
                                volume_cutoff = Fq::from(0);
                            }
                        }
                    }
                }
            }
        }
    }

    if !matched_orders.is_empty() {
        Some(matched_orders)
    } else {
        println!("No match!");
        None
    }
}

pub async fn inorder_traverse<T>(tree: &RBTree<T>) -> Vec<Node<T>>
where
    T: Ord + Clone + Debug + Copy,
{
    let mut result: Vec<Node<T>> = Vec::new();
    inorder(&tree.root, &mut result).await;
    result
}

#[async_recursion]
pub async fn inorder<T>(tree: &LimitNodePtr<T>, result: &mut Vec<Node<T>>)
where
    T: Ord + Clone + Debug + Copy,
{
    if let Some(node) = tree {
        inorder(&node.read().await.left, result).await;
        result.push(node.read().await.clone());
        inorder(&node.read().await.left, result).await;
    }
}
