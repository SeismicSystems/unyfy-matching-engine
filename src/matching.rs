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
    let volume = order.s.v * order.s.p;
    let mut target_volume = three * volume;
    println!("target volume is: {:?}", target_volume);
    let opposite_side = ask_tree.read().await;

    let ask_tree: Vec<Node<T>> = inorder_traverse(&opposite_side).await;

    let mut matched_orders: Vec<Order> = Vec::new();

    for node in ask_tree.iter() {
        while node.price <= order.s.p && target_volume > Fq::from(0) {
            println!("node price is: {:?}", node.price);
            if node.value_sum <= target_volume {
                for (_, order_map) in &node.orders {
                    for (_, order_tuple) in order_map {
                        if order_tuple.1 != pubkey {
                            println!("matched order is: {:?}", order_tuple.0);
                            matched_orders.push(order_tuple.0.clone());
                        }
                    }
                }
                target_volume = target_volume - node.value_sum;
            } else {
                for (_, order_map) in &node.orders {
                    for (_, order_tuple) in order_map {
                        if order_tuple.1 != pubkey {
                            if (order_tuple.0.s.p * order_tuple.0.s.v) <= target_volume {
                                println!("matched order is: {:?}", order_tuple.0);
                                matched_orders.push(order_tuple.0.clone());
                                target_volume = target_volume - (order_tuple.0.s.v * order_tuple.0.s.p);
                            } else {
                                println!("matched order is: {:?}", order_tuple.0);
                                let order_clone_volume = (target_volume
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
                                target_volume = Fq::from(0);
                            }
                        }
                    }
                }
            }
        }
        println!("Target volume is: {:?}", target_volume);
    }

    if target_volume == Fq::from(0) {
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
    let volume = order.s.v * order.s.p;
    let mut target_volume = three * volume;
    let opposite_side = bid_tree.read().await;

    let bid_tree: Vec<Node<T>> = inorder_traverse(&opposite_side).await;

    // println!("bid tree is: {:?}", bid_tree);

    let mut matched_orders: Vec<Order> = Vec::new();

    for node in bid_tree.iter().rev() {
        println!("node price is: {:?}", node.price);
        if node.price >= order.s.p && target_volume > Fq::from(0) {
            println!("node price is: {:?}", node.price);
            if node.value_sum <= target_volume {
                for (_, order_map) in &node.orders {
                    for (_, order_tuple) in order_map {
                        if order_tuple.1 != pubkey {
                            println!("matched order is: {:?}", order_tuple.0);
                            matched_orders.push(order_tuple.0.clone());
                        }
                    }
                }
                target_volume = target_volume - node.value_sum;
            } else {
                for (_, order_map) in &node.orders {
                    for (_, order_tuple) in order_map {
                        if order_tuple.1 != pubkey {
                            if (order_tuple.0.s.p * order_tuple.0.s.v) <= target_volume {
                                println!("matched order is: {:?}", order_tuple.0);
                                matched_orders.push(order_tuple.0.clone());
                                target_volume = target_volume - (order_tuple.0.s.v * order_tuple.0.s.p);
                            } else {
                                println!("matched order is: {:?}", order_tuple.0);
                                let order_clone_volume = (target_volume
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
                                target_volume = Fq::from(0);
                            }
                        }
                    }
                }
            }
        }
    }

    if target_volume == Fq::from(0) {
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
