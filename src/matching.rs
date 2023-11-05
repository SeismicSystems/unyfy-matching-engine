use ark_bn254::Fr as Fq;
use crate::raw_order::ShieldedStructure;
use crate::models::RBTree;
use crate::models::{Node,LimitNodePtr};
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::RwLock;
use crate::raw_order::Order;
use std::fmt::Display;
use async_recursion::async_recursion;

// TODO -- insert the order

pub async fn match_bid<T>(order: Order, ask_tree: Arc<RwLock<RBTree<T>>>) -> Option<Vec<Order>> where T: Ord + Clone + Debug + Display + Copy{
    let three = Fq::from(3u32);
    let volume = order.s.v*order.s.p;
    let mut target_volume = three*volume;
    let opposite_side = ask_tree.read().unwrap();
    
    let ask_tree: Vec<Node<T>> = inorder_traverse(&opposite_side).await;

    let mut matched_orders: Vec<Order> = Vec::new();

    for node in ask_tree.iter(){
    
    if node.price <= order.s.p && target_volume > Fq::from(0u32){
        if node.value_sum <= target_volume {
            for (_, order_map) in &node.orders {
                for (_, order) in order_map {
                    matched_orders.push(order.clone());
                }
            }
            target_volume=target_volume-node.value_sum;
        }else{
            for (_, order_map) in &node.orders {
                for (_, order) in order_map {
                    if (order.s.p*order.s.v) <= target_volume {
                        matched_orders.push(order.clone());
                        target_volume=target_volume-(order.s.v*order.s.p);
                    }else{
                        let order_clone_volume = (target_volume / order.s.p) + Fq::from(1u32);
                        let order_clone = Order {
                            t: order.t.clone(),
                            s: ShieldedStructure {
                                p: order.s.p,
                                v: order_clone_volume,
                                alpha: order.s.alpha,
                            },
                        };  
                        matched_orders.push(order_clone);
                        target_volume = Fq::from(0u32);
                    }
                }
            }
        }
    
    }

    }

    if target_volume == Fq::from(0u32){
        Some(matched_orders)
    }
    else{
        None
    }

}

async fn match_ask<T>(order: Order, bid_tree: Arc<RwLock<RBTree<T>>>) -> Option<Vec<Order>> where T: Ord + Clone + Debug + Display + Copy{
    let three = Fq::from(3u32);
    let volume = order.s.v*order.s.p;
    let mut target_volume = three*volume;
    let opposite_side = bid_tree.read().unwrap();
    
    let bid_tree: Vec<Node<T>> = inorder_traverse(&opposite_side).await;

    let mut matched_orders: Vec<Order> = Vec::new();

    for node in bid_tree.iter().rev(){
    
    if node.price >= order.s.p && target_volume > Fq::from(0u32){
        if node.value_sum <= target_volume {
            for (_, order_map) in &node.orders {
                for (_, order) in order_map {
                    matched_orders.push(order.clone());
                }
            }
            target_volume=target_volume-node.value_sum;
        }else{
            for (_, order_map) in &node.orders {
                for (_, order) in order_map {
                    if (order.s.p*order.s.v) <= target_volume {
                        matched_orders.push(order.clone());
                        target_volume=target_volume-(order.s.v*order.s.p);
                    }else{
                        let order_clone_volume = (target_volume / order.s.p) + Fq::from(1u32);
                        let order_clone = Order {
                            t: order.t.clone(),
                            s: ShieldedStructure {
                                p: order.s.p,
                                v: order_clone_volume,
                                alpha: order.s.alpha,
                            },
                        };  
                        matched_orders.push(order_clone);
                        target_volume = Fq::from(0u32);
                    }
                }
            }
        }
    
    }

    }

    if target_volume == Fq::from(0u32){
        Some(matched_orders)
    }
    else{
        println!("No match!");
        None
    }

}



pub async fn inorder_traverse<T>(tree: &RBTree<T>)->Vec<Node<T>> where T: Ord + Clone + Debug + Display + Copy{
    let mut result: Vec<Node<T>> = Vec::new();
    inorder(&tree.root, &mut result).await;
    result

}

#[async_recursion]
pub async fn inorder<T>(tree: &LimitNodePtr<T>, result: &mut Vec<Node<T>>) where T: Ord + Clone + Debug + Display + Copy{
        if let Some(node) = tree {
            inorder(&node.read().await.left, result).await;
            result.push(node.read().await.clone());
            inorder(&node.read().await.left, result).await;
        }

}