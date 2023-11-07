use ark_ff::BigInt;
use futures_util::stream::StreamExt;
use futures_util::TryFutureExt;
use futures_util::{FutureExt, SinkExt};
use halo2curves::ff::Field;
use num_bigint::{BigUint, ToBigUint};
use sha2::digest::typenum::uint;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use unyfy_matching_engine::models::Orderbook;
use unyfy_matching_engine::models::RBTree;
use warp::ws::Message;
use warp::Rejection;
use warp::*;
// use ark_bn254::Fr as Fq;
use ethnum::U256;
use halo2curves::bn256::Fr as Fq;
use rand::Rng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use unyfy_matching_engine::matching::*;
use unyfy_matching_engine::models::*;
use unyfy_matching_engine::raw_order::*;
use warp::ws::WebSocket;

pub struct Client {
    pub user_id: u32, // pubkey of the client
    pub topics: Vec<String>,
    pub sender: Option<mpsc::UnboundedSender<std::result::Result<Message, warp::Error>>>,
}
#[derive(serde::Deserialize, serde::Serialize)]
pub struct RegisterRequest {
    user_id: u32,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct RegisterResponse {
    url: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct Event {
    topic: String,
    user_id: Option<u32>,
    message: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct TopicsRequest {
    topics: Vec<String>,
}

type Result<T> = std::result::Result<T, Rejection>;
type Clients = Arc<Mutex<HashMap<String, Client>>>;

async fn read_and_insert(
    file_path: &Path,
    bid_tree: Arc<RwLock<RBTree<Fq>>>,
    ask_tree: Arc<RwLock<RBTree<Fq>>>,
) {
    let file = File::open(file_path).expect("cannot open file");
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.expect("could not read line");
        let order_data: Vec<&str> = line.split(',').collect();

        if order_data.len() != 6 {
            continue; // or handle the error
        }

        let pubkey = U256::from_str_hex(&format!("0x{}", order_data[0])).expect("invalid pubkey");
        let phi_value: u64 = order_data[1].parse().expect("invalid phi value");
        let chi = order_data[2].to_string();
        let d = "0x1".to_string();
        let p_value: u128 = order_data[4].parse().expect("invalid price");
        let p_bytes = p_value.to_le_bytes();
        let mut p_bytes_32: [u8; 32] = [0; 32];
        p_bytes_32[..16].copy_from_slice(&p_value.to_le_bytes());
        let v_value: u128 = order_data[5].parse().expect("invalid volume");
        let v_bytes = v_value.to_le_bytes();
        let mut v_bytes_32: [u8; 32] = [0; 32];
        v_bytes_32[..16].copy_from_slice(&v_value.to_le_bytes());
        let alpha_value = rand::thread_rng().gen::<u128>();
        // Assuming conversion function u128_to_fq is implemented for converting u128 to Fq
        let p = Fq::from_bytes(&p_bytes_32).unwrap();
        let v = Fq::from_bytes(&v_bytes_32).unwrap();
        let alpha = Fq::random(&mut rand::thread_rng());
        let phi = Fq::from(phi_value);
        let raw_order_commitment = hash_three_values(p, v, alpha).await;
        let order_commitment = Fq::from(raw_order_commitment);

        let order = Order {
            t: TransparentStructure { phi, chi, d },
            s: ShieldedStructure { p, v, alpha },
        };

        let commitment = Commitment {
            public: order.t.clone(),
            private: order_commitment,
        };

        let data = Data {
            pubkey,
            raw_order: order,
            raw_order_commitment: commitment,
        };

        match phi_value {
            0 => {
                let mut bid_tree_write = bid_tree.write().await;
                bid_tree_write.insert(p, data).await;
            }
            1 => {
                let mut ask_tree_write = ask_tree.write().await;
                ask_tree_write.insert(p, data).await;
            }
            _ => eprintln!("Invalid phi value: {:?}", phi),
        }
    }
}

async fn handle_websocket_messages(
    websocket: WebSocket,
    bid_tree: Arc<RwLock<RBTree<Fq>>>,
    ask_tree: Arc<RwLock<RBTree<Fq>>>,
) {
    let (mut sender, mut receiver) = websocket.split();

    while let Some(message) = receiver.next().await {
        if let Ok(msg) = message {
            if msg.is_text() {
                // Parse the message
                let text = msg.to_str().unwrap();
                let json_msg: serde_json::Value = serde_json::from_str(text).unwrap();

                // Assuming 'action' field determines the kind of the message
                if json_msg["action"] == "sendorder" {
                    println!("Hi!");
                    let side = json_msg["data"]["transparent"]["side"].as_str().unwrap();
                    let side_num = side.to_string().parse::<u64>().unwrap();
                    let price_str = json_msg["data"]["shielded"]["price"].as_str().unwrap();
                    let volume_str = json_msg["data"]["shielded"]["volume"].as_str().unwrap();
                    let access_key_str =
                        json_msg["data"]["shielded"]["accessKey"].as_str().unwrap();
                    // Parse the strings into BigUint, assuming decimal format
                    let price = BigUint::parse_bytes(price_str.as_bytes(), 10).unwrap();
                    let volume = BigUint::parse_bytes(volume_str.as_bytes(), 10).unwrap();
                    let access_key = BigUint::parse_bytes(access_key_str.as_bytes(), 10).unwrap();

                    let price_bytes_vec = price.to_bytes_le();
                    let volume_bytes_vec = volume.to_bytes_le();
                    let access_key_bytes_vec = access_key.to_bytes_le();

                    // Convert BigUint to [u8; 32] in little-endian format
                    let mut price_bytes = [0u8; 32];
                    let mut volume_bytes = [0u8; 32];
                    let mut access_key_bytes = [0u8; 32];
                    for (i, byte) in price_bytes_vec.iter().enumerate() {
                        price_bytes[i] = *byte;
                    }

                    for (i, byte) in volume_bytes_vec.iter().enumerate() {
                        volume_bytes[i] = *byte;
                    }

                    for (i, byte) in access_key_bytes_vec.iter().enumerate() {
                        access_key_bytes[i] = *byte;
                    }

                    let token = json_msg["data"]["transparent"]["token"].as_str().unwrap();
                    let denomination = json_msg["data"]["transparent"]["denomination"]
                        .as_str()
                        .unwrap();

                    // Create the order

                    let order = Order {
                        t: TransparentStructure {
                            phi: Fq::from(side_num),
                            chi: token.to_string(),
                            d: denomination.to_string(),
                        },
                        s: ShieldedStructure {
                            p: Fq::from_bytes(&price_bytes).unwrap(),
                            v: Fq::from_bytes(&volume_bytes).unwrap(),
                            alpha: Fq::from_bytes(&access_key_bytes).unwrap(),
                        },
                    };

                    let hash = hash_three_values(order.s.p, order.s.v, order.s.alpha).await;

                    let commitment = Commitment {
                        public: order.t.clone(),
                        private: hash,
                    };

                    let data = Data {
                        pubkey: U256::from_str_hex("0x0").unwrap(), // example pubkey, replace with actual -- TODO
                        raw_order: order.clone(),
                        raw_order_commitment: commitment.clone(),
                    };

                    println!("We here!");

                    if side_num == 0 {
                        bid_tree.write().await.insert(order.s.p, data).await;
                        bid_tree.read().await.print_inorder().await;
                    } else {
                        ask_tree.write().await.insert(order.s.p, data).await;
                        ask_tree.read().await.print_inorder().await;
                    }

                    // Add to the appropriate tree
                    /*if side == 0 {
                        let mut bid_tree_write = bid_tree.write().await;
                        bid_tree_write.insert(order.s.p, data).await;
                        bid_tree.read().await.print_inorder().await;
                        // should actually be inserted into the staging queue -- TODO
                    } else {
                        let mut ask_tree_write = ask_tree.write().await;
                        ask_tree_write.insert(order.s.p, data).await;
                        ask_tree.read().await.print_inorder().await;
                        // should actually be inserted into the staging queue -- TODO
                    }


                    println!("Ok!!"); */

                    let side_return =
                        BigUint::from_bytes_le(&order.t.phi.to_bytes()).to_str_radix(10);
                    let commitment_return =
                        BigUint::from_bytes_le(&commitment.private.to_bytes()).to_str_radix(10);

                    // Construct the JSON payload
                    let payload = json!({
                        "action": "sendorder",
                        "enclaveSignature": {
                            "orderCommitment": {
                                "transparent": {
                                    "side": side_return,
                                    "token": order.t.chi,
                                    "denomination": order.t.d
                                },
                                "shielded": commitment_return,
                            },
                            "signatureValue": "Yes"
                        }
                    });

                    // Send the payload back to the client
                    let message = Message::text(payload.to_string());
                    sender.send(message).await.unwrap();

                    // sender.
                } else if json_msg["action"] == "getcrossedorders" {
                    let side = json_msg["data"]["transparent"]["side"].as_str().unwrap();
                    let side_num = side.to_string().parse::<u64>().unwrap();
                    let price_str = json_msg["data"]["shielded"]["price"].as_str().unwrap();
                    let volume_str = json_msg["data"]["shielded"]["volume"].as_str().unwrap();
                    let access_key_str =
                        json_msg["data"]["shielded"]["accessKey"].as_str().unwrap();
                    // Parse the strings into BigUint, assuming decimal format
                    let price = BigUint::parse_bytes(price_str.as_bytes(), 10).unwrap();
                    let volume = BigUint::parse_bytes(volume_str.as_bytes(), 10).unwrap();
                    let access_key = BigUint::parse_bytes(access_key_str.as_bytes(), 10).unwrap();

                    let price_bytes_vec = price.to_bytes_le();
                    let volume_bytes_vec = volume.to_bytes_le();
                    let access_key_bytes_vec = access_key.to_bytes_le();

                    // Convert BigUint to [u8; 32] in little-endian format
                    let mut price_bytes = [0u8; 32];
                    let mut volume_bytes = [0u8; 32];
                    let mut access_key_bytes = [0u8; 32];
                    for (i, byte) in price_bytes_vec.iter().enumerate() {
                        price_bytes[i] = *byte;
                    }

                    for (i, byte) in volume_bytes_vec.iter().enumerate() {
                        volume_bytes[i] = *byte;
                    }

                    for (i, byte) in access_key_bytes_vec.iter().enumerate() {
                        access_key_bytes[i] = *byte;
                    }

                    let token = json_msg["data"]["transparent"]["token"].as_str().unwrap();
                    let denomination = json_msg["data"]["transparent"]["denomination"]
                        .as_str()
                        .unwrap();

                    // Create the order

                    let order = Order {
                        t: TransparentStructure {
                            phi: Fq::from(side_num),
                            chi: token.to_string(),
                            d: denomination.to_string(),
                        },
                        s: ShieldedStructure {
                            p: Fq::from_bytes(&price_bytes).unwrap(),
                            v: Fq::from_bytes(&volume_bytes).unwrap(),
                            alpha: Fq::from_bytes(&access_key_bytes).unwrap(),
                        },
                    };

                    let hash = hash_three_values(order.s.p, order.s.v, order.s.alpha).await;

                    let commitment = Commitment {
                        public: order.t.clone(),
                        private: hash,
                    };

                    let data = Data {
                        pubkey: U256::from_str_hex("0x0").unwrap(), // example pubkey, replace with actual -- TODO
                        raw_order: order.clone(),
                        raw_order_commitment: commitment.clone(),
                    };

                    let mut found: bool;

                    let mut matches: Option<Vec<Order>>;

                    if side_num == 0 {
                        match bid_tree.read().await.search_exact_order(data).await {
                            Some(_) => found = true,
                            None => found = false,
                        }

                        if found {
                            matches =
                                Some(match_bid(order.clone(), ask_tree.clone()).await.unwrap());
                        } else {
                            matches = None
                        }
                    } else {
                        match ask_tree.read().await.search_exact_order(data).await {
                            Some(_) => found = true,
                            None => found = false,
                        }

                        if found {
                            matches =
                                Some(match_ask(order.clone(), bid_tree.clone()).await.unwrap());
                        } else {
                            matches = None
                        }
                    }
                    let mut json_array = serde_json::Value::Array(Vec::new());
                    match matches {
                        Some(matches) => {
                            for order in matches {
                                let hash =
                                    hash_three_values(order.s.p, order.s.v, order.s.alpha).await;
                                let order_json = json!({
                                    "raw_order": {
                                        "t": {
                                            "phi": BigUint::from_bytes_le(&order.t.phi.to_bytes()).to_str_radix(10),
                                            "chi": order.t.chi,
                                            "d": order.t.d,
                                        },
                                        "s": {
                                            "p": BigUint::from_bytes_le(&order.s.p.to_bytes()).to_str_radix(10),
                                            "v": BigUint::from_bytes_le(&order.s.v.to_bytes()).to_str_radix(10),
                                            "alpha": BigUint::from_bytes_le(&order.s.alpha.to_bytes()).to_str_radix(10),
                                        },
                                    },
                                    "raw_order_commitment": {
                                        "public": {
                                            "phi": BigUint::from_bytes_le(&order.t.phi.to_bytes()).to_str_radix(10),
                                            "chi": order.t.chi,
                                            "d": order.t.d,
                                        },
                                        "private": BigUint::from_bytes_le(&hash.to_bytes()).to_str_radix(10),
                                    },
                                });
                                json_array.as_array_mut().unwrap().push(order_json);
                            }
                        }
                        None => {}
                    }

                    // Construct the JSON payload
                    let payload = json!({
                        "action": "getcrossedorders",
                        "orderCommitment": {
                            "transparent": {
                                "side": side,
                                "token": order.t.chi,
                                "denomination": order.t.d
                            },
                            "shielded": BigUint::from_bytes_le(&commitment.private.to_bytes()).to_str_radix(10),
                        },
                        "data": {
                            "orders": json_array,
                        }
                    });

                    let message = Message::text(payload.to_string());
                    sender.send(message).await.unwrap();
                }
            }
        }
    }
}

async fn hash_three_values(a: Fq, b: Fq, c: Fq) -> Fq {
    let mut hasher = Sha256::new();
    hasher.update(a.to_bytes());
    hasher.update(b.to_bytes());
    hasher.update(c.to_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    // println!("hash is: {:?} ", hash);
    // let hash_array: [u8; 32] = hash.into();
    let mut bytes = [0u8; 32];
    bytes[0..30].copy_from_slice(&hash[0..30]);
    Fq::from_bytes(&bytes).unwrap()
}

type SafeOrderbook = Arc<RwLock<Orderbook<Fq>>>;

#[tokio::main]
async fn main() {
    // let clients = Clients::new(Mutex::new(HashMap::new()));
    let sample = Arc::new(RwLock::new(u8::from(0u8)));
    let sample = warp::any().map(move || sample.clone());

    let orderbook = Orderbook::<Fq> {
        bid_tree: Arc::new(RwLock::new(RBTree::new())),
        ask_tree: Arc::new(RwLock::new(RBTree::new())),
    };

    let file_path = Path::new("orders.txt");
    read_and_insert(
        &file_path,
        orderbook.bid_tree.clone(),
        orderbook.ask_tree.clone(),
    )
    .await;

    // let safe_orderbook = SafeOrderbook::new(RwLock::new(orderbook));

    // let safe_orderbook = warp::any().map(move || safe_orderbook.clone());

    let bid_tree = warp::any().map(move || orderbook.bid_tree.clone());
    let ask_tree = warp::any().map(move || orderbook.ask_tree.clone());

    pretty_env_logger::init();

    let routes = warp::path("ws")
        .and(warp::ws())
        .and(bid_tree)
        .and(ask_tree)
        .map(|ws: warp::ws::Ws, bid_tree, ask_tree| {
            ws.on_upgrade(move |socket| handle_websocket_messages(socket, bid_tree, ask_tree))
        });
    // Then in your main function:

    warp::serve(routes).run(([0, 0, 0, 0], 8000)).await;
}
