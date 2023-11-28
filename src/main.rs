use ark_ff::BigInt;
use futures_util::stream::StreamExt;
use futures_util::TryFutureExt;
use futures_util::{FutureExt, SinkExt};
use std::fs::read_to_string;
use halo2curves::ff::Field;
use num_bigint::{BigUint, ToBigUint};
use serde_derive::{Deserialize, Serialize};
use sha2::digest::typenum::uint;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use unyfy_matching_engine::models::Orderbook;
use unyfy_matching_engine::models::RBTree;
use warp::ws::Message;
use warp::*;
// use ark_bn254::Fr as Fq;
use ethnum::U256;
use halo2curves::bn256::Fr as Fq;
use rand::Rng;
use serde_json::json;
use sha2::{Digest, Sha256};
// use std::error::Error;
use ethers::prelude::*;
use std::fmt::Debug;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use std::time::SystemTime;
use unyfy_matching_engine::matching::*;
use unyfy_matching_engine::models::*;
use unyfy_matching_engine::raw_order::*;
use warp::ws::WebSocket;
use warp::Reply;
// use ethers::utils::keccak256;
use chrono::prelude::*;
use dotenv::dotenv;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::env;
use std::fmt;
use std::io::Error;
use std::str::FromStr;
use std::time::UNIX_EPOCH;
use warp::{
    filters::header::headers_cloned,
    http::header::{HeaderMap, HeaderValue, AUTHORIZATION},
    reject, Filter, Rejection,
};
use web3::signing::{keccak256, recover, Key};
use ethsign::{PublicKey, SecretKey, Signature};


const BEARER: &str = "Bearer ";

const JWT_SECRET: &[u8] = b"secret";
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

// Shared state to track challenges
pub struct AppState {
    challenges: Mutex<HashMap<String, u64>>, // Maps challenge ID/string to the timestamp of the challenge, useful for timeouts
}

#[derive(Deserialize, Serialize)]
pub struct ClientResponse {
    challenge_id: String,
    signature: String,
    pub_key: String,
}

#[derive(Debug, Deserialize, Serialize)]

pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

#[derive(Debug)]
pub enum MyError {
    Timeout,
    InvalidSignature,
    InvalidChallenge,
    JWTTokenCreationError,
    NoAuthHeaderError,
    InvalidAuthHeaderError,
    JWTTokenError,
}

impl warp::reject::Reject for MyError {}

type ResultUtil<T> = std::result::Result<T, Rejection>;
type Clients = Arc<Mutex<HashMap<String, Client>>>;
// type Result<T> = std::result::Result<T, error::Error>;
type WebResult<T> = std::result::Result<T, Rejection>;

async fn clear_orderbook<T: Ord + Debug + Copy>(tree: &Arc<RwLock<RBTree<T>>>) {
    let mut tree = tree.write().await;
    tree.root = None;
    tree.count = 0;
}

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
    pubkey: String,
) {
    
    let (mut sender, mut receiver) = websocket.split();

    sender
        .send(Message::text("Hello from the server!"))
        .await
        .unwrap();

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
                    let hash_str = json_msg["hash"].as_str().unwrap();
                    // Parse the strings into BigUint, assuming decimal format
                    let price = BigUint::parse_bytes(price_str.as_bytes(), 10).unwrap();
                    let volume = BigUint::parse_bytes(volume_str.as_bytes(), 10).unwrap();
                    let access_key = BigUint::parse_bytes(access_key_str.as_bytes(), 16).unwrap();
                    let hash = BigUint::parse_bytes(hash_str.as_bytes(), 16).unwrap();

                    let price_bytes_vec = price.to_bytes_le();
                    let volume_bytes_vec = volume.to_bytes_le();
                    let access_key_bytes_vec = access_key.to_bytes_le();
                    let hash_bytes_vec = hash.to_bytes_le();

                    // Convert BigUint to [u8; 32] in little-endian format
                    let mut price_bytes = [0u8; 32];
                    let mut volume_bytes = [0u8; 32];
                    let mut access_key_bytes = [0u8; 32];
                    let mut hash_bytes = [0u8; 32];
                    for (i, byte) in price_bytes_vec.iter().enumerate() {
                        price_bytes[i] = *byte;
                    }

                    for (i, byte) in volume_bytes_vec.iter().enumerate() {
                        volume_bytes[i] = *byte;
                    }

                    for (i, byte) in access_key_bytes_vec.iter().enumerate() {
                        access_key_bytes[i] = *byte;
                    }

                    for (i, byte) in hash_bytes_vec.iter().enumerate() {
                        hash_bytes[i] = *byte;
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

                    //   let hash = hash_three_values(order.s.p, order.s.v, order.s.alpha).await;

                    let hash_value = Fq::from_bytes(&hash_bytes).unwrap();

                    let commitment = Commitment {
                        public: order.t.clone(),
                        private: hash_value,
                    };

                    let data = Data {
                        pubkey: U256::from_str_hex(pubkey.as_str()).unwrap(), // example pubkey, replace with actual -- TODO
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
                        BigUint::from_bytes_le(&commitment.private.to_bytes()).to_str_radix(16);


                    /*let signature: Signature = enclave_private_key.sign(&eth_message(hash_str.to_string())).unwrap();

                    let r = signature.r;
                    let s = signature.s;
                    let v = signature.v;
                    let mut combined = Vec::new();
combined.extend(&r);
combined.extend(&s);
combined.extend(&[v]); */


// let signature_hex = format!("0x{}", hex::encode(combined));
                    
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
                            "signatureValue": "yes"
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
                    let hash_str = json_msg["hash"].as_str().unwrap();
                    // Parse the strings into BigUint, assuming decimal format
                    let price = BigUint::parse_bytes(price_str.as_bytes(), 10).unwrap();
                    let volume = BigUint::parse_bytes(volume_str.as_bytes(), 10).unwrap();
                    let access_key = BigUint::parse_bytes(access_key_str.as_bytes(), 10).unwrap();
                    let hash = BigUint::parse_bytes(hash_str.as_bytes(), 16).unwrap();

                    let price_bytes_vec = price.to_bytes_le();
                    let volume_bytes_vec = volume.to_bytes_le();
                    let access_key_bytes_vec = access_key.to_bytes_le();
                    let hash_bytes_vec = hash.to_bytes_le();
                    // Convert BigUint to [u8; 32] in little-endian format
                    let mut price_bytes = [0u8; 32];
                    let mut volume_bytes = [0u8; 32];
                    let mut access_key_bytes = [0u8; 32];
                    let mut hash_bytes = [0u8; 32];
                    for (i, byte) in price_bytes_vec.iter().enumerate() {
                        price_bytes[i] = *byte;
                    }

                    for (i, byte) in volume_bytes_vec.iter().enumerate() {
                        volume_bytes[i] = *byte;
                    }

                    for (i, byte) in access_key_bytes_vec.iter().enumerate() {
                        access_key_bytes[i] = *byte;
                    }

                    for (i, byte) in hash_bytes_vec.iter().enumerate() {
                        hash_bytes[i] = *byte;
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

                    // let hash = hash_three_values(order.s.p, order.s.v, order.s.alpha).await;

                    let commitment = Commitment {
                        public: order.t.clone(),
                        private: Fq::from_bytes(&hash_bytes).unwrap(),
                    };

                    let data = Data {
                        pubkey: U256::from_str_hex(&pubkey.as_str()).unwrap(), // example pubkey, replace with actual -- TODO
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
                            matches = Some(
                                match_bid(
                                    order.clone(),
                                    U256::from_str_hex(pubkey.as_str()).unwrap(),
                                    ask_tree.clone(),
                                )
                                .await
                                .unwrap(),
                            );
                        } else {
                            matches = None
                        }
                    } else {
                        match ask_tree.read().await.search_exact_order(data).await {
                            Some(_) => found = true,
                            None => found = false,
                        }

                        if found {
                            matches = match_ask(
                                order.clone(),
                                U256::from_str_hex(pubkey.as_str()).unwrap(),
                                bid_tree.clone(),
                            )
                            .await
                        } else {
                            matches = None
                        }
                    }
                    let mut json_array = serde_json::Value::Array(Vec::new());
                    match matches {
                        Some(matches) => {
                            for order in matches {
                                let hash = Fq::from_bytes(&hash_bytes).unwrap();
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
                } else if json_msg["action"] == "clearorderbook" {
                    clear_orderbook(&bid_tree).await;
                    clear_orderbook(&ask_tree).await;
                    sender
                        .send(Message::text("Orderbook cleared"))
                        .await
                        .unwrap();
                } else if json_msg["action"] == "openorders" {
                    let bid_orders = bid_tree
                        .write()
                        .await
                        .get_orders_by_pubkey(U256::from_str_hex(pubkey.as_str()).unwrap())
                        .await;
                    let ask_orders = ask_tree
                        .write()
                        .await
                        .get_orders_by_pubkey(U256::from_str_hex(pubkey.as_str()).unwrap())
                        .await;
                    println!("bid orders: {:?}", bid_orders);
                    println!("ask orders: {:?}", ask_orders);
                    let mut json_array = serde_json::Value::Array(Vec::new());
                    for order in bid_orders {
                        // let hash = Fq::from_bytes(&hash_bytes).unwrap();
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
                        });
                        json_array.as_array_mut().unwrap().push(order_json);
                    }

                    for order in ask_orders {
                        // let hash = Fq::from_bytes(&hash_bytes).unwrap();
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
                        });
                        json_array.as_array_mut().unwrap().push(order_json);
                    }

                    // Construct the JSON payload
                    let payload = json!({
                        "action": "openorders",
                        "data": {
                            "orders": json_array,
                        }
                    });

                    let message = Message::text(payload.to_string());
                    sender.send(message).await.unwrap();
                }
                else if json_msg["action"]=="fillorders"{
                    let side = json_msg["data"]["side"].as_str().unwrap();
                    let side_num = side.to_string().parse::<u64>().unwrap();
                    let hash_own_str = json_msg["data"]["hash_own"].as_str().unwrap();
                    let hash_own_bytes = BigUint::parse_bytes(hash_own_str.as_bytes(), 16).unwrap().to_bytes_le();
                    let mut hash_own_array = [0u8; 32];
                    for (i, byte) in hash_own_bytes.iter().enumerate() {
                        hash_own_array[i] = *byte;
                    }
                    let hash_own = Fq::from_bytes(&hash_own_array).unwrap();

                    let hash_matched = json_msg["data"]["hash_matched"].as_array().unwrap().iter().map(|x| {
                        let hash_str = x.as_str().unwrap();
                        let hash_bytes = BigUint::parse_bytes(hash_str.as_bytes(), 16).unwrap().to_bytes_le();
                        let mut hash_array = [0u8; 32];
                        for (i, byte) in hash_bytes.iter().enumerate() {
                            hash_array[i] = *byte;
                        }
                        Fq::from_bytes(&hash_array).unwrap()
                    }).collect::<Vec<Fq>>();

                    if side_num==0{
                        bid_tree.write().await.delete_hash(hash_own).await;
                        for hash in hash_matched{
                            ask_tree.write().await.delete_hash(hash).await;
                        }
                    }
                    else{
                        ask_tree.write().await.delete_hash(hash_own).await;
                        for hash in hash_matched{
                            bid_tree.write().await.delete_hash(hash).await;
                        }
                    }

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

pub async fn handle_request_challenge(state: Arc<AppState>) -> WebResult<impl Reply> {
    let challenge_id = generate_challenge_id(); // Implement this function to generate unique challenge IDs
    let challenge_timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut challenges = state.challenges.lock().unwrap();
    challenges.insert(challenge_id.clone(), challenge_timestamp);
    // Send the challenge to the client
    Ok(warp::reply::json(&challenge_id))
}

pub fn generate_challenge_id() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    let id = format!("0x{}", hex::encode(bytes));
    id
}

pub async fn handle_submit_response(
    state: Arc<AppState>,
    response: ClientResponse,
) -> WebResult<impl Reply> {
    let challenges = state.challenges.lock().unwrap();
    if let Some(challenge) = challenges.get(&response.challenge_id) {
        if current_timestamp() - challenge > 300 {
            // 5 minutes in seconds
            return Ok(warp::reply::json(&"Challenge timed out!"));
        }
        return match verify_signature(&response) {
            Ok(_) => {
                //let jwt = issue_jwt();
                Ok(warp::reply::json(&create_jwt(&response.pub_key).unwrap()))
            }
            Err(_) => Ok(warp::reply::json(&"Invalid signature")),
        };
    } else {
        return Ok(warp::reply::json(&"Challenge not found!"));
    }
}

fn create_jwt(pub_key: &str) -> Result<String, MyError> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(900))
        .expect("valid timestamp")
        .timestamp(); // valid for 15 minutes from issuance

    let claims = Claims {
        sub: pub_key.to_owned(),
        exp: expiration as usize,
    };

    // let a: &[u8] = b"hello";

    let header = Header::new(Algorithm::HS512);
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET))
        .map_err(|_| MyError::JWTTokenCreationError)
}

pub fn with_auth() -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    headers_cloned().and_then(authorize)
}

pub async fn authorize(headers: HeaderMap<HeaderValue>) -> WebResult<String> {
    match jwt_from_header(&headers) {
        Ok(jwt) => {
            let decoded = decode::<Claims>(
                &jwt,
                &DecodingKey::from_secret(JWT_SECRET),
                &Validation::new(Algorithm::HS512),
            )
            .map_err(|_| reject::custom(MyError::JWTTokenError))?;
            Ok(decoded.claims.sub)
        }
        Err(e) => return Err(reject::custom(e)),
    }
}

fn jwt_from_header(headers: &HeaderMap<HeaderValue>) -> Result<String, MyError> {
    let header = match headers.get(AUTHORIZATION) {
        Some(v) => v,
        None => return Err(MyError::NoAuthHeaderError),
    };
    let auth_header = match std::str::from_utf8(header.as_bytes()) {
        Ok(v) => v,
        Err(_) => return Err(MyError::NoAuthHeaderError),
    };
    if !auth_header.starts_with(BEARER) {
        return Err(MyError::InvalidAuthHeaderError);
    }
    Ok(auth_header.trim_start_matches(BEARER).to_owned())
}

fn verify_signature(client_response: &ClientResponse) -> Result<(), &'static str> {
    // Decode the hex-encoded signature, message, and public key
    let signature_bytes = hex::decode(strip_0x_prefix(&client_response.signature)).unwrap();
    let message_bytes = hex::decode(strip_0x_prefix(&client_response.challenge_id)).unwrap();
    let pub_key_bytes = hex::decode(strip_0x_prefix(&client_response.pub_key)).unwrap();

    // println!("pubkey: {:?}", &client_response.pub_key);
    // println!("signature: {:?}", &client_response.signature);
    // println!("challenge_id: {:?}", &client_response.challenge_id);

    // println!("pubkey_bytes: {:?}", pub_key_bytes);
    // println!("signature_bytes: {:?}", signature_bytes);
    // println!("message_bytes: {:?}", message_bytes);

    let message_bytes = eth_message(client_response.challenge_id.clone());

    let recovery_id = signature_bytes[64] as i32 - 27;

    let pubkey = recover(&message_bytes, &signature_bytes[..64], recovery_id);

    let pubkey = pubkey.unwrap();
    let pubkey = format!("{:02X?}", pubkey);
    let recovered_pub_key_bytes = hex::decode(strip_0x_prefix(&pubkey)).unwrap();

    println!("pubkey: {:?}", pubkey);

    if recovered_pub_key_bytes == pub_key_bytes {
        Ok(())
    } else {
        Err("Values are not equal")
    }
}

fn strip_0x_prefix(hex_str: &str) -> &str {
    if hex_str.starts_with("0x") {
        &hex_str[2..]
    } else {
        hex_str
    }
}

pub fn eth_message(message: String) -> [u8; 32] {
    keccak256(
        format!(
            "{}{}{}",
            "\x19Ethereum Signed Message:\n",
            message.len(),
            message
        )
        .as_bytes(),
    )
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::main]
async fn main() {
    // Read public and private keys from .env file
    // let clients = Clients::new(Mutex::new(HashMap::new()));
    let state = Arc::new(AppState {
        challenges: Mutex::new(HashMap::new()),
    });

    let state_req_challenge = state.clone();
    let state_sub_response = state.clone();

    let request_challenge = warp::post()
        .and(warp::path("request_challenge"))
        .and(warp::any().map(move || state_req_challenge.clone()))
        .and_then(handle_request_challenge);

    let submit_response = warp::post()
        .and(warp::path("submit_response"))
        .and(warp::any().map(move || state_sub_response.clone()))
        .and(warp::body::json())
        .and_then(handle_submit_response);

    let orderbook = Orderbook::<Fq> {
        bid_tree: Arc::new(RwLock::new(RBTree::new())),
        ask_tree: Arc::new(RwLock::new(RBTree::new())),
    };

    /*let file_path = Path::new("orders.txt");
    read_and_insert(
        &file_path,
        orderbook.bid_tree.clone(),
        orderbook.ask_tree.clone(),
    )
    .await; */

    // let safe_orderbook = SafeOrderbook::new(RwLock::new(orderbook));

    // let safe_orderbook = warp::any().map(move || safe_orderbook.clone());

    let bid_tree = warp::any().map(move || orderbook.bid_tree.clone());
    let ask_tree = warp::any().map(move || orderbook.ask_tree.clone());


    pretty_env_logger::init();

    /* let ws_with_auth = warp::path("ws_auth")
    .and(warp::ws())
    .and(with_auth())
    .map(|ws: warp::ws::Ws, pubkey: String| {
        ws.on_upgrade(move |socket| handle_success(socket, pubkey))
    }); */

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(bid_tree)
        .and(ask_tree)
        .and(with_auth())
        .map(|ws: warp::ws::Ws, bid_tree, ask_tree, pubkey| {
            ws.on_upgrade(move |socket| {
                handle_websocket_messages(socket, bid_tree, ask_tree, pubkey)
            })
        });
    // Then in your main function:

    /*let routes = warp::path("ws")
    .and(warp::ws())
    .and(warp::header::headers_cloned())
    .map(|ws: warp::ws::Ws, headers: warp::http::HeaderMap| {
        println!("{:?}", headers);
        ws.on_upgrade(|websocket| {
            // Handle the websocket connection here
            // For example, you can just echo back all received messages:
            let (tx, rx) = websocket.split();
            rx.forward(tx).map(|result| {
                if let Err(e) = result {
                    eprintln!("websocket error: {:?}", e);
                }
            })
        })
    }); */

    let routes = request_challenge.or(submit_response).or(ws_route);

    warp::serve(routes).run(([0, 0, 0, 0], 8000)).await;
}
