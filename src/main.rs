use chrono::prelude::*;
use ethers::core::types::Filter as EthersFilter;
use ethers::core::types::H160;
use ethers::core::types::H256;
use ethers::core::types::U256 as EthersU256;
use ethers::prelude::*;
use ethers::signers::LocalWallet;
use ethers::{
    core::{
        abi::AbiDecode,
        types::{Address, BlockNumber, ValueOrArray},
    },
    providers::{Middleware, Provider},
};
use ethers_providers::Ws;
use ethnum::U256;
use eyre::Ok as OkEyre;
use eyre::Result;
use futures_util::stream::StreamExt;
use futures_util::SinkExt;
use halo2curves::bn256::Fr as Fq;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use num_bigint::BigUint;
use rand::Rng;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio::time::Duration;
use unyfy_matching_engine::matching::*;
use unyfy_matching_engine::models::Orderbook;
use unyfy_matching_engine::models::RBTree;
use unyfy_matching_engine::models::*;
use unyfy_matching_engine::raw_order::*;
use unyfy_matching_engine::staging::*;
use warp::ws::Message;
use warp::ws::WebSocket;
use warp::Reply;
use warp::{
    filters::header::headers_cloned,
    http::header::{HeaderMap, HeaderValue, AUTHORIZATION},
    reject, Filter, Rejection,
};
use web3::signing::{keccak256, recover};

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

type WebResult<T> = std::result::Result<T, Rejection>;

async fn clear_orderbook<T: Ord + Debug + Copy>(tree: &Arc<RwLock<RBTree<T>>>) {
    let mut tree = tree.write().await;
    tree.root = None;
    tree.count = 0;
}

async fn handle_websocket_messages(
    websocket: WebSocket,
    bid_tree: Arc<RwLock<RBTree<Fq>>>,
    ask_tree: Arc<RwLock<RBTree<Fq>>>,
    pubkey: String,
    queue: Arc<RwLock<StagingQueue>>,
    curr_addr: Arc<RwLock<String>>,
) {
    let keys = fs::read_to_string("enclave_data.txt").unwrap();
    let split: Vec<&str> = keys.split_whitespace().collect();
    let private_key = split.get(0).ok_or("Private key not found").unwrap();
    let private_key = format!("0x{}", private_key);
    let public_address = split.get(1).ok_or("Private key not found").unwrap();

    // Create a wallet from the private key
    let wallet: LocalWallet = private_key.parse().unwrap();

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

                    let staging_order = StagingOrder {
                        pubkey: U256::from_str_hex(pubkey.as_str()).unwrap(),
                        order: order.clone(),
                        timestamp: SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as u32,
                    };

                    queue.write().await.add_order(staging_order, hash_value);

                    /*if side_num == 0 {
                        // bid_staging_queue.write()....
                        // listen for events
                        // if (event_is_listened) { bid_staging_queue.pop()}
                        // ^ this should be a separate endpoint call
                        bid_tree.write().await.insert(order.s.p, data).await;
                        bid_tree.read().await.print_inorder().await;
                    } else {
                        ask_tree.write().await.insert(order.s.p, data).await;
                        ask_tree.read().await.print_inorder().await;
                    } */

                    let side_return =
                        BigUint::from_bytes_le(&order.t.phi.to_bytes()).to_str_radix(10);
                    let commitment_return =
                        BigUint::from_bytes_le(&commitment.private.to_bytes()).to_str_radix(16);

                    // Your message to sign
                    let message = &commitment_return;

                    // Hash the message (Ethereum signed message format)
                    let hashed_message = eth_message(message.to_string());
                    // Sign the message
                    let signature = wallet.sign_hash(hashed_message.into()).unwrap().to_string();

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
                            "signatureValue": signature,
                            "enclavePublicAddress": public_address.to_string(),
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

                    let commitment = Commitment {
                        public: order.t.clone(),
                        private: Fq::from_bytes(&hash_bytes).unwrap(),
                    };

                    let data = Data {
                        pubkey: U256::from_str_hex(&pubkey.as_str()).unwrap(), // example pubkey, replace with actual -- TODO
                        raw_order: order.clone(),
                        raw_order_commitment: commitment.clone(),
                    };

                    let found: bool;

                    let matches: Option<Vec<(Fq, Order)>>;

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
                            for (matched_hash, matched) in matches {
                                let order_json = json!({
                                    "raw_order": {
                                        "t": {
                                            "phi": BigUint::from_bytes_le(&matched.t.phi.to_bytes()).to_str_radix(10),
                                            "chi": matched.t.chi,
                                            "d": matched.t.d,
                                        },
                                        "s": {
                                            "p": BigUint::from_bytes_le(&matched.s.p.to_bytes()).to_str_radix(10),
                                            "v": BigUint::from_bytes_le(&matched.s.v.to_bytes()).to_str_radix(10),
                                            "alpha": BigUint::from_bytes_le(&matched.s.alpha.to_bytes()).to_str_radix(16),
                                        },
                                    },
                                    "raw_order_commitment": {
                                        "public": {
                                            "phi": BigUint::from_bytes_le(&matched.t.phi.to_bytes()).to_str_radix(16),
                                         "chi": matched.t.chi,
                                            "d": matched.t.d,
                                        },
                                     "private": BigUint::from_bytes_le(&matched_hash.to_bytes()).to_str_radix(16),
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
                            "shielded": BigUint::from_bytes_le(&commitment.private.to_bytes()).to_str_radix(16),
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
                                    "alpha": BigUint::from_bytes_le(&order.s.alpha.to_bytes()).to_str_radix(16),
                                },
                            },
                        });
                        json_array.as_array_mut().unwrap().push(order_json);
                    }

                    for order in ask_orders {
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
                                    "alpha": BigUint::from_bytes_le(&order.s.alpha.to_bytes()).to_str_radix(16),
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
                } else if json_msg["action"] == "upgradelisteningcontract" {
                    let new_address = json_msg["data"]["newAddress"].as_str().unwrap();
                    *curr_addr.write().await = new_address.to_string();
                    let payload = json!({
                        "action": "upgradelisteningcontract",
                        "status": "success",
                        "newAddress": new_address,
                    });
                    let message = Message::text(payload.to_string());
                    sender.send(message).await.unwrap();
                }
            }
        }
    }
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
            Ok(_) => Ok(warp::reply::json(&create_jwt(&response.pub_key).unwrap())),
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
    let signature_bytes = hex::decode(strip_0x_prefix(&client_response.signature)).unwrap();
    let pub_key_bytes = hex::decode(strip_0x_prefix(&client_response.pub_key)).unwrap();

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
async fn main() -> Result<()> {
    abigen!(
        AdLib,
        r#"[
            event orderPlaced(address indexed pubaddr, uint256 indexed orderhash)
            event orderCancelled(address indexed pubaddr, uint256 indexed orderhash)
            event orderDelete(uint256 indexed orderhash)
            event orderFilled(address indexed pubaddr, uint256 indexed orderhash, uint256[] indexed filledorderhashes)
        ]"#,
    );

    let current_address = Arc::new(RwLock::new(
        "0x3C3EF8652c104f57acd42D077F060cf00cFc53B5".to_string(),
    ));
    let temp_address = Arc::new(RwLock::new(current_address.read().await.clone()));
    let client = Provider::<Ws>::connect("wss://ethereum-sepolia.publicnode.com").await?;
    let client = Arc::new(client);

    let staging_queue = Arc::new(RwLock::new(StagingQueue {
        stagingorders: HashMap::new(),
    }));

    let staging_queue_clone = staging_queue.clone();

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

    let bid_tree_main = orderbook.bid_tree.clone();
    let ask_tree_main = orderbook.ask_tree.clone();

    let current_address_clone = current_address.clone();

    let bid_tree = warp::any().map(move || orderbook.bid_tree.clone());
    let ask_tree = warp::any().map(move || orderbook.ask_tree.clone());
    let queue = warp::any().map(move || staging_queue_clone.clone());
    let curr_addr = warp::any().map(move || current_address.clone());
    pretty_env_logger::init();

    let placed_order_event =
        Contract::event_of_type::<OrderPlacedFilter>(client.clone()).from_block(4980382
        ).address(ValueOrArray::Value(("0x3C3EF8652c104f57acd42D077F060cf00cFc53B5".parse::<H160>().unwrap()).into()));

    let cancelled_order_event =
        Contract::event_of_type::<OrderCancelledFilter>(client.clone()).from_block(4980382
        ).address(ValueOrArray::Value(("0x3C3EF8652c104f57acd42D077F060cf00cFc53B5".parse::<H160>().unwrap()).into()));

    let deleted_order_event =
        Contract::event_of_type::<OrderDeleteFilter>(client.clone()).from_block(4980382
        ).address(ValueOrArray::Value(("0x3C3EF8652c104f57acd42D077F060cf00cFc53B5".parse::<H160>().unwrap()).into()));

    let placed_order_event = Arc::new(placed_order_event);
    let cancelled_order_event = Arc::new(cancelled_order_event);
    let deleted_order_event = Arc::new(deleted_order_event);

    let placed_order_event_clone = Arc::clone(&placed_order_event);
    let cancelled_order_event_clone = Arc::clone(&cancelled_order_event);
    let deleted_order_event_clone = Arc::clone(&deleted_order_event);

    let bid_tree_main_clone1 = bid_tree_main.clone();
    let ask_tree_main_clone1 = ask_tree_main.clone();
    tokio::spawn(async move {
        let mut placed_order_stream = placed_order_event_clone
            .subscribe_with_meta()
            .await
            .unwrap()
            .take(2);

        let mut cancelled_order_stream = cancelled_order_event_clone
            .subscribe_with_meta()
            .await
            .unwrap()
            .take(2);

        let mut deleted_order_stream = deleted_order_event_clone
            .subscribe_with_meta()
            .await
            .unwrap()
            .take(2);

        loop {
            tokio::select! {
                Some(Ok((log, _meta))) = placed_order_stream.next() => {
                    // Handle placed order event
                    println!("Placed order event: {:?}", log);
                    //   println!("The pub addr is: {:?}", log.pubaddr);
                     let mut addr_bytes = [0u8; 32];
                    addr_bytes[12..].copy_from_slice(log.pubaddr.as_bytes());
                    let mut addr_str = hex::encode(addr_bytes);
                    addr_str.insert_str(0, "0x");
                    // println!("The pub addr is: {:?}", addr_str);
                    let addr_u256 = U256::from_str_hex(addr_str.as_str()).unwrap();
                    //  println!("The pub addr is: {:?}", addr_u256);

                    let mut orderhash_bytes = [0u8; 32];
                    log.orderhash.to_little_endian(&mut orderhash_bytes);
                    let orderhash = Fq::from_bytes(&orderhash_bytes).unwrap();

                    println!("The orderhash is: {:?}", orderhash);

                    let staging_queue_read = staging_queue.read().await;
                    let order_option = staging_queue_read.stagingorders.get(&addr_u256);

                    let order_found_1 = match order_option {
                        Some(x) => x.get(&orderhash),
                        None => {
                            println!("No orders found for the given user");
                            continue;
                        }
                    };

                    match order_found_1 {
                        Some(x) => {
                            let data = Data {
                                pubkey: addr_u256,
                                raw_order: x.order.clone(),
                                raw_order_commitment: Commitment {
                                    public: x.order.t.clone(),
                                    private: orderhash,
                                },
                            };
                    
                            if x.order.t.phi == Fq::from(0u64) {
                                bid_tree_main_clone1.write().await.insert(x.order.s.p, data).await;
                                bid_tree_main_clone1.read().await.print_inorder().await;
                            } else {
                                ask_tree_main_clone1.write().await.insert(x.order.s.p, data).await;
                                ask_tree_main_clone1.read().await.print_inorder().await;
                            }
                        }
                        None => {
                            println!("Order not found in user_orders");
                            continue;
                        }
                    };

                    if let Some(user_orders) = staging_queue
                        .write()
                        .await
                        .stagingorders
                        .get_mut(&addr_u256)
                    {
                        if user_orders.contains_key(&orderhash) {
                            user_orders.remove(&orderhash);
                        } else {
                            println!("Order not found in user_orders");
                        }

                    
                        
                    } else {
                        // Handle the case where there are no orders for the given user
                        println!("No orders found for the given user");
                    }
                }
                Some(Ok((log, _meta))) = cancelled_order_stream.next() => {
                    // Handle cancelled order event
                    println!("{log:?}");

                    let mut orderhash_bytes = [0u8; 32];
                    log.orderhash.to_little_endian(&mut orderhash_bytes);
                    let orderhash = Fq::from_bytes(&orderhash_bytes).unwrap();

                    // Search for the orderhash in bid_tree_main's map and delete if found
                    if bid_tree_main_clone1.write().await.map.contains_key(&orderhash) {
                        bid_tree_main_clone1.write().await.delete_hash(orderhash).await;
                    } else if ask_tree_main_clone1.write().await.map.contains_key(&orderhash) {
                        ask_tree_main_clone1.write().await.delete_hash(orderhash).await;
                    } else {
                        println!("Order not found");
                    } 
                }
                Some(Ok((log, _meta))) = deleted_order_stream.next() => {
                    // Handle deleted order event
                    println!("Deleted order event: {:?}", log);
                    println!("{log:?}");

                    let mut orderhash_bytes = [0u8; 32];
                    log.orderhash.to_little_endian(&mut orderhash_bytes);
                    let orderhash = Fq::from_bytes(&orderhash_bytes).unwrap();

                    // Search for the orderhash in bid_tree_main's map and delete if found
                    if bid_tree_main_clone1.write().await.map.contains_key(&orderhash) {
                        bid_tree_main_clone1.write().await.delete_hash(orderhash).await;
                    }
                    // Search for the orderhash in ask_tree_main's map and delete if found
                    else if ask_tree_main_clone1.write().await.map.contains_key(&orderhash) {
                        ask_tree_main_clone1.write().await.delete_hash(orderhash).await;
                    }
                    // If the orderhash is not found in either tree, print a message
                    else {
                        println!("Order not found in either tree");
                    } 
                }
                else => {
                    break;
                }
            }
        }
    });

    let ws_route = warp::path("ws")
        .and(warp::ws())
        .and(bid_tree)
        .and(ask_tree)
        .and(with_auth())
        .and(queue)
        .and(curr_addr)
        .map(
            |ws: warp::ws::Ws, bid_tree, ask_tree, pubkey, queue, curr_addr| {
                ws.on_upgrade(move |socket| {
                    handle_websocket_messages(socket, bid_tree, ask_tree, pubkey, queue, curr_addr)
                })
            },
        );

    let routes = request_challenge.or(submit_response).or(ws_route);

    warp::serve(routes).run(([0, 0, 0, 0], 8000)).await;

    OkEyre(())
}
