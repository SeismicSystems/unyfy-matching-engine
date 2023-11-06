
use tokio::sync::mpsc;
use warp::ws::{Message};
use warp::Rejection;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use unyfy_matching_engine::models::Orderbook;
use futures_util::stream::StreamExt;
use futures_util::FutureExt;
use futures_util::TryFutureExt;
use warp::*;
use tokio::sync::RwLock;
use unyfy_matching_engine::models::RBTree;
use ark_bn254::Fr as Fq;
use unyfy_matching_engine::raw_order::*;
use unyfy_matching_engine::matching::*;
use warp::ws::WebSocket;
use unyfy_matching_engine::models::*;
use sha2::{Sha256, Digest};
use ethnum::U256;
use rand::Rng;
use std::path::Path;
use std::io::BufReader;
use std::io::BufRead;
use std::fs::File;
use std::error::Error;


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


async fn read_and_insert(file_path: &Path, bid_tree: Arc<RwLock<RBTree<Fq>>>, ask_tree: Arc<RwLock<RBTree<Fq>>>) {
    let file = File::open(file_path).expect("cannot open file");
    let reader = BufReader::new(file);
    
    for line in reader.lines() {
        let line = line.expect("could not read line");
        let order_data: Vec<&str> = line.split(',').collect();

        if order_data.len() != 6 {
            continue; // or handle the error
        }


        let pubkey = U256::from_str_hex(&format!("0x{}", order_data[0])).expect("invalid pubkey");
        let phi_value: u8 = order_data[1].parse().expect("invalid phi value");
        let chi = order_data[2].to_string();
        let d = "0x1".to_string();
        let p_value: u128 = order_data[4].parse().expect("invalid price");
        let v_value: u128 = order_data[5].parse().expect("invalid volume");
        let alpha_value = rand::thread_rng().gen::<u128>();
        // Assuming conversion function u128_to_fq is implemented for converting u128 to Fq
        let p = Fq::from(p_value);
        let v = Fq::from(v_value);
        let alpha = Fq::from(rand::thread_rng().gen::<u128>());
        let phi = Fq::from(phi_value);
        let raw_order_commitment = hash_three_values(p_value, v_value, alpha_value).await;
        let order_commitment = Fq::from(raw_order_commitment);

        let order = Order {
            t: TransparentStructure { phi, chi, d },
            s: ShieldedStructure { p, v, alpha },
        };

        let commitment = Commitment {
            public: order.t.clone(),
            private: order_commitment,
        };

        let data = Data { pubkey, raw_order: order, raw_order_commitment: commitment };

        match phi_value {
            0 => {
                let mut bid_tree_write = bid_tree.write().await;
                bid_tree_write.insert(p, data).await;
            },
            1 => {
                let mut ask_tree_write = ask_tree.write().await;
                ask_tree_write.insert(p, data).await;
            },
            _ => eprintln!("Invalid phi value: {}", phi),
        }
    }
}


async fn handle_websocket_messages(websocket: WebSocket, bid_tree: Arc<RwLock<RBTree<Fq>>>, ask_tree: Arc<RwLock<RBTree<Fq>>>){
    
    let order1 = Order {
        t: TransparentStructure {
            phi: Fq::from(1u128),     // 0 for bid
            chi: "92bf259f558808106e4840e2642352b156a31bc41e5b4283df2937278f0a7a65".to_string(),  // Token address for the target project
            d: "0x1".to_string(),    // Denomination token address, set to "0x1" for USDC or ETH
        },
        s: ShieldedStructure {
            p: Fq::from(100931421600u128),       // Price, scaled by 10^9 with 10^7 precision
            v: Fq::from(1000000000u128),       // Volume, scaled by 10^9
            alpha: Fq::from(1u128),   // Access key, randomly sampled from Fq
        },
    };

    let hash = hash_three_values(1, 1, 1).await;

    let order_1_commitment =  Commitment{
        public: order1.t.clone(),
        private: Fq::from(hash),
    };

    let data = Data {
        pubkey: U256::from_str_hex("0x0").unwrap(),
        raw_order: order1.clone(),
        raw_order_commitment: order_1_commitment.clone(),
    };
    

    ask_tree.write().await.insert(order1.s.p, data).await;

    ask_tree.read().await.print_inorder().await;

    let mut matches: Vec<Order> = Vec::new();

    matches = match_ask::<Fq>(order1.clone(), bid_tree.clone()).await.unwrap();

    for order_match in &matches {
        println!("{:?}", order_match);
    }


    /*let (mut tx, mut rx) = websocket.split();

    while let Some(result) = rx.next().await {
        match result {
            Ok(msg) => {
                if msg.is_text() {
                    let text = msg.to_str().unwrap();
                    if text == "insert 1" {
                        // match_bid(order, orderbook).await;
                    }
                    println!("Received message: {}", text);
                    // Here you can parse `text` as a JSON object and handle it accordingly
                }
            }
            Err(e) => eprintln!("Error receiving message: {:?}", e),
        }
    } */
}


async fn hash_three_values(a: u128, b: u128, c: u128) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(a.to_be_bytes());
    hasher.update(b.to_be_bytes());
    hasher.update(c.to_be_bytes());
    let hash = hasher.finalize();
    let array: [u8; 16] = hash[0..16].try_into().unwrap();
    u128::from_be_bytes(array)
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
    read_and_insert(&file_path, orderbook.bid_tree.clone(), orderbook.ask_tree.clone()).await;

   // let safe_orderbook = SafeOrderbook::new(RwLock::new(orderbook));

    // let safe_orderbook = warp::any().map(move || safe_orderbook.clone());

    let bid_tree = warp::any().map(move || orderbook.bid_tree.clone());
    let ask_tree = warp::any().map(move || orderbook.ask_tree.clone());

    

        pretty_env_logger::init();
        
        let routes = warp::path("ws")
        .and(warp::ws())
        .and(bid_tree)
        .and(ask_tree)
        .map(|ws: warp::ws::Ws, bid_tree, ask_tree| ws.on_upgrade(move |socket| handle_websocket_messages(socket, bid_tree, ask_tree)));
        // Then in your main function:

        warp::serve(routes).run(([127, 0, 0, 1], 8000)).await;

}

