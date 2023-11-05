
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




async fn handle_websocket_messages(websocket: WebSocket, tree: Arc<RwLock<RBTree<Fq>>>){
    
    todo!();
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

   // let safe_orderbook = SafeOrderbook::new(RwLock::new(orderbook));

    // let safe_orderbook = warp::any().map(move || safe_orderbook.clone());

    let bid_tree = warp::any().map(move || orderbook.bid_tree.clone());
    let ask_tree = warp::any().map(move || orderbook.ask_tree.clone());

    let order1 = Order {
        t: TransparentStructure {
            phi: Fq::from(0u32),     // 0 for bid
            chi: "0x0".to_string(),  // Token address for the target project
            d: "0x1".to_string(),    // Denomination token address, set to "0x1" for USDC or ETH
        },
        s: ShieldedStructure {
            p: Fq::from(1u32),       // Price, scaled by 10^9 with 10^7 precision
            v: Fq::from(1u32),       // Volume, scaled by 10^9
            alpha: Fq::from(1u32),   // Access key, randomly sampled from Fq
        },
    };
    

        pretty_env_logger::init();
        
        let routes = warp::path("ws")
        .and(warp::ws())
        .and(bid_tree)
        .map(|ws: warp::ws::Ws, bid_tree| ws.on_upgrade(move |socket| handle_websocket_messages(socket, bid_tree)));
        // Then in your main function:

}

