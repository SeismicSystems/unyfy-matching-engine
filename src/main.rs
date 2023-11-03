use tokio::sync::mpsc;
use warp::ws::Message;

pub struct Client {
    pub user_id: u32, // pubkey of the client
    pub topics: Vec<String>,
    pub sender: Option<mpsc::UnboundedSender<std::result::Result<Message, warp::Error>>>,
}

fn main() {
    println!("Hello, world!");
}
