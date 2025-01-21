use const_hex::FromHex;
use kademlia::*;
use std::{io, net::SocketAddr, str::FromStr};
use tracing::error;

const HELP: &str = r"
help               ..print help message
put <string value> ..store value at key
get                ..lookup value at key
======\/ lower level \/======
p <ip>:<port> <key>  ..pings the node
s <ip>:<port> <key>  ..sends store req to node
fn <ip>:<port> <key> ..sends find_node req to node
fv <ip>:<port> <key> ..sends find_value req to node
lv <string key>      ..performs iterative value lookup
";

// TODO: Rewrite it to be less ugly

#[tokio::main]
async fn main() {
    let subscriber = tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let input = io::stdin();
    let mut buffer = String::new();
    input.read_line(&mut buffer).unwrap();
    let params = buffer.trim_end().split(' ').collect::<Vec<_>>();

    let mut handle = KademliaNode::setup();
    if params.len() >= 2 {
        let nodes = vec![NodeInfo {
            id: DHTKey::from_hex(params[0]).unwrap(),
            addr: SocketAddr::from_str(params[1]).unwrap(),
        }];

        handle.bootstrap(nodes);
    }

    let handle = handle
        .address("127.0.0.1:0".parse().unwrap())
        .start()
        .await
        .unwrap();

    let mut dummy_info = NodeInfo {
        addr: SocketAddr::from_str("127.0.0.1:0").unwrap(),
        id: DHTKey::random(),
    };

    loop {
        let mut buffer = String::new();
        if input.read_line(&mut buffer).is_err() {
            break;
        }
        let args = buffer.trim_end().split(' ').collect::<Vec<_>>();
        match args[0] {
            "h" | "help" => {
                println!("{}", HELP)
            }
            "p" => {
                dummy_info.addr = SocketAddr::from_str(args[1]).unwrap();
                dummy_info.id = DHTKey::from_hex(args[2]).unwrap();
                println!("{:?}", handle.ping(&dummy_info, false).await);
            }
            "s" => {
                dummy_info.addr = SocketAddr::from_str(args[1]).unwrap();
                dummy_info.id = DHTKey::from_hex(args[2]).unwrap();
                println!("{:?}", handle.store(&dummy_info, args[3]).await);
            }
            "fn" => {
                dummy_info.addr = SocketAddr::from_str(args[1]).unwrap();
                dummy_info.id = DHTKey::from_hex(args[2]).unwrap();
                println!(
                    "{:?}",
                    handle
                        .find_node(&dummy_info, &DHTKey::from_hex(args[3]).unwrap())
                        .await
                );
            }
            "fv" => {
                dummy_info.addr = SocketAddr::from_str(args[1]).unwrap();
                dummy_info.id = DHTKey::from_hex(args[2]).unwrap();
                println!(
                    "{:?}",
                    handle
                        .find_value(&dummy_info, &DHTKey::hash(args[3].as_bytes()))
                        .await
                        .unwrap()
                );
            }
            "ln" => {
                println!(
                    "{:?}",
                    handle.lookup_nodes(&DHTKey::hash(args[1].as_bytes())).await
                );
            }
            "lv" => {
                println!(
                    "{:?}",
                    handle.lookup_value(&DHTKey::hash(args[1].as_bytes())).await
                );
            }
            "put" => {
                println!("{:?}", handle.put(args[1]).await);
            }
            "get" => match DHTKey::from_hex(args[1].as_bytes()) {
                Ok(key) => println!("{:?}", handle.get(&key).await),
                Err(e) => error!("can't get value by key: {}", e),
            },
            _ => {
                println!("no match");
            }
        }
    }
}
