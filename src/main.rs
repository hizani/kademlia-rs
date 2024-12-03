use const_hex::FromHex;
use kademlia::*;
use log::error;
use std::{io, net::SocketAddr, str::FromStr};

const HELP: &str = r"
help               ..print help message
put <string value> ..store value at key
get                ..lookup value at key
======\/ lower level \/======
p <ip>:<port> <key>  ..pings the node
s <ip>:<port> <key>  ..sends store req to node
fn <ip>:<port> <key> ..sends find_node req to node
fv <ip>:<port> <key> ..sends find_value req to node
ln <key>             ..performs iterative node lookup
lv <string key>      ..performs iterative value lookup
";

fn main() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let input = io::stdin();
    let mut buffer = String::new();
    input.read_line(&mut buffer).unwrap();
    let params = buffer.trim_end().split(' ').collect::<Vec<_>>();
    let bootstrap = if params.len() < 2 {
        None
    } else {
        Some(NodeInfo {
            id: Key::from_hex(params[1]).unwrap(),
            addr: SocketAddr::from_str(params[0]).unwrap(),
            net_id: String::from("test_net"),
        })
    };
    let handle = Kademlia::start(
        String::from("test_net"),
        Key::new(),
        SocketAddr::from_str("127.0.0.1:0").unwrap(),
        bootstrap,
    );

    let mut dummy_info = NodeInfo {
        net_id: String::from("test_net"),
        addr: SocketAddr::from_str("127.0.0.1:0").unwrap(),
        id: Key::new(),
    };

    loop {
        let mut buffer = String::new();
        if input.read_line(&mut buffer).is_err() {
            break;
        }
        let args = buffer.trim_end().split(' ').collect::<Vec<_>>();
        match args[0].as_ref() {
            "h" | "help" => {
                println!("{}", HELP)
            }
            "p" => {
                dummy_info.addr = SocketAddr::from_str(args[1]).unwrap();
                dummy_info.id = Key::from_hex(args[2]).unwrap();
                println!("{:?}", handle.ping(dummy_info.clone()));
            }
            "s" => {
                dummy_info.addr = SocketAddr::from_str(args[1]).unwrap();
                dummy_info.id = Key::from_hex(args[2]).unwrap();
                println!(
                    "{:?}",
                    handle.store(dummy_info.clone(), &Key::hash(args[3].as_bytes()), args[4])
                );
            }
            "fn" => {
                dummy_info.addr = SocketAddr::from_str(args[1]).unwrap();
                dummy_info.id = Key::from_hex(args[2]).unwrap();
                println!(
                    "{:?}",
                    handle.find_node(dummy_info.clone(), &Key::from_hex(args[3]).unwrap())
                );
            }
            "fv" => {
                dummy_info.addr = SocketAddr::from_str(args[1]).unwrap();
                dummy_info.id = Key::from_hex(args[2]).unwrap();
                println!(
                    "{:?}",
                    handle.find_value(dummy_info.clone(), &Key::hash(args[3].as_bytes()))
                );
            }
            "ln" => {
                println!(
                    "{:?}",
                    handle.lookup_nodes(&Key::from_hex(args[1]).unwrap())
                );
            }
            "lv" => {
                println!("{:?}", handle.lookup_value(&Key::hash(args[1].as_bytes())));
            }
            "put" => {
                println!("{:?}", handle.put(args[1]));
            }
            "get" => match Key::from_hex(args[1].as_bytes().to_owned()) {
                Ok(key) => println!("{:?}", handle.get(&key)),
                Err(e) => error!("can't get value by key: {}", e),
            },
            _ => {
                println!("no match");
            }
        }
    }
}
