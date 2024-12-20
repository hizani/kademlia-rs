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
lv <string key>      ..performs iterative value lookup
";

// TODO: Move this from src to examples

fn main() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let input = io::stdin();
    let mut buffer = String::new();
    input.read_line(&mut buffer).unwrap();
    let params = buffer.trim_end().split(' ').collect::<Vec<_>>();

    let mut handle = Kademlia::new();
    if params.len() >= 2 {
        let nodes = vec![NodeInfo {
            id: Key::from_hex(params[1]).unwrap(),
            addr: SocketAddr::from_str(params[0]).unwrap(),
        }];

        handle.bootstrap(nodes);
    }

    let handle = handle
        .address("127.0.0.1".parse().unwrap())
        .start()
        .unwrap();

    let mut dummy_info = NodeInfo {
        addr: SocketAddr::from_str("127.0.0.1:0").unwrap(),
        id: Key::random(),
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
                println!("{:?}", handle.store(dummy_info.clone(), args[3]));
            }
            "fn" => {
                dummy_info.addr = SocketAddr::from_str(args[1]).unwrap();
                dummy_info.id = Key::from_hex(args[2]).unwrap();
                println!(
                    "{:?}",
                    handle.find_node(dummy_info.clone(), Key::from_hex(args[3]).unwrap())
                );
            }
            "fv" => {
                dummy_info.addr = SocketAddr::from_str(args[1]).unwrap();
                dummy_info.id = Key::from_hex(args[2]).unwrap();
                println!(
                    "{:?}",
                    handle
                        .find_value(dummy_info.clone(), &Key::hash(args[3].as_bytes()))
                        .unwrap()
                );
            }
            "ln" => {
                println!("{:?}", handle.lookup_nodes(&Key::hash(args[1].as_bytes())));
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
