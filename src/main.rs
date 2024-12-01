use const_hex::FromHex;
use kademlia::*;
use std::io;

const HELP: &str = r"help                            ..print help message
put <string key> <string value> ..store value at key
get <string key>                ..lookup value at key
======\/ lower level \/======
p <ip>:<port> <key>  ..pings the node
s <ip>:<port> <key>  ..sends store req to node
fn <ip>:<port> <key> ..sends find_node req to node
fv <ip>:<port> <key> ..sends find_value req to node
ln <key>             ..performs iterative node lookup
lv <string key>      ..performs iterative value lookup
";

fn main() {
    env_logger::init();

    let input = io::stdin();
    let mut buffer = String::new();
    input.read_line(&mut buffer).unwrap();
    let params = buffer.trim_end().split(' ').collect::<Vec<_>>();
    let bootstrap = if params.len() < 2 {
        None
    } else {
        Some(NodeInfo {
            id: Key::from_hex(params[1]).unwrap(),
            addr: String::from(params[0]),
            net_id: String::from("test_net"),
        })
    };
    let handle = Kademlia::start(
        String::from("test_net"),
        Key::random(),
        "127.0.0.1:0",
        bootstrap,
    );

    let mut dummy_info = NodeInfo {
        net_id: String::from("test_net"),
        addr: String::from("asdfasdf"),
        id: Key::random(),
    };

    loop {
        let mut buffer = String::new();
        if input.read_line(&mut buffer).is_err() {
            break;
        }
        let args = buffer.trim_end().split(' ').collect::<Vec<_>>();
        match args[0].as_ref() {
            "h" => {
                println!("{}", HELP)
            }
            "p" => {
                dummy_info.addr = String::from(args[1]);
                dummy_info.id = Key::from_hex(args[2]).unwrap();
                println!("{:?}", handle.ping(dummy_info.clone()));
            }
            "s" => {
                dummy_info.addr = String::from(args[1]);
                dummy_info.id = Key::from_hex(args[2]).unwrap();
                println!(
                    "{:?}",
                    handle.store(
                        dummy_info.clone(),
                        String::from(args[3]),
                        String::from(args[4])
                    )
                );
            }
            "fn" => {
                dummy_info.addr = String::from(args[1]);
                dummy_info.id = Key::from_hex(args[2]).unwrap();
                println!(
                    "{:?}",
                    handle.find_node(dummy_info.clone(), Key::from_hex(args[3]).unwrap())
                );
            }
            "fv" => {
                dummy_info.addr = String::from(args[1]);
                dummy_info.id = Key::from_hex(args[2]).unwrap();
                println!(
                    "{:?}",
                    handle.find_value(dummy_info.clone(), String::from(args[3]))
                );
            }
            "ln" => {
                println!("{:?}", handle.lookup_nodes(Key::from_hex(args[1]).unwrap()));
            }
            "lv" => {
                println!("{:?}", handle.lookup_value(String::from(args[1])));
            }
            "put" => {
                println!(
                    "{:?}",
                    handle.put(String::from(args[1]), String::from(args[2]))
                );
            }
            "get" => {
                println!("{:?}", handle.get(String::from(args[1])));
            }
            _ => {
                println!("no match");
            }
        }
    }
}
