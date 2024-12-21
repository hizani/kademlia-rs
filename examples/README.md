Running
=======

`cargo run --example node`

Once started, it will expect one line of input; the info for an existing node, formatted as follows:

    <IP>:<Port> <Key>

This is optional, and if you enter a blank line, the node will start up without bootstrapping.

At this point, you can enter some commands:

    help               ..print help message
    put <string value> ..store value at key
    get                ..lookup value at key
    ======\/ lower level \/======
    p <ip>:<port> <key>             ..pings the node
    s <ip>:<port> <node_key> <key>  ..sends store req to node
    fn <ip>:<port> <node_key>       ..sends find_node req to node
    fv <ip>:<port> <node_key> <key> ..sends find_value req to node
    lv <string key>                 ..performs iterative value lookup
    ln <string key>                 ..performs iterative node lookup

Note that there is a distinction between keys (32-length byte strings) and string keys (arbitrary strings).