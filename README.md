# websocket-because-yes


This repository contains implementation of [The WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455#section-5.2).

### Necesarry liblaries:

Only numpy :) *(tested on 1.26.4)*

## This repository contains: 
- Basic server that listens on 127.0.0.1:5006 and can recievie data via WebSocket
- WebSocket class (that currently can recieve non-fragmented messages)

## Usage:

### Demonstration:

Run `server.py` file:

```txt
python3 -m src.server
```

From (for example) console in web browser connect to the server:

```js
const socket = new WebSocket("ws://localhost:5006/websocket");
```

Try sending messages to the server:
```js
socket.send('test');
...
socket.send(125);
```

The WebSocket also correctly interprets binary data:
```js
socket.send(new Uint8Array([72, 101, 108, 108, 111]));
```

The server *very robustly* logs connections and recieved messages :)

### Tests:

Tests are implemented with `unittest`, to start them:

```sh
python3 -m unittest discover test -p "test_*.py"
```