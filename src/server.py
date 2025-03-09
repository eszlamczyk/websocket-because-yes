'''
HTTP server to listen on a port and respond
'''

import socket
import select

from ws_util import *

from websocket import WebSocket, WebSocketFrame

TCP_IP = '127.0.0.1'
TCP_PORT = 5006

BUFFER_SIZE = 1024 * 1024

WS_ENDPOINT = '/websocket'

DEFAULT_HTTP_RESPONSE = (
    b'''<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\r\n
<TITLE>200 OK</TITLE></HEAD><BODY>\r\n
<H1>200 OK</H1>\r\n
Welcome to the default.\r\n
</BODY></HTML>\r\n\r\n''')

# legacy: need fixing to multithreading per socket to remove need of select, then everything should work


def main():
    '''
    front-door TCP socket and listens for connections
    '''

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_socket.bind((TCP_IP, TCP_PORT))

    tcp_socket.listen(1)
    print(f"Listening on port: {TCP_PORT}")
    input_sockets = [tcp_socket]
    output_sockets = []
    _xlist = []

    ws_sockets = []

    while True:
        readable_sockets = select.select(
            input_sockets, output_sockets, _xlist, 5)[0]

        for ready_socket in readable_sockets:
            if (ready_socket.fileno() == -1):
                continue
            if ready_socket == tcp_socket:
                print('\n\n\nHandling main door socket')
                handle_new_connection(tcp_socket, input_sockets)
            elif ready_socket in ws_sockets:
                handle_websocket_message(ready_socket, input_sockets,
                                         ws_sockets)
            else:
                print('\n\n\nHandling regular socket read')
                handle_request(ready_socket, input_sockets, ws_sockets)


def handle_new_connection(main_door_socket: socket.socket, input_sockets: list[socket.socket]):
    client_socket, client_addr = main_door_socket.accept()
    print(f"New socket {client_socket.fileno()} from address: {client_addr}")
    input_sockets.append(client_socket)


def handle_websocket_message(client_socket, input_sockets, ws_sockets):

    data_in_bytes = client_socket.recv(BUFFER_SIZE)

    websocket = WebSocketFrame.frame_from_data(data_in_bytes)

    print(
        f"Recieved Websocket Message!\n\n{websocket}")


def handle_request(client_socket: socket.socket, input_sockets: list[socket.socket], ws_sockets: list[WebSocket]):

    print(
        f"Handling request from client socket: {client_socket.fileno()}")
    message = ''

    while True:
        data_in_bytes = client_socket.recv(BUFFER_SIZE)

        if len(data_in_bytes) == 0:
            close_socket(client_socket, input_sockets, ws_sockets)
            return

        message_segment = data_in_bytes.decode()
        message += message_segment

        if (len(message) > 4 and message_segment[-4:] == '\r\n\r\n'):
            break

    print('Received message:')
    print(message)

    method, target, http_version, headers_map = parse_request(message)

    print(f'method {method}, target {target}, http_version {http_version}')

    print('headers:')
    print(headers_map)

    if target == WS_ENDPOINT:
        print('request to ws endpoint')

        ws_socket = WebSocket.WebSocket_server(
            client_socket, method, http_version, headers_map)

        if ws_socket is not None:
            ws_sockets.append(ws_socket)
            return

    client_socket.send(b'HTTP/1.1 200 OK\r\n\r\n' + DEFAULT_HTTP_RESPONSE)
    close_socket(client_socket, input_sockets, ws_sockets)


def parse_request(request):
    headers_map = {}

    split_request = request.split('\r\n\r\n')[0].split('\r\n')
    [method, target, http_version] = split_request[0].split(' ')
    headers = split_request[1:]
    for header_entry in headers:
        [header, value] = header_entry.split(': ')
        headers_map[header.lower()] = value
    return method, target, http_version, headers_map


def close_socket(client_socket, input_sockets, ws_sockets):
    if client_socket in ws_sockets:
        ws_sockets.remove(client_socket)

    input_sockets.remove(client_socket)
    client_socket.close()


if __name__ == '__main__':
    main()
