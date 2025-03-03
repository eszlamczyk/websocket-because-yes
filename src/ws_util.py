'''
No idea how to better name this :p
'''
import hashlib
import base64


def is_valid_ws_handshake_request(method, http_version, headers_map):
    '''
    2. The method of the request MUST be GET, and the HTTP version MUST
        be at least 1.1.
    '''

    is_get = method == 'GET'

    http_version_number = float(http_version.split('/')[1])

    is_good_version = http_version_number >= 1.1

    '''
    4.   The request MUST contain a |Host| header field whose value
        contains /host/ plus optionally ":" followed by /port/ (when not
        using the default port).
    '''

    has_good_host = 'host' in headers_map

    '''
    5.   The request MUST contain an |Upgrade| header field whose value
        MUST include the "websocket" keyword.
    '''

    includes_upgrade = 'upgrade' in headers_map and 'websocket' in headers_map.get(
        'upgrade')

    '''   
    6.   The request MUST contain a |Connection| header field whose value
        MUST include the "Upgrade" token.
    '''

    includes_connection = 'connection' in headers_map and 'Upgrade' in headers_map.get(
        'connection')

    '''
    7.   The request MUST include a header field with the name
        |Sec-WebSocket-Key|.  The value of this header field MUST be a
        nonce consisting of a randomly selected 16-byte value that has
        been base64-encoded.  The nonce
        MUST be selected randomly for each connection.
    '''
    includes_websocket_key = 'sec-websocket-key' in headers_map

    '''
    9.   The request MUST include a header field with the name
        |Sec-WebSocket-Version|.  The value of this header field MUST be 13.
    '''

    includes_websocket_version = (
        'sec-websocket-version' in headers_map
        and headers_map.get('sec-websocket-version') == '13')

    return (is_get
            and is_good_version
            and has_good_host
            and includes_upgrade
            and includes_connection
            and includes_websocket_key
            and includes_websocket_version)


def generate_sec_websocket_accept(sec_websocket_key):

    MAGIC_WEBSOCKET_UUID_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

    combined = sec_websocket_key + MAGIC_WEBSOCKET_UUID_STRING
    hashed_combined_string = hashlib.sha1(combined.encode())
    encoded = base64.b64encode(hashed_combined_string.digest())
    return encoded
