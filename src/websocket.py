import numpy as np
import socket
import logging


class WebSocketFrame:

    MAX_OUTPUT_STRING_LENGTH = 50

    def __init__(self,
                 fin=True,
                 RSV1=False,
                 RSV2=False,
                 RSV3=False,
                 opcode=0,
                 mask=False,
                 payload_length=0,
                 masking_key=None,
                 payload_data=None):
        self.fin = fin
        self.RSV1 = RSV1
        self.RSV2 = RSV2
        self.RSV3 = RSV3
        self.opcode = opcode
        self.mask = mask
        self.payload_length = payload_length
        self.masking_key = masking_key if masking_key is not None else []  # arr of bytes
        # data IS NOT stored as masked
        self.payload_data = bytes(
            payload_data) if payload_data is not None else bytes()

    @classmethod
    def frame_from_data(cls, data_in_bytes):
        frame = cls()
        frame.__parse_flags(data_in_bytes)
        frame.__parse_length(data_in_bytes)
        frame.__parse_mask(data_in_bytes)
        frame.__parse_payload(data_in_bytes)
        return frame

    def __apply_masking(self, data):
        decoded_data = []
        if self.mask:
            for byte, data in enumerate(data):
                decoded_data.append(data ^ self.masking_key[byte % 4])
            payload_data = bytes(decoded_data)
        else:
            payload_data = bytes(data)

        return payload_data

    def __create_bool_from_byte_and_mask(self, byte, mask):
        return (byte & mask) == mask

    def __parse_flags(self, data_in_bytes):
        first_byte = data_in_bytes[0]

        self.fin = self.__create_bool_from_byte_and_mask(
            first_byte, 0b10000000)

        self.RSV1 = self.__create_bool_from_byte_and_mask(
            first_byte, 0b01000000)

        self.RSV2 = self.__create_bool_from_byte_and_mask(
            first_byte, 0b00100000)

        self.RSV3 = self.__create_bool_from_byte_and_mask(
            first_byte, 0b00010000)

        self.opcode = first_byte & 0b00001111

    def __parse_length(self, data_in_bytes):
        second_byte = data_in_bytes[1]

        payload_length = second_byte & 0b01111111

        masking_key_start = 2

        if payload_length == 126:
            masking_key_start = 4
            payload_length = int.from_bytes(data_in_bytes[2:4], 'big')

        elif payload_length == 127:
            masking_key_start = 10
            payload_length = int.from_bytes(data_in_bytes[2:10], 'big')

        self.masking_key_start = masking_key_start
        self.payload_length = payload_length

    def __parse_mask(self, data_in_bytes):

        self.mask = self.__create_bool_from_byte_and_mask(
            data_in_bytes[1], 0b10000000)

        self.masking_key = []
        if self.mask:
            # better to keep in bytes
            self.masking_key = data_in_bytes[self.masking_key_start: self.masking_key_start+4]
            self.data_start = self.masking_key_start + 4
        else:
            self.data_start = self.masking_key_start

    def __parse_payload(self, data_in_bytes):
        if self.payload_length == 0:
            self.payload_data = b''
            return

        self.payload_data = self.__apply_masking(
            data_in_bytes[self.data_start:])

    def parse_payload_acording_to_opcode(self):
        if self.opcode == 1:
            return self.payload_data.decode("utf-8")
        if self.opcode == 2:
            return ' '.join(format(byte, '08b')
                            for byte in self.payload_data)

    def data_from_frame(self) -> list:
        result = [self.__first_byte_from_frame()]

        result = result + self.__payload_length_from_frame()

        result = result + self.masking_key

        result = result + list(self.__apply_masking(list(self.payload_data)))

        return result

    def __first_byte_from_frame(self):
        result = 1 if self.fin else 0
        result <<= 1
        result += 1 if self.RSV1 else 0
        result <<= 1
        result += 1 if self.RSV2 else 0
        result <<= 1
        result += 1 if self.RSV3 else 0
        result <<= 4
        result += self.opcode
        return result

    def __payload_length_from_frame(self):
        result = [1] if self.mask else [0]
        result[0] <<= 7

        if self.payload_length <= 125:
            result[0] += self.payload_length
        elif self.payload_length <= 65535:  # 16 unsigned integer limit
            result[0] += 126
            result += list(self.payload_length.to_bytes(2, 'big'))
        elif self.payload_length <= 18446744073709551615:  # 64 unsigned integer limit
            result[0] += 127
            result += list(self.payload_length.to_bytes(8, 'big'))
        else:
            raise ValueError("payload lenght is too large for one frame!")

        return result

    def __repr__(self):
        result = "Web Socket Frame:\n"
        result += f"fin = {self.fin}, RSV1 = {self.RSV1}, RSV2 = {self.RSV2}, RSV3 = {self.RSV3}\n"
        result += f"oppcode = {self.opcode}, meaning this is a {self.__decode_opcode()}\n"
        result += f"Mask bit is {self.mask}"
        if self.mask:
            result += f" while masking key is {''.join(format(byte, '0X') for byte in self.masking_key)}\n"
        else:
            result += "\n"
        result += f"Data length is {self.payload_length}\n"
        result += f"Data is {self.__truncate_string(''.join(format(byte, '0X') for byte in self.payload_data))}\n"
        result += f"meaing: {self.__truncate_string(self.parse_payload_acording_to_opcode())}"

        return result

    def __decode_opcode(self):
        match self.opcode:
            case 0: return "continuation frame"
            case 1: return "text frame"
            case 2: return "binary frame"
            case 3 | 4 | 5 | 6 | 7: return "reserved (non-control frame)"
            case 8: return "connection close"
            case 9: return "ping"
            case 10: return "pong"
            case 11 | 12 | 13 | 14 | 15: return "reserved (control frame)"
            case _: return "unknown opcode (invalid)"

    def __truncate_string(self, s):
        return s[:self.MAX_OUTPUT_STRING_LENGTH] + "..." if len(s) > self.MAX_OUTPUT_STRING_LENGTH else s

    def __eq__(self, other):
        if isinstance(other, WebSocketFrame):
            return (
                self.fin == other.fin and
                self.RSV1 == other.RSV1 and
                self.RSV2 == other.RSV2 and
                self.RSV3 == other.RSV3 and
                self.opcode == other.opcode and
                self.mask == other.mask and
                self.payload_length == other.payload_length and
                self.masking_key == other.masking_key and
                self.payload_data == other.payload_data
            )
        if isinstance(other, list):
            try:
                return WebSocketFrame.frame_from_data(other) == self
            except Exception:
                return False
        return False


# LEGACY CODE - toto: fix it and implement recieve message and send message
class WebSocket:

    STATE_ESTABLISHING = 0
    STATE_OPEN = 1
    STATE_CLOSING = 2
    STATE_CLOSED = 3

    def __init__(self,
                 base_socket: socket.socket,
                 buffer_size: int = 1024 * 1024,
                 is_server: bool = False,
                 server_logging_file="logs/server_logs.log"):
        self.base_socket = base_socket
        self.buffer_size = buffer_size
        self.state = self.STATE_OPEN
        self.is_server = is_server
        if is_server:
            logger = logging.getLogger("server_logger")
            logger.setLevel(logging.DEBUG)

            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)

            file_handler = logging.FileHandler(server_logging_file)
            file_handler.setLevel(logging.DEBUG)

            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)

            logger.addHandler(console_handler)
            logger.addHandler(file_handler)

            logger.debug("Starting new websocket instance for the server!")

            self.logger = logger

    def __catch_protocol_error(function):
        def decorated_function(self, *arg, **kw):
            try:
                function(self, *arg, **kw)
            except Exception as e:
                # protocol error
                self.__fail_websocket_connection(1002, e)
        return decorated_function

    @__catch_protocol_error
    def send_data(self, data_in_bytes, is_mask, opcode, max_fragment_size=1024, RSV=(False, False, False)):
        if self.state == self.STATE_CLOSING or self.state == self.STATE_CLOSED:
            # don't do anything for now
            return
        total_length = len(data_in_bytes)
        start = 0
        first = True
        masking_key = None

        if opcode >= 8:
            '''
            All control frames MUST have a payload length of 125 bytes or less
            and MUST NOT be fragmented.
            '''
            if total_length > 125:
                if self.is_server:
                    self.logger.error(f"While trying to send controll frame of opcode {opcode} " +
                                      f"got payload_lenght longer than 125 ({total_length}), which is prohibited")
                    return

            if is_mask or not self.is_server:
                masking_key = np.random.randint(0, 255, 4)

            frame = WebSocketFrame(True,
                                   RSV[0],
                                   RSV[1],
                                   RSV[2],
                                   current_opcode,
                                   is_mask,
                                   total_length,
                                   masking_key,
                                   data_in_bytes)

            self.base_socket.send(frame.data_from_frame())
            return

        while start < total_length:
            if is_mask or not self.is_server:
                masking_key = np.random.randint(0, 255, 4)

            end = min(start + max_fragment_size, total_length)
            fragment = data_in_bytes[start:end]
            is_last = end == total_length

            current_opcode = opcode if first else 0x0

            frame = WebSocketFrame(is_last,
                                   RSV[0],
                                   RSV[1],
                                   RSV[2],
                                   current_opcode,
                                   is_mask,
                                   end - start + 1,
                                   masking_key,
                                   fragment)

            self.base_socket.send(frame.data_from_frame())

            first = False
            start = end

    def recieve_message(self):
        full_data = []
        first_frame = True
        dummy_frame = WebSocketFrame()
        while True:
            data_in_bytes = self.base_socket.recv(self.buffer_size)
            frame = WebSocketFrame.frame_from_data(data_in_bytes)
            if first_frame:
                first_frame = False
                dummy_frame.opcode = frame.opcode
                dummy_frame.payload_data = frame.payload_data
            full_data += frame.payload_data
            if frame.fin:
                break

        return self.__process_frame_acording_to_opcode(frame, full_data)

    @__catch_protocol_error
    def __process_frame_acording_to_opcode(self, dummy_frame: WebSocketFrame, data_in_bytes):
        match dummy_frame.opcode:
            case 0x8:
                return self.__handle_receive_close(dummy_frame)
            case 0x9:
                return self.__handle_receive_ping(dummy_frame)
            case 0xA:
                return self.__handle_receive_pong(dummy_frame)

            case 0x1:
                return self.__handle_receive_text(data_in_bytes)

            case 0x2:
                return self.__handle_receive_binary(data_in_bytes)

            case _:
                raise ValueError("undefined opcode")

    def __handle_receive_close(self, frame: WebSocketFrame):
        status_code = int.from_bytes(frame.payload_data[:2], 'big')

        print(f"WebSocket recieved close frame\nStatus code: {status_code}")

        if frame.payload_length > 2:
            reason = frame.payload_data[2:].decode("utf-8")
        else:
            reason = ""

        if self.state == self.STATE_CLOSING:
            self.state = self.STATE_CLOSED
        elif self.state == self.STATE_OPEN:
            self.state = self.STATE_CLOSING
            response_frame = WebSocketFrame(True,
                                            False,
                                            False,
                                            False,
                                            0x8,
                                            False,
                                            2,
                                            None,
                                            frame.payload_data[:2])
            self.base_socket.send(response_frame.data_from_frame())
            self.state = self.STATE_CLOSED
        else:
            '''
            If a client and server both send a Close message at the same time,
            both endpoints will have sent and received a Close message and should
            consider the WebSocket connection closed and close the underlying TCP
            connection.
            '''
            self.__clean_closure_socket()

        '''
        After both sending and receiving a Close message, an endpoint
        considers the WebSocket connection closed and MUST close the
        underlying TCP connection.  The server MUST close the underlying TCP
        connection immediately; the client SHOULD wait for the server to
        close the connection but MAY close the connection at any time after
        sending and receiving a Close message, e.g., if it has not received a
        TCP Close from the server in a reasonable time period.
        '''
        if self.is_server:
            self.__clean_closure_socket()

        return reason

    def __handle_receive_ping(self, frame: WebSocketFrame):
        self.send_data(
            frame.payload_data, not self.is_server, 0xA
        )
        return f"Received Ping with data: {frame.payload_data}"

    def __handle_receive_pong(self, frame: WebSocketFrame):
        return f"Received Pong with data: {frame.payload_data}"

    @__catch_protocol_error
    def __handle_receive_text(self, data_in_bytes):
        return data_in_bytes.decode("utf-8")

    def __handle_receive_binary(self, data_in_bytes):
        return data_in_bytes

    def force_close(self):
        self.state = self.STATE_CLOSED
        self.base_socket.close()

    def start_closing_handshake(self, code: int = 1000, reason: str = ""):
        self.state = self.STATE_CLOSING

        close_frame = WebSocketFrame(
            opcode=0x8,
            mask=not self.is_server,
            masking_key=np.random.randint(0, 255, 4),
            payload_length=2 + len(reason),
            payload_data=list(code.to_bytes(2, 'big')) +
            list(reason.encode("utf-8"))
        )

        self.base_socket.send(close_frame.data_from_frame())

    def __clean_closure_socket(self):
        self.base_socket.shutdown(socket.SHUT_WR)

        while self.base_socket.recv(self.buffer_size) != 0:
            continue

        self.base_socket.close()

    def __fail_websocket_connection(self, code: int, reason: str):
        if self.state == self.STATE_ESTABLISHING:
            if self.is_server:
                '''
                [...] and SHOULD log the problem
                '''
                self.logger.error(
                    f"Failed to establish WebSocket Connection! Reason: {reason}")
                self.state = self.STATE_CLOSED
                self.__clean_closure_socket()
            else:
                '''
                [...] and MAY report the problem to the user (which would be 
                especially useful for developers) in an appropriate manner.
                '''
                print(
                    f"Failed to establish WebSocket Connection! Reason: {reason}")
                self.state = self.STATE_CLOSED
                self.__clean_closure_socket()
        else:
            self.start_closing_handshake(code, reason)
