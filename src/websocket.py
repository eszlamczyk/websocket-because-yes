import numpy as np


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

    def __init__(self):
        pass

    def create_frames(self, data_in_bytes, is_mask, opcode, max_fragment_size=1024):
        frames = []
        total_length = len(data_in_bytes)
        start = 0
        first = True

        while start < total_length:
            end = min(start + max_fragment_size, total_length)
            fragment = data_in_bytes[start:end]
            is_last = end == total_length

            current_opcode = opcode if first else 0x0

            frame = self.create_frame(
                fragment, is_mask, current_opcode, is_last)
            frames.append(frame)

            first = False
            start = end

        return frames

    def create_frame(self, data_in_bytes, is_mask, opcode, is_last):

        self.is_last = is_last
        self.opcode = opcode
        self.is_mask = is_mask

        frame = []

        frame.append(self._create_first_byte())

        frame + self._create_payload_length_bytes(data_in_bytes)

        if is_mask:
            masking_key = np.random.randint(0, 2**32)
            byte_array = masking_key.to_bytes(4, byteorder='big')
            frame + byte_array

        if is_mask:
            data_in_bytes = self._parse_payload(data_in_bytes)

        frame += data_in_bytes

        return (frame)

    def _create_first_byte(self):
        result = 128 if self.is_last else 0
        result += self.opcode

    def _create_payload_length_bytes(self, data_in_bytes):
        frame_part = []
        if self.is_mask:
            first_byte = 128
        else:
            first_byte = 0
        if len(data_in_bytes) < 126:
            first_byte += len(data_in_bytes)
            frame_part.append(first_byte)
            return frame_part
        if len(data_in_bytes) < 65535:
            first_byte += 126
            byte_array = len(data_in_bytes).to_bytes(2, byteorder='big')
            return frame_part + byte_array

        first_byte += 127
        byte_array = len(data_in_bytes).to_bytes(8, byteorder='big')
        return frame_part + byte_array

    def recieve_message(data_in_bytes):
        frame = WebSocketFrame()
        frame.frame_from_data(data_in_bytes)
