import numpy as np


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

    def get_frame_from_data(self, data_in_bytes):
        self._parse_flags(data_in_bytes)
        self._parse_length(data_in_bytes)
        self._parse_mask(data_in_bytes)
        self._parse_payload(data_in_bytes)
        self._parse_payload_acording_to_opcode()

    def _parse_flags(self, data_in_bytes):
        first_byte = data_in_bytes[0]

        self.fin = first_byte & 0b10000000
        self.rsv1 = first_byte & 0b01000000

        if self.rsv1 != 0:
            raise ValueError("rsv1 non zero value")

        self.rsv2 = first_byte & 0b00100000

        if self.rsv2 != 0:
            raise ValueError("rsv2 non zero value")

        self.rsv3 = first_byte & 0b00010000

        if self.rsv3 != 0:
            raise ValueError("rsv3 non zero value")

        self.opcode = first_byte & 0b00001111

    def _parse_length(self, data_in_bytes):
        second_byte = data_in_bytes[1]
        self.payload_length = second_byte & 0b01111111

        mask_key_start = 2

        if self.payload_length == 126:
            mask_key_start = 4
            self.payload_length = int.from_bytes(data_in_bytes[2:4], 'big')

        if self.payload_length == 127:
            mask_key_start = 10
            self.payload_length = int.from_bytes(data_in_bytes[2:10], 'big')

        self.mask_key_start = mask_key_start

    def _parse_mask(self, data_in_bytes):

        second_byte = data_in_bytes[1]
        self.is_mask = second_byte & 0b10000000 == 0b10000000

        self.mask = []
        if self.is_mask:
            # better to keep in bytes
            self.mask = data_in_bytes[self.mask_key_start: self.mask_key_start+4]
            self.data_start = self.mask_key_start + 4
        else:
            self.data_start = self.mask_key_start

    def _parse_payload(self, data_in_bytes):
        payload_data = b''

        if self.payload_length == 0:
            self.payload_data = payload_data
            return

        decoded_data = []
        if self.is_mask:
            for byte, data in enumerate(data_in_bytes[self.data_start:]):
                decoded_data.append(data ^ self.mask[byte % 4])
            payload_data = bytes(decoded_data)
        else:
            payload_data = bytes(data_in_bytes[self.data_start:])

        self.payload_data = payload_data

    def _parse_payload_acording_to_opcode(self):
        if self.opcode == 1:
            self.payload_data = self.payload_data.decode("utf-8")
        if self.opcode == 2:
            self.payload_data = ' '.join(format(byte, '08b')
                                         for byte in self.payload_data)

    def get_payload_data(self):
        return self.payload_data

    def get_payload_length(self):
        return self.payload_length
