import unittest
import numpy as np

from src.websocket import WebSocketFrame


class TestRecieveFrame(unittest.TestCase):

    def test_single_frame_unmasked_text_message(self):
        message = [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]
        expected = WebSocketFrame(
            fin=True, opcode=1, payload_length=5, payload_data=[0x48, 0x65, 0x6c, 0x6c, 0x6f]
        )

        frame = WebSocketFrame.frame_from_data(message)

        self.assertEqual(frame, expected)

    def test_single_frame_masked_text_message(self):
        message = [0x81, 0x85, 0x37, 0xfa, 0x21,
                   0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]
        expected = WebSocketFrame(
            fin=True, opcode=1, payload_length=5, payload_data=[0x48, 0x65, 0x6c, 0x6c, 0x6f],
            mask=True, masking_key=[0x37, 0xfa, 0x21, 0x3d]
        )

        frame = WebSocketFrame.frame_from_data(message)

        self.assertEqual(frame, expected)

    def test_fragmented_unmasked_text_message(self):
        messages = [[0x01, 0x03, 0x48, 0x65, 0x6c], [0x80, 0x02, 0x6c, 0x6f]]

        expected_frames = [
            WebSocketFrame(
                fin=False, opcode=1, payload_length=3, payload_data=[0x48, 0x65, 0x6c]
            ),
            WebSocketFrame(
                opcode=0, payload_length=2, payload_data=[0x6c, 0x6f]
            )
        ]

        for message, expected_frame in zip(messages, expected_frames):
            result = WebSocketFrame.frame_from_data(message)

            self.assertEqual(result, expected_frame)

    def test_ping(self):
        message = [0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]

        expected = WebSocketFrame(
            opcode=9, payload_length=5, payload_data=[0x48, 0x65, 0x6c, 0x6c, 0x6f]
        )

        frame = WebSocketFrame.frame_from_data(message)

        self.assertEqual(frame, expected)

    def test_masked_pong(self):
        message = [0x8a, 0x85, 0x37, 0xfa, 0x21,
                   0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]

        expected = WebSocketFrame(
            opcode=10, payload_length=5, payload_data=[0x48, 0x65, 0x6c, 0x6c, 0x6f],
            mask=True, masking_key=[0x37, 0xfa, 0x21, 0x3d,]
        )

        frame = WebSocketFrame.frame_from_data(message)
        self.assertEqual(frame, expected)

    def test_extended_payload_length(self):
        '''
        this test is for 7 + 16 bits of frame length
        '''
        long_binary_message_in_bytes = np.random.randint(0, 16, 256).tolist()

        message = [0x82, 0x7E, 0x01, 0x00] + long_binary_message_in_bytes

        expected = WebSocketFrame(
            opcode=2, payload_length=256, payload_data=long_binary_message_in_bytes
        )

        frame = WebSocketFrame.frame_from_data(message)

        self.assertEqual(frame, expected)

    def test_more_extended_payload_length(self):
        '''
        this test is for 7 + 64 bits of frame length
        '''
        long_binary_message_in_bytes = np.random.randint(
            0, 16, 65536).tolist()  # 64KiB

        message = [0x82, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x01, 0x00, 0x00] + long_binary_message_in_bytes

        expected = WebSocketFrame(
            opcode=2, payload_length=65536, payload_data=long_binary_message_in_bytes
        )

        frame = WebSocketFrame.frame_from_data(message)

        self.assertEqual(frame, expected)

    def test_RSV1_parsing(self):
        message = [0xc1, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]

        expected = WebSocketFrame(
            opcode=1, payload_length=5, payload_data=[0x48, 0x65, 0x6c, 0x6c, 0x6f], RSV1=True
        )

        frame = WebSocketFrame.frame_from_data(message)

        self.assertEqual(frame, expected)

    def test_RSV2_parsing(self):
        message = [0xa1, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]

        expected = WebSocketFrame(
            opcode=1, payload_length=5, payload_data=[0x48, 0x65, 0x6c, 0x6c, 0x6f], RSV2=True
        )

        frame = WebSocketFrame.frame_from_data(message)

        self.assertEqual(frame, expected)

    def test_RSV3_parsing(self):
        message = [0x91, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]

        expected = WebSocketFrame(
            opcode=1, payload_length=5, payload_data=[0x48, 0x65, 0x6c, 0x6c, 0x6f], RSV3=True
        )

        frame = WebSocketFrame.frame_from_data(message)

        self.assertEqual(frame, expected)


class TestDecodeFrame(unittest.TestCase):

    def test_decode_acording_to_opcode(self):
        for opcode in range(0, 15):
            frame = WebSocketFrame(
                fin=True, opcode=opcode, payload_length=5, payload_data=[0x48, 0x65, 0x6c, 0x6c, 0x6f]
            )
            if opcode == 1:
                self.assertEqual(
                    frame.parse_payload_acording_to_opcode(), 'Hello')
            elif opcode == 2:
                self.assertEqual(
                    frame.parse_payload_acording_to_opcode(),
                    '01001000 01100101 01101100 01101100 01101111'
                )
            else:
                self.assertEqual(
                    frame.parse_payload_acording_to_opcode(), None)


if __name__ == '__main__':
    unittest.main()
