import unittest

from scapy.layers.inet import Ether
from ..iex_protocols.iex import *

# https://iextrading.com/docs/IEX%20Transport%20Specification.pdf
class TestIEX_Transport(unittest.TestCase):
    def test_load_iex_transport_header(self):
        p = IEX_TP(b'\x01\x00\x04\x80\x01\x00\x00\x00\x00\x00\x87\x42\x48\x00\x02\x00\x8c\xa6\x21\x00\x00\x00\x00\x00\xca\xc3\x00\x00\x00\x00\x00\x00\xec\x45\xc2\x20\x96\x86\x6d\x14')
        print(repr(p))
        self.assertEqual(p.version, 1)
        self.assertEqual(p.reserved, 0)
        self.assertEqual(p.msgProtoId, 0x8004) # DEEP v1.0
        self.assertEqual(p.channelId, 1)
        self.assertEqual(p.sessionId, 0x42870000)
        self.assertEqual(p.payloadLen, 72)
        self.assertEqual(p.messageCount, 2)
        self.assertEqual(p.streamOffset, 2205324)
        self.assertEqual(p.firstSequenceNumber, 50122)
        self.assertEqual(p.timestamp, 0x146d869620c245ec)

    def test_udp_dissection(self):
        p = Ether(b'\x01\x00^W\x15\x03\xb8Y\x9f\xfe\\\xc1\x08\x00E\x00\x00D\xdc\xdc@\x00@\x11\xab\x8c\x17\xe2\x9b\x83\xe9\xd7\x15\x03(\x89(\x89\x000\xcd\xe7\x01\x00\x03\x80\x01\x00\x00\x00\x00\x00\nI\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xe9=\xc1\x9e\x07\x98k\x16')
        self.assertIsNotNone(p[IEX_TP])
        p = p[IEX_TP]

        self.assertEqual(p.version, 1)
        self.assertEqual(p.reserved, 0)
        self.assertEqual(p.msgProtoId, 0x8003)
        self.assertEqual(p.channelId, 1)
        self.assertEqual(p.sessionId, 1225392128)
        self.assertEqual(p.payloadLen, len(p.payload))
        self.assertEqual(p.messageCount, 0)
        self.assertEqual(p.streamOffset, 0)
        self.assertEqual(p.firstSequenceNumber, 1)
        self.assertEqual(p.timestamp, 1615552049838112233)

class TestMessageBlock(unittest.TestCase):
    # Message block 1 in IEX Transport Specification (pg 10)
    def test_message_block1(self):
        d = b'\x26\x00\x54\x00\xac\x63\xc0\x20\x96\x86\x6d\x14\x5a\x49\x45\x49\x45\x58\x54\x20\x20\x20\x64\x00\x00\x00\x24\x1d\x0f\x00\x00\x00\x00\x00\x96\x8f\x06\x00\x00\x00\x00\x00'
        p = MessageBlock(d)
        self.assertEqual(p.messageLen, 38)

    # Message block 2 in IEX Transport Specification (pg 11)
    def test_message_block2(self):
        d = b'\x1e\x00\x38\x01\xac\x63\xc0\x20\x96\x86\x6d\x14\x5a\x49\x45\x58\x54\x20\x20\x20\xe4\x25\x00\x00\x24\x1d\x0f\x00\x00\x00\x00\x00'
        p = MessageBlock(d)
        self.assertEqual(p.messageLen, 30)

class TestSecurityDirectorymessage(unittest.TestCase):
    def test_security_directorymessage(self):
        d = bytes.fromhex('44800020897b5a1fb6145a4945585420202064000000241d0f000000000001')
        p = SecurityDirectoryMessage(d)
        print(p)
        self.assertEqual(p.messageType, int(b'D'))

if __name__ == '__main__':
    unittest.main()
