import unittest

from scapy.layers.inet import Ether
from ..iex_protocols.iex import *

# https://iextrading.com/docs/IEX%20Transport%20Specification.pdf
class TestIEX_Transport(unittest.TestCase):
    def test_load_iex_transport_header(self):
        p = IEX_TP(b'\x01\x00\x04\x80\x01\x00\x00\x00\x00\x00\x87\x42\x48\x00\x02\x00\x8c\xa6\x21\x00\x00\x00\x00\x00\xca\xc3\x00\x00\x00\x00\x00\x00\xec\x45\xc2\x20\x96\x86\x6d\x14')
        print(repr(p))
        self.assertEqual(1, p.version)
        self.assertEqual(0, p.reserved)
        self.assertEqual(0x8004, p.msgProtoId)
        self.assertEqual(1, p.channelId)
        self.assertEqual(0x42870000, p.sessionId)
        self.assertEqual(72, p.payloadLen)
        self.assertEqual(2, p.messageCount)
        self.assertEqual(2205324, p.streamOffset)
        self.assertEqual(50122, p.firstSequenceNumber)
        self.assertEqual(0x146d869620c245ec, p.timestamp)

    def test_udp_dissection(self):
        p = Ether(b'\x01\x00^W\x15\x03\xb8Y\x9f\xfe\\\xc1\x08\x00E\x00\x00D\xdc\xdc@\x00@\x11\xab\x8c\x17\xe2\x9b\x83\xe9\xd7\x15\x03(\x89(\x89\x000\xcd\xe7\x01\x00\x03\x80\x01\x00\x00\x00\x00\x00\nI\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xe9=\xc1\x9e\x07\x98k\x16')
        self.assertIsNotNone(p[IEX_TP])
        p = p[IEX_TP]

        self.assertEqual(1, p.version)
        self.assertEqual(0, p.reserved)
        self.assertEqual(0x8003, p.msgProtoId)
        self.assertEqual(1, p.channelId)
        self.assertEqual(1225392128, p.sessionId)
        self.assertEqual(len(p.payload), p.payloadLen)
        self.assertEqual(0, p.messageCount)
        self.assertEqual(0, p.streamOffset)
        self.assertEqual(1, p.firstSequenceNumber)
        self.assertEqual(1615552049838112233, p.timestamp)

class TestMessageBlock(unittest.TestCase):
    # Message block 1 in IEX Transport Specification (pg 10)
    def test_message_block1(self):
        d = b'\x26\x00\x54\x00\xac\x63\xc0\x20\x96\x86\x6d\x14\x5a\x49\x45\x49\x45\x58\x54\x20\x20\x20\x64\x00\x00\x00\x24\x1d\x0f\x00\x00\x00\x00\x00\x96\x8f\x06\x00\x00\x00\x00\x00'
        p = MessageBlock(d)
        self.assertEqual(38, p.messageLen)

    # Message block 2 in IEX Transport Specification (pg 11)
    def test_message_block2(self):
        d = b'\x1e\x00\x38\x01\xac\x63\xc0\x20\x96\x86\x6d\x14\x5a\x49\x45\x58\x54\x20\x20\x20\xe4\x25\x00\x00\x24\x1d\x0f\x00\x00\x00\x00\x00'
        p = MessageBlock(d)
        self.assertEqual(30, p.messageLen)

class TestSecurityDirectoryMessage(unittest.TestCase):
    def test_security_directorymessage(self):
        d = bytes.fromhex('44800020897b5a1fb6145a4945585420202064000000241d0f000000000001')
        p = SecurityDirectoryMessage(d)
        print(p)
        self.assertEqual(b'D', p.messageType)
        self.assertEqual('T', p.flags)
        self.assertEqual(1492414800000000000, p.timestamp)

class TestTradingStatusMessage(unittest.TestCase):
    def test_trading_status_message(self):
        d = bytes.fromhex('4848ac63c02096866d145a4945585420202054312020')
        p = TradingStatusMessage(d)
        print(p)
        self.assertEqual(b'H', p.messageType)
        self.assertEqual(ord('H'), p.tradingStatus)
        # self.assertEqual(, p.timestamp) # fixme
        self.assertEqual(b'ZIEXT   ', p.symbol)
        self.assertEqual(b'T1  ', p.reason)

if __name__ == '__main__':
    unittest.main()
