import argparse
from scapy.layers.inet import *
from iex_protocols.iex_protocols.iex import IEX_TP

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=argparse.FileType(mode='rb'))
    return parser.parse_args()

def main():
    args = parse_args()
    p = Ether(b'\x01\x00^W\x15\x03\xb8Y\x9f\xfe\\\xc1\x08\x00E\x00\x00D\xdc\xdc@\x00@\x11\xab\x8c\x17\xe2\x9b\x83\xe9\xd7\x15\x03(\x89(\x89\x000\xcd\xe7\x01\x00\x03\x80\x01\x00\x00\x00\x00\x00\nI\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xe9=\xc1\x9e\x07\x98k\x16')
    print(repr(p[UDP]))

if __name__ == '__main__':
    main()
