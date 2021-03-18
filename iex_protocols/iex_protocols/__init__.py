from scapy.all import bind_layers
from scapy.layers.inet import UDP, TCP
from .iex import IEX_TP

bind_layers(UDP, IEX_TP, sport=10377)
bind_layers(UDP, IEX_TP, dport=10377)
# bind_layers(TCP, IEX_TP, sport=10377)
# bind_layers(TCP, IEX_TP, dport=10377)
