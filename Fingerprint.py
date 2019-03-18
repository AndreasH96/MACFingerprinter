try:
    import pyshark
    import argparse
    import sys
    import scapy.all as scapy
    from scapy.layers.dot11 import Dot11,sendp,RadioTap,Dot11FCS
    from scapy.all import wireshark
    from scapy import all
    import uuid
    import pyx
    import struct
except:
    print("!! Failed to import dependencies... ")
    raise SystemExit
