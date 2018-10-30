# splittcp

Simple program to split large TCP packets in a pcap into smaller packets.

TCP sequence numbers are updated to reflect the new packet sizes.

**Note**: Only works with Ethernet packets.

## Build

Depends on libtins and C++11.

Should be able to just run make if you have libtins installed and your compiler
supports C++ 11.

## Usage

`./splittcp pcap_with_huge_tcp_packets.pcap output.pcap`
