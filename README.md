#C_repo
# C_repo
This repository is implementing a network packet parser for common network packets. The packet_parser starts packet parsing from ethernet, vlan, double vlan, mpls, ipv4/ipv6, and tcp/udp. Ths parser will be also extented for tunnel packets as well. 

The packet parser can now parse the following packets. 
```shell
eth / ipv4 / udp
eth / ipv4 / tcp
eth / vlan / ipv4 / udp
eth / vlan / ipv4 / tcp

eth / ipv6 / udp
eth / ipv6 / tcp
eth / vlan / ipv6 / udp
eth / vlan / ipv6 / tcp
```
The parser will be also extented for QinQ packets. 
