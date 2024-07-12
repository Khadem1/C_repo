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
This repository also comprises many other usefull implementations to be found easily for reference. The possible test cases will be updated soon. 

Added, a list of networking fields of a different headers, e.g. fields of ethernet, vlan, ipv4, ipv6, tcp, gtp, vxlan, gre, mpls, ipsec, ROCE_V2 etc. The stack has to be updated as well. The parser will parse different fields of different header received randomly.     
