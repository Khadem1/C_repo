#include<stdio.h>
#include<string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#pragma pack(1) 

/**
 * This is just parser code, for printing all the releavnt fields, 
 * refer to packet_parser_v2.c 
*/
/*unsigned char buff[]={0x08,0x00, 0x27, 0xf2, 0x1d, 0x8c, 0x08, 0x00, 0x27, 0xae, 0x4d, 0x62, 0x08, 0x00,
 0x45, 0x00, 0x00, 0x4e, 0xd9, 0x98, 0x40, 0x00, 0x40, 0x11, 0x6f, 0x9e, 0xc0, 0xa8, 0x38, 0x0b, 0xc0, 0xa8, 0x38, 0x0c,
  0x9b, 0xf4, 0x12, 0xb5, 0x00, 0x3a, 0x00, 0x00, 
  0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x00};*/

/*eth/ipv4/tcp packet*/
static const unsigned char buff[78] = {
0x28, 0xa6, 0xdb, 0x40, 0x6f, 0x97, 0x10, 0x6f, /* (..@o..o */
0xd9, 0x0c, 0x05, 0x77, 0x08, 0x00, 0x45, 0x00, /* ...w..E. */
0x00, 0x40, 0x69, 0x04, 0x40, 0x00, 0x40, 0x06, /* .@i.@.@. */
0xf4, 0xf4, 0x0a, 0x07, 0x10, 0xb1, 0xac, 0xd9, /* ........ */
0x15, 0x2e, 0xaa, 0x3a, 0x01, 0xbb, 0x97, 0xee, /* ...:.... */
0x40, 0x77, 0x06, 0xe5, 0xef, 0x93, 0xb0, 0x10, /* @w...... */
0x01, 0xf5, 0xc9, 0x21, 0x00, 0x00, 0x01, 0x01, /* ...!.... */
0x08, 0x0a, 0x90, 0x31, 0x54, 0x31, 0x27, 0x3a, /* ...1T1': */
0x25, 0x94, 0x01, 0x01, 0x05, 0x0a, 0x06, 0xe5, /* %....... */
0xef, 0x6c, 0x06, 0xe5, 0xef, 0x93              /* .l.... */
};


struct ether_hdr
{
    unsigned char dmac[6];
    unsigned char smac[6];
    uint16_t ethertype;
};

struct ipv4_hdr{
    uint8_t version : 4;
    uint8_t ihl : 4;
    uint8_t d_sf;
    uint16_t len;
    uint16_t iden;
    uint16_t flags;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t saddr;
    uint32_t daddr;

};     

struct udp_hdr{
    u_int16_t source_port;
	u_int16_t dest_port;
	u_int16_t length; 
    u_int16_t checksum;
};
    
struct vxlan_hdr
{
    u_int16_t flags;
    u_int16_t group_policy_id; 
    u_int32_t VNI:24; 
    u_int8_t reserved; 
};

struct icmp_hdr{
    u_int8_t type;
    u_int8_t code; 
    u_int16_t checksum; 
    u_int16_t identifier; 
    u_int16_t seq_numbr; 
    unsigned char time_stamp[8]; 
    unsigned char data[48];   
};

struct VLAN{
    uint16_t priority; 
    uint16_t tag_proto_ident; //TPID 
};

struct tcp_hdr{
    uint16_t source_port;
    uint16_t destination_port; 
    uint32_t seq_num; 
    uint32_t ack_num;
    uint16_t flags;
    uint16_t win_size; 
    uint16_t checksum; 
    uint16_t urgent_pointer;
};

struct gre_hdr
{
    uint8_t version; 
    uint8_t flags; 
    uint16_t proto_type; 
    uint32_t VNI:24; 
    uint8_t reserved; 
};

struct  ipv6_hdr
{
    uint8_t version:4; 
    uint8_t traffic_class:8; 
    uint32_t flow_label:20; 
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit; 
    unsigned char src_addr[16];
    unsigned char dst_addr[16];  
};

struct arp_hdr
{
    u_int16_t hw_type; 
    u_int16_t proto_type; 
    u_int8_t hw_size;
    u_int8_t proto_size; 
    u_int16_t opcode; 
    unsigned char sender_mac[6];
    uint32_t sender_ip_addr;
    unsigned char target_mac[6];
    uint32_t target_ip_addr;
};


void packet_parser(){
    unsigned char ethhdr[62];
    struct ether_hdr eth1;
    struct ipv4_hdr ipv4_hdr1; 
    struct udp_hdr udp_hdr1; 
    struct vxlan_hdr vxlan_hdr1; 
    struct icmp_hdr icmp_hdr1;
    struct VLAN vlan1; 
    struct ipv6_hdr ipv6_hdr1; 
    struct arp_hdr arp_hdr1;   
    struct tcp_hdr tcp_hdr1; 
    struct gre_hdr gre_hdr1;  
    
    memcpy(&eth1,buff,sizeof(buff)); 
    if (ntohs(eth1.ethertype)==0x0800){  // IPV4 header 
        memcpy(&ipv4_hdr1,buff+14,sizeof(buff)); 
        if (ipv4_hdr1.proto==0x0001){  // ICMP header 
            memcpy(&icmp_hdr1,buff+34,sizeof(buff)); 
        }
        else if (ipv4_hdr1.proto==0x0006){
            memcpy(&tcp_hdr1,buff+14,sizeof(buff)); //TCP header 
            printf("TCP header \n");
        }
        else if(ipv4_hdr1.proto==0x11){    // UDP header (17)
           memcpy(&udp_hdr1,buff+34,sizeof(buff)); 
          if(ntohs(udp_hdr1.dest_port)==0x12b5){
             memcpy(&vxlan_hdr1,buff+42,sizeof(buff)); // Vxlan header 
          }
        }  
    }
    else if(ntohs(eth1.ethertype)==0x8100){
         memcpy(&vlan1,buff+14,sizeof(buff));
    }
    else if(ntohs(eth1.ethertype)==0x86dd){   // IPV6 Header
        memcpy(&ipv6_hdr1,buff+14,sizeof(buff)); 
    }
    else if(ntohs(eth1.ethertype)==0x0806){  // ARP header
        memcpy(&arp_hdr1,buff+14,sizeof(buff)); 
    }
    else if(ntohs(eth1.ethertype)==0xb7ea){      // GRE header
       memcpy(&gre_hdr1,buff+14,sizeof(buff));  
    }
}
int main(int argc, char *argv[]){
    //unsigned char buff[200]={}; 
    packet_parser(); 
    
     
    return 0; 
}
