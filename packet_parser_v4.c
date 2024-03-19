#include<stdio.h>
#include<string.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include<ctype.h>
#include"packet_parser_v4.h"
#pragma pack(1) 

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
    struct infiniband infiniband_hdr; 
    
    memcpy(&eth1,buff,sizeof(buff)); 
    if (ntohs(eth1.ethertype)==0x0800){  // IPV4 header 
        memcpy(&ipv4_hdr1,buff+14,sizeof(buff)); 
        
        if (ipv4_hdr1.proto==0x0001){  // ICMP header 
            memcpy(&icmp_hdr1,buff+34,sizeof(buff)); 
        }
        
        else if (ipv4_hdr1.proto==0x0006){
            memcpy(&tcp_hdr1,buff+14,sizeof(buff)); //TCP header 
            printf("TCP header\n");
        }
        else if(ipv4_hdr1.proto==0x11){    // UDP header (17)
            printf("UDP header \n"); 
            memcpy(&udp_hdr1,buff+34,sizeof(buff)); 
            if(ntohs(udp_hdr1.dest_port)==0x12b5){
                memcpy(&vxlan_hdr1,buff+42,sizeof(buff)); // Vxlan header 
            }
            else if(ntohs(udp_hdr1.dest_port)==0x12b7){
                   printf("Infinband header \n"); 
                   memcpy(&infiniband_hdr,buff+42,sizeof(buff)); // infinband header
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
    hexdump(buff,sizeof(buff));
    packet_parser(); 
    
     
    return 0; 
}
