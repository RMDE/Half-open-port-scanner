#include "checksums.h"
#include"half_open_scan.h"
#include"packet_headers.h"

#include<arpa/inet.h>
#include<stdlib.h>
#include<string.h>

/*  __Checksum Algorithm__
    1. Set the chk_sum to 0,
    2. Pad the data to an even number of bytes,
    3. Reinterpret the data as a sequence of 16-bit unsigned integers that are 
        in network byte order,
    4. Calculate the sum of the integers, subtracting 0xffff whenever 
        the sum => 0x10000, and
    5. Calculate the bitwise complement of the sum and set it as the checksum.
*/

struct pseudo_header psh;

uint16_t csum(uint16_t *buf, int len){  // uint16_t is used for it to be 16-bit addressable
    uint32_t sum;
    for(sum = 0; len > 0; --len){
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);    /* 
                                   Complement of the sum, which is returned, is 
                                   the sum
                                */     
}

short checksum_calc(unsigned short *addr, unsigned int count) {
          /* Compute Internet Checksum for "count" bytes
            *         beginning at location "addr".
            */
       register long sum = 0;


        while( count > 1 )  {
           /*  This is the inner loop */
               sum += * addr++;
               count -= 2;
       }
           /*  Add left-over byte, if any */
       if( count > 0 )
               sum += * (unsigned char *) addr;

           /*  Fold 32-bit sum to 16 bits */
       while (sum>>16)
           sum = (sum & 0xffff) + (sum >> 16);

       return ~sum;
}

short temp_tcp_checsum(){
    uint16_t total_len = ntohs(ip->iph_tlen);

    int tcpopt_len = 0;
    int tcpdatalen = 0;

    psh.source_address = ntohl(0xC0A87F85); //ip->iph_src;
    psh.dest_address = ip->iph_dst;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcpheader) + tcpopt_len + tcpdatalen);

    int totaltcp_len = sizeof(struct pseudo_header) + sizeof(struct tcpheader) + tcpopt_len + tcpdatalen;
    unsigned short * temp_tcp = (unsigned short *)malloc(totaltcp_len);

    memcpy((unsigned char *)temp_tcp, &psh, sizeof(struct pseudo_header));
    memcpy((unsigned char *)temp_tcp+sizeof(struct pseudo_header), (unsigned char *)tcp, sizeof(struct tcpheader));
    memcpy((unsigned char *)temp_tcp+sizeof(struct pseudo_header)+sizeof(struct tcpheader), (unsigned char *)ip+(ip->iph_hlen)+(sizeof(struct tcpheader)), tcpopt_len);
    memcpy((unsigned char *)temp_tcp+sizeof(struct pseudo_header)+sizeof(struct tcpheader)+tcpopt_len, (unsigned char *)tcp+(tcp->tcph_data_offset*4), tcpdatalen);

    //printf("%"PRIu32"\n", psh.source_address);
    return (checksum_calc(temp_tcp, totaltcp_len));
}