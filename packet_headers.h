#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H

#include<stdint.h>

/* My own header structs */
struct ipheader {
    uint8_t iph_hlen: 4, iph_ver: 4; /* The ordering is due to the
                                       endianness (intel: little endian)
                                     */
    uint8_t iph_tos;
    uint16_t iph_tlen;
    uint16_t iph_id;
    //u_short iph_flg;         
    uint16_t iph_frag_offset; 
    uint8_t iph_ttl;
    uint8_t iph_protocol;
    uint16_t iph_chk_sum;
    uint32_t iph_src;
    uint32_t iph_dst;
    /* Can add options from here */
};

struct tcpheader {
    uint16_t tcph_src_port;
    uint16_t tcph_dst_port;
    uint32_t tcph_seq_num;
    uint32_t tcph_ack_num;
    uint8_t tcph_reserved1: 4;   // Unused (future use); Must be set to 0
    uint8_t tcph_data_offset: 4;
    uint16_t tcph_ctrl_fin: 1,
            tcph_ctrl_syn: 1,
            tcph_ctrl_rst: 1,
            tcph_ctrl_psh: 1,
            tcph_ctrl_ack: 1,
            tcph_ctrl_urg: 1,
            tcph_reserved2: 2;  // Splliting reserved (6 bits) into two parts
    uint16_t tcph_window;
    uint16_t tcph_chk_sum;
    uint16_t tcph_urg_ptr;
};

struct icmpheader {
    uint8_t icmph_type;
    uint8_t icmph_code;
    uint16_t icmph_chk_sum;
    /* ICMP header type specific */
    uint16_t icmph_id;
    uint16_t icmph_seq_num;
    /* uint32_t icmph_data; */  //Verify why data field is not provided  
};

struct pseudo_header{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t zero;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

#endif