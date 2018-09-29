#include"packet_headers.h"
#include"half_open_scan.h"

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<inttypes.h>
#include<arpa/inet.h>
#include<netdb.h>


#define DEFAULT_PORT "9897"

void headersInit(){
    /* __IP_header__ */
    ip->iph_hlen = 5;   // (5*4) = 20 bytes; no options
    ip->iph_ver = 4;    // IPv4
    ip->iph_tos = 0;    // Normal delivery
    ip->iph_tlen = sizeof(struct ipheader) + sizeof(struct tcpheader); // No payload; Can add
    //ip->iph_id = htonl(54321);  // can be randomly set; We are not setting it since we need it pick systems ip address.
    //ip->iph_flg
    ip->iph_frag_offset = htons(0x4000);    // Dont fragment
    ip->iph_ttl = 255;      // Maximum number of hops
    ip->iph_protocol = 6;   // TCP
    ip->iph_chk_sum = 0;    // Initially set to 0

    /* Can be set randomly to avoid being blocked by firewall */
    ip->iph_src = src_in.sin_addr.s_addr;   // Source IP address
    ip->iph_dst = dst_in.sin_addr.s_addr;   // Destination Ip address

    /* __TCP_header__ */
    tcp->tcph_src_port = htons(src_in.sin_port);
    
    srand(time(0));
    tcp->tcph_seq_num = rand(); // In a SYN packet, the seq_num is random 

    tcp->tcph_ack_num = 0;  // TCP ack is 0 in first packet 
    tcp->tcph_data_offset = (uint8_t)5;  // Header length

    /* __Flags__ */
    tcp->tcph_ctrl_syn = 1;
    tcp->tcph_ctrl_fin = 0;
    tcp->tcph_ctrl_psh = 0;
    tcp->tcph_ctrl_rst = 0;
    tcp->tcph_ctrl_urg = 0;
    tcp->tcph_ctrl_ack = 0;

    tcp->tcph_window = htons(29200);
    tcp->tcph_chk_sum = 0; // TCP Checksum offload
    tcp->tcph_urg_ptr = 0;
}

void manualAddrPacking(const char *src_ip_addr, const char *src_port, char *dest_host_name){
    
    /* __Source_Address__ */
    src_in.sin_family = AF_INET;

    if(*src_ip_addr == 'n' && *src_port == 'n'){
        src_in.sin_addr.s_addr = htonl(INADDR_ANY); // Bind to any local address
        src_in.sin_port = (atoi(DEFAULT_PORT));  // Bind to port 9897
    }
    else{  
        /* Bind to specified port and ip address */
        src_in.sin_addr.s_addr = (inet_addr(src_ip_addr));
        src_in.sin_port = (atoi(src_port));
    }

    /* __Destination_address__ */
    struct addrinfo hints;
    struct addrinfo *dest_info, *p;
    int status;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;    // Get only IPv4 addresses
    hints.ai_socktype = SOCK_STREAM;

    /* __Destination_resolution__ */
    if((status == getaddrinfo(dest_host_name,
                                NULL,  // No specified port
                                &hints,
                                &dest_info)) != 0){
        printf("getaddrinfo: %s\n", gai_strerror(status));
        error("getaddrinfo error");
        exit(-1);
    }

    printf("Destination host IP address for %s:\n\t", dest_host_name);
    
    /* loop through the results and use the first (dest addr) we can */
    char ipstr[INET6_ADDRSTRLEN];
    for(p = dest_info;p != NULL; p = p->ai_next) {
        void *addr;
        char *ipver;

        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            dst_in.sin_addr.s_addr = ipv4->sin_addr.s_addr;
            ipver = "IPv4";
        } 
        /* __Not_in_use__ __Future_update__ 
        else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }
        */
        // convert the IP to a string and print it:
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("  %s: %s\n", ipver, ipstr);
        break;
    }
    free(dest_info);
} 