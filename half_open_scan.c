#include<stdio.h>
#include<string.h>
#include<stdlib.h>  // For exit()
#include<libio.h>   // For NULL
#include<time.h>

/* For Error checking */
#include<errno.h>

/* For socket() */
#include<sys/socket.h>
#include<sys/types.h>   // For get,setsockopt()
#include<netinet/in.h>  // For socket()
#include<arpa/inet.h>   // For byte-order functions: eg., htonl(), ntohl()
#include<netdb.h>       // For getaddrinfo()
#include<unistd.h>      // For close()

/* __Own_Header_Structs__ */
#include"packet_headers.h"

/* __OS_Network_Stack_Headers__ */
#include<netinet/ip.h> 
#include<linux/if_ether.h>
#include<netinet/tcp.h>

/* Defines */
#define PCKT_LEN 8192
#define DEFAULT_PORT "9897"

/* Source, destination address structs */
struct sockaddr_in src_in, dst_in;
struct pseudo_header psh;

/* For sending */
struct ipheader *ip;
struct tcpheader *tcp;

char datagram[PCKT_LEN];  // Just datagram, no data;

int raw_socket;

/* Function definitions */
void error(const char* msg){
    perror(msg);
    exit(-1);
}


/*  __Checksum Algorithm__
    1. Set the chk_sum to 0,
    2. Pad the data to an even number of bytes,
    3. Reinterpret the data as a sequence of 16-bit unsigned integers that are 
        in network byte order,
    4. Calculate the sum of the integers, subtracting 0xffff whenever 
        the sum => 0x10000, and
    5. Calculate the bitwise complement of the sum and set it as the checksum.
*/

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

uint16_t tcp_checksum(const void* buff,size_t len){
    const uint16_t *buf = buff;
    uint16_t *ip_src = (void *)&(ip->iph_src);
    uint16_t *ip_dst = (void *)&(ip->iph_dst);
    uint32_t sum;
    size_t length = len;

    // Calculate the sum
    sum = 0;
    while(len > 1){
        sum += *buf++;
        if(sum & 0x80000000){
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        len -= 2;
    }

    if(len & 1){    // Add padding if the packet length is odd
        sum += *((uint8_t *)buf);
    }

    // Add the pseudo-header
    sum += htons(*(ip_src++));
    sum += htons(*ip_src);
    sum += htons(*(ip_dst++));
    sum += htons(*ip_dst);
    sum += htons(IPPROTO_TCP);
    sum += htons(length);

    // Add the carries
    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return the one's complement of the sum
    return (htons((uint16_t)(~sum)));
}

void resetCurrentPortConnection(){
    tcp->tcph_ctrl_rst = 1;
    tcp->tcph_ctrl_syn = 0;
    
    if(sendto(raw_socket,
                  datagram,
                  ip->iph_tlen,
                  0,
                  (struct sockaddr *)&dst_in,
                  sizeof(dst_in)) < 0) {
                    printf("sendto() error:\n");
    }

    tcp->tcph_ctrl_syn = 1;
}

void packetReturnFlagCheck(const int curr_port){
    unsigned char *return_packet = (unsigned char *) malloc(65536); //to receive data
    memset(return_packet,0,65536);

    //Receive a network packet and copy in to buffer
    int buflen=recvfrom(raw_socket,return_packet, 65536, 0, (struct sockaddr *)&dst_in,(socklen_t *)sizeof(struct sockaddr));
    if(buflen<0){
        return;
        /*printf("error in reading recvfrom function\n");
        exit(-1);*/
    }
    else{
        printf("one packet recieved\n");
    }

    /* Using Network Stack structs */
    struct iphdr *rcv_iph = (struct iphdr*)(return_packet + sizeof(struct ethhdr));
    uint8_t rcv_ip_hdrlen = rcv_iph->ihl*4;
    struct tcphdr *rcv_tcph = (struct tcphdr*)(return_packet + rcv_ip_hdrlen + sizeof(struct ethhdr));
    if(rcv_tcph->th_flags == TH_ACK){
        printf("%d is open.\n");
        resetCurrentPortConnection();
    }
}

void headersInit(){
    /* __IP_header__ */
    ip->iph_hlen = 5;   // (5*4) = 20 bytes; no options
    ip->iph_ver = 4;    // IPv4
    ip->iph_tos = 0;    // Normal delivery
    ip->iph_tlen = sizeof(struct ipheader) + sizeof(struct tcpheader); // No payload; Can add
    ip->iph_id = htonl(54321);  // can be randomly set
    //ip->iph_flg = 
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
    struct addrinfo hints, *dest_info, *p;
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

void portScanner(int argc, char *argv[]){
    
    ip = (struct ipheader *)datagram;
    tcp = (struct tcpheader *)(datagram + sizeof(struct ipheader));
    
    /* check why the following is used (a lot in others code) */
    int one = 1;
    const int *val = &one;  

    memset(datagram, 0, PCKT_LEN);

    /* __Block__for__src_&__dst__addrs_struct__ */
    char *src_ip_addr;
    char *src_port;
    src_ip_addr = malloc(sizeof(char));
    src_port = malloc(sizeof(char));
    if(argc == 2){  // Use interface IP address and default port for source address
        src_ip_addr[0] = 'n';
        src_port[0] = 'n';
        manualAddrPacking((const char*)src_ip_addr, (const char*)src_port, argv[1]);
    }
    else if (argc == 4){    // Use provided IP address and port for source address
        /* __Parse_Spoofed_SRC_IP_&_Port__ */
        for(int i = 0; *(argv[1] + i) != '\0'; ++i){
            src_ip_addr[i] = *(argv[1] + i);
        }
        for(int i = 0; *(argv[2] + i) != '\0'; ++i){
            src_port[i] = *(argv[2] + i);
        }
       
        manualAddrPacking((const char*)src_ip_addr, (const char*)src_port, argv[3]);  // Passing <source hostname/IP> <source port> 
    }
    else{
        printf("__Invalid parameters__\n");
        printf(" -Usage: %s <target hostname/ip> or %s <source hostname/IP> <source port> <target hostname/IP>", argv[0], argv[0]);
        exit(-1);
    }
    
    /* __socket_creation__ */
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(raw_socket == -1){
        error("Failed to create socket: ");
    }
    else{
        printf("Created raw socket successfully.\n");
    }

    if(setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1){
        error("Setsocket  error: ");
    }
    else{
        printf("setsockopt(IPHDRINCL) successful.\n");
    }

    headersInit();
 
    struct timeval tv;
    tv.tv_sec = 5;   /* 5 Sec timeout */
    tv.tv_usec = 0;

    /* __Move_on_to_next_port_after_timeout__ */
    if(setsockopt(raw_socket, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv, sizeof(struct timeval))){
        error("setsockopt: rcvtimeout");
    }
    else{
        printf("setsockopt(SO_RCVTIMEO) successful.\n");
    } 

    printf("Port Scan:\n");
    printf("__Open ports__\n");
    for(int i = 1; i < 65535; ++i){
        tcp->tcph_dst_port = htons(i);
        ip->iph_chk_sum = csum((uint16_t *)datagram, ip->iph_tlen >> 1);
        //tcp->tcph_chk_sum = tcp_checksum(tcp, 4*(tcp->tcph_data_offset));
        if(sendto(raw_socket,
                  datagram,
                  ip->iph_tlen,
                  0,
                  (struct sockaddr *)&dst_in,
                  sizeof(dst_in)) < 0) {
                    printf("sendto() error:\n");
        }

        packetReturnFlagCheck(i);
    }    
}



