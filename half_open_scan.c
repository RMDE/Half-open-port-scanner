#include<stdio.h>
#include<string.h>
#include<stdlib.h>  // For exit()
#include<libio.h>   // For NULL
#include<time.h>
#include<sys/time.h>
#include<inttypes.h>

#include<errno.h>

/* For socket() */
#include<sys/socket.h>
#include<sys/types.h>   // For get,setsockopt()
#include<netinet/in.h>  // For socket()
#include<arpa/inet.h>   // For byte-order functions: eg., htonl(), ntohl()
#include<netdb.h>       // For getaddrinfo()
#include<unistd.h>      // For close()

/* __Own_Header_Files__ */
#include"packet_headers.h"
#include"half_open_scan.h"
#include"header_funcs.h"
#include"checksums.h"

/* __OS_Network_Stack_Headers__ */
#include<netinet/ip.h> 
#include<linux/if_ether.h>
#include<netinet/tcp.h>


/* Defines */
#define PCKT_LEN 8192

/* Source, destination address structs */
struct sockaddr_in src_in, dst_in;

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

void packetReturnFlagCheck(){
    unsigned char *return_packet;
    return_packet = (unsigned char *)malloc(65536); //to receive data
    if(return_packet == NULL){
        perror("Malloc: ");
    }

    memset(return_packet, 0, 65535);
    socklen_t len = sizeof(dst_in);  
    
    //Receive a network packet and copy in to buffer
    int buflen = recvfrom(raw_socket, return_packet, 65536, 0, (struct sockaddr *)&dst_in, &len);
    if(buflen<0 && errno != EAGAIN){    /* errno != EAGAIN makes sure that error is not due to recvfrom blocking for data */
        perror("recvfrom");
        return;
    }
       
    /* Using Network Stack structs */
    struct iphdr *rcv_iph = (struct iphdr*)(return_packet);
    unsigned short rcv_ip_hdrlen = rcv_iph->ihl*4;
    struct tcphdr *rcv_tcph = (struct tcphdr*)(return_packet + rcv_ip_hdrlen);
    
    if(rcv_tcph->th_dport == ntohs(9897)){
        //printf("\nReceived packet for port: %d\n", ntohs(rcv_tcph->th_sport));
        if(rcv_tcph->th_flags == (0x012) || rcv_tcph->th_flags == (0x10)){ //(0x012) == SYN & ACK flags
            printf("%d is open.\n", ntohs(rcv_tcph->th_sport));
        }
        else if((unsigned int)rcv_tcph->rst == 1){
            //printf("\nclosed\n");
        }
    }    
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
        for(int i = 0; *(argv[1] + i) != '\0'; ++i){    // Need to fix for memory overflow
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
    tv.tv_sec = 3;   /* 3 Sec timeout */
    tv.tv_usec = 0;

    if (setsockopt(raw_socket, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0){
        error("setsockopt(SO_REUSEADDR) failed");
    }
    else{
        printf("setsockopt(SO_REUSEADDR) successful.\n");
    }
    
    /* __Move_on_to_next_port_after_timeout__ */
    if(setsockopt(raw_socket, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv, sizeof(struct timeval))){
        error("setsockopt: rcvtimeout");
    }
    else{
        printf("setsockopt(SO_RCVTIMEO) successful.\n");
    }

    printf("Port Scan:\n");
    printf("__PORTS__\n");
    for(int i = 1; i < 65535; ++i){
        tcp->tcph_dst_port = htons(i);
        ip->iph_chk_sum = csum((uint16_t *)datagram, ip->iph_tlen >> 1);
        tcp->tcph_chk_sum = temp_tcp_checsum();
        if(sendto(raw_socket,
                  datagram,
                  ip->iph_tlen,
                  0,
                  (struct sockaddr *)&dst_in,
                  sizeof(dst_in)) < 0) {
                    printf("sendto() error:\n");
        }
        tcp->tcph_chk_sum = 0;
        packetReturnFlagCheck();
    }    
}



