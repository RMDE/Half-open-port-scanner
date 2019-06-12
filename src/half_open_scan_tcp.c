#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "../include/my_headers.h"
#include "../include/thread_related.h"

#define COMMS_PORT "9897"

in_addr_t *dst_ip;
int g_sockfd;

/* Target's network info */
struct sockaddr_in dst_addr;

/* struct filled while sending the packet */
struct my_iph snd_iph;
struct my_tcph snd_tcph;


void perror_exit(const char *s) 
{
    fprintf(stderr, "%s: %s\n", s, strerror(errno));
    exit(EXIT_FAILURE);
}

void set_interface_ip(char *interface_name)
{
	struct ifaddrs *ifaddr, *ifa;
	//int family;
	int s;
	char host[NI_MAXHOST];

	/* get all interfaces addresses */
	if (getifaddrs(&ifaddr) == -1) {
		perror_exit("getifaddrs");
	}

	/* walk the linked list of interface addresses to get the specified interface's address */
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		/* address to name translation */	  
		s = getnameinfo(ifa->ifa_addr, 
				sizeof(struct sockaddr_in),
				host, 
				NI_MAXHOST, 
				NULL, 
				0, 
				NI_NUMERICHOST);

		/* get only the specified interface's name */
		if((strcmp(ifa->ifa_name, interface_name)==0)&&(ifa->ifa_addr->sa_family==AF_INET)) {
			if (s != 0) {
				perror_exit("getnameinfo()");
			}
			
			printf("\tInterface : <%s>\n",ifa->ifa_name );
			printf("\t  Address : <%s>\n", host); 

			/* set the source IP address of the given interface */
			snd_iph.src_addr = ((struct sockaddr_in *)(ifa->ifa_addr->sa_data))->sin_addr.s_addr;
		}
	}	
}

void set_ip_hdr(void)
{
	snd_iph.version = 4;
	snd_iph.hdr_len = 4;	/* 20 bytes */ /* change to calc by div by 5 */
	
	snd_iph.tos_precedence = 0x001;	/* priority */
	snd_iph.tos_throughput = 1;	/* low delay */
	snd_iph.tos_reliability = 1;	/* high priority */
	snd_iph.tos_reserved = 0;

	snd_iph.tot_len = 0;	/* calc later */
	snd_iph.identification = 0;
	
	snd_iph.flg_rsrvd = 0;
	snd_iph.flg_DF = 0;
	snd_iph.flg_MF = 0;
	
	snd_iph.frg_offset = 0;
	snd_iph.ttl = 255;
	snd_iph.protocol = 6;	/* TCP */ /* Assigned numbers https://tools.ietf.org/html/rfc790 */
	snd_iph.hdr_chk_sum = 0;	/* calc later */
	
	//snd_iph.src_addr = atoi("192.168.1.5");
	set_interface_ip("wifi0");
	snd_iph.dst_addr = atoi("172.217.163.132");	/* test */
}

void set_tcp_hdr()
{
	snd_tcph.src_port = atoi(COMMS_PORT);
	snd_tcph.dst_port = 0;		/* Iterate through later */

	snd_tcph.seq_no = rand();
	snd_tcph.ack_no = 0;		/* TCP ack is 0 in first packet */
	
	snd_tcph.data_offset = 5;	/* Assuming the minimal header length */

	snd_tcph.ack = 1;
	snd_tcph.urg = 0;
	snd_tcph.psh = 0;
	snd_tcph.rst = 0;
	snd_tcph.fin = 0;

	snd_tcph.window = htons(29200);
	snd_tcph.chksum = 0;		/* Will compute after header is completly set */
	
	snd_tcph.urg_ptr = 0; 
}

void scanner(void)
{
	set_ip_hdr();
	set_tcp_hdr();

}

void listener(void)
{

}

void wrapper_setsockopt_iplvl(int sock_opt)
{
	int retv = -1;
	retv = setsockopt(g_sockfd, IPPROTO_IP, sock_opt, &(int){1}, sizeof(int));

	if (retv == -1) {
		perror_exit("Unable to set socket option");
	}

	switch (sock_opt)
	{
	case IP_HDRINCL:
		printf("IP_HDRINCL option set successfully\n");
		break;
	
	default:
		break;
	}
}

void set_raw_socket(void)
{
	g_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (g_sockfd == -1) {
		perror_exit("[#] Unable to create socket\n");
	} else {
		printf("[*] Socket created successfully\n");
	}
}


in_addr_t* read_dst_ip(int argc, char **argv) 
{
	
	if (argc < 2 || argc > 3) {
		printf("[*] Invalid parameters\n");
		exit(EXIT_FAILURE);
	}

	/* Use the struct to store the converted IP address */
	struct sockaddr_in *temp_addr = malloc(sizeof(struct sockaddr_in));

	/* If only IP address of destination is given */
	if (argc == 2) {
		inet_pton(AF_INET, argv[1], &(temp_addr->sin_addr));
	}

	return &(temp_addr->sin_addr.s_addr);
}

void scan_tcp_ports(int argc, char **argv) 
{
	
	dst_ip = read_dst_ip(argc, argv);

	set_raw_socket();
	
	/* don't let sys add the IP header */
	wrapper_setsockopt_iplvl(IP_HDRINCL);

	create_thread(LISTENER_THREAD);
	create_thread(SCANNER_THREAD);



	pthread_join(g_listener_thread, NULL);
	pthread_join(g_scanner_thread, NULL);

}

/*

gcc -g half_open_scan_tcp.c main.c thread_related.c -o test -Wall -pthread

*/