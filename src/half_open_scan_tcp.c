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
#include "../include/header_funcs.h"
#include "../include/checksums.h"
#include "../include/socket_related.h"


#define MAX_PCKT_LEN 8192

char *dest_host_name;

int g_sockfd;

/* Struct filled while sending the packet */
struct my_iph *snd_iph;
struct my_tcph *snd_tcph;

/* Packet to be sent to scan for ports */
char scanning_packet[MAX_PCKT_LEN];

void perror_exit(const char *s)
{
	fprintf(stderr, "%s: %s\n", s, strerror(errno));
	exit(EXIT_FAILURE);
}

void scan_tcp_ports(int argc, char **argv)
{
	if (argc == 2) {
		dest_host_name = argv[1];
	}

	set_raw_socket();
	set_socket_options();

	create_thread(LISTENER_THREAD);
	create_thread(SCANNER_THREAD);

	pthread_join(g_listener_thread, NULL);
	pthread_join(g_scanner_thread, NULL);
}

void scanner(void)
{
	memset(scanning_packet, 0 , MAX_PCKT_LEN);

	snd_iph = (struct my_iph *)scanning_packet;
	snd_tcph = (struct my_tcph *)(scanning_packet + sizeof(struct my_iph));

	set_ip_hdr();
	set_tcp_hdr();

	printf("PORT SCAN\n");
	printf("__PORTS__\n");

	for (int i = 0; i < 65535; ++i) {
		snd_tcph->dst_port = htons(i);
		snd_iph->hdr_chk_sum = ip_chksum(scanning_packet, snd_iph->tot_len);

	}

}

void listener(void)
{

}



/*

gcc -g half_open_scan_tcp.c main.c thread_related.c -o test -Wall -pthread

*/