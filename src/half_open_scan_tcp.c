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
#include "../include/half_open_scan_tcp.h"

#define MAX_PCKT_LEN 8192
#define IP_PCKT_MAX_LEN 65536
#define PORT_RANGE 65536

struct psuedo_header psh;

char *dest_host_name;

int g_sockfd;

int g_port_counter = 0;

/* Ineffecient but to do for now */
int discovered_ports[PORT_RANGE] = {0};

void perror_exit(const char *s)
{
	fprintf(stderr, "%s: %s\n", s, strerror(errno));
	exit(EXIT_FAILURE);
}

void scan_tcp_ports(int argc, char **argv)
{
	/* Get the destination host name */
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

void* scanner(__attribute__((unused)) void *unused)
{
	/* Packet to be sent to scan for ports */
	char scanning_packet[MAX_PCKT_LEN];
	
	/* Zero out the packet */
	memset(scanning_packet, 0 , MAX_PCKT_LEN);

	struct my_iph *snd_iph = (struct my_iph *)scanning_packet;
	struct my_tcph *snd_tcph = (struct my_tcph *)(scanning_packet + sizeof(struct my_iph));

	set_ip_hdr(snd_iph);
	set_tcp_hdr(snd_tcph);

	/* Set up the destination address struct */
	struct sockaddr_in p_dest_addr;
	memset((char *)&p_dest_addr, 0, sizeof(struct sockaddr_in));
	p_dest_addr.sin_family = AF_INET;	/* IPv4 address */
	p_dest_addr.sin_port = htons(atoi(COMMS_PORT)); 
	p_dest_addr.sin_addr.s_addr = snd_iph->dst_addr;

	printf("[*] Port Scan Started\n");
	printf("------------------------\n");
	printf("------------------------\n");

	for (int i = 1; i < 65535; ++i) {
		snd_tcph->dst_port = htons(i);
		snd_iph->hdr_chk_sum = csum(scanning_packet, snd_iph->tot_len);
		snd_tcph->chksum = tcp_chksum(snd_iph, snd_tcph);
		
		if (sendto(g_sockfd, scanning_packet, snd_iph->tot_len,
			0, (struct sockaddr *)&p_dest_addr, sizeof(p_dest_addr)) <= 0) {
			perror("sendto() error:");
			printf("fail\n");
		}

		snd_tcph->chksum = 0;

		/* Sleep before sending again */
		usleep(100000);
	}

	return NULL;
}

void close_connection(uint16_t port, struct sockaddr_storage from_addr)
{
	/* Packet to be sent to close a connection to a port  */
	char closing_packet[MAX_PCKT_LEN];
	
	/* Zero out the packet */
	memset(closing_packet, 0 , MAX_PCKT_LEN);

	/* Struct to send for closing the connection */
	struct my_iph *close_iph = (struct my_iph *)closing_packet;
	struct my_tcph *close_tcph = (struct my_tcph *)(closing_packet + sizeof(struct my_iph));

	set_ip_hdr(close_iph);
	set_tcp_hdr(close_tcph);

	/* Hacky code; need to find a better approach */
	close_iph->dst_addr = ((struct sockaddr_in *)&from_addr)->sin_addr.s_addr;

	/* Close the connection to the port */
	close_tcph->fin = 0x1;	
	close_tcph->ack = 0x0;

	close_tcph->dst_port = htons(port);
	close_iph->hdr_chk_sum = csum(closing_packet, close_iph->tot_len);
	close_tcph->chksum = tcp_chksum(close_iph, close_tcph);
	
	if (sendto(g_sockfd, closing_packet, close_iph->tot_len,
		0, (struct sockaddr *)&from_addr, sizeof(from_addr)) <= 0) {
		perror("sendto()");
	}

	close_tcph->chksum = 0;
}


void* listener(__attribute__((unused)) void *unused)
{
	for (;;) {
		/* Packet received as reply from target */
		char response_packet[IP_PCKT_MAX_LEN];

		/* Zero out the buffer */
		memset(response_packet, 0, IP_PCKT_MAX_LEN);

		/* Holds the destination network information */
		struct sockaddr_storage from_addr;
		socklen_t from_len = 0;

		/* Recieve the response from the target */
		int byte_count = recvfrom(g_sockfd, response_packet, MAX_PCKT_LEN, 0, (struct sockaddr *)&from_addr, &from_len);
		if (byte_count < 0 && errno != EAGAIN) {
			perror("recvfrom: ");
			continue;
		}

		/* Get the pointers to the IP & TCP headers */
		struct my_iph *recv_iph = (struct my_iph*)response_packet;
		struct my_tcph *recv_tcph = (struct my_tcph*)(response_packet + 4 * (recv_iph->hdr_len));


		/* Check if the message is for COMMS_PORT port */
		if (recv_tcph->dst_port != ntohs(atoi(COMMS_PORT))) {
			continue;
		}

		/* Check if we the port is closed (denoted by a rst flag) */
		if (recv_tcph->rst == 0x01) {
			continue;
		}

		/* Check if the target is closing the connection (done if we haven't responded to it's acks) */
		if (recv_tcph->fin == 0x01) {
			continue;
		}

		/* Check to see if we recived an ACK for a port */
		if (recv_tcph->ack == 0x01) {
			//printf("\nChecking port %d\n", ntohs(recv_tcph->src_port));
			/* Check if ack is retransmitted due to delayed fin */
			if (discovered_ports[ntohs(recv_tcph->src_port) == 1]) {
				continue;
			}
			printf("[*] Port: %d is open.\n", ntohs(recv_tcph->src_port));

			/* Close the connection */
			discovered_ports[ntohs(recv_tcph->src_port)] = 1;
			close_connection(ntohs(recv_tcph->src_port), from_addr);
		}
	}

	return NULL;
}