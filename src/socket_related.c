#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>
#include <sys/time.h>

#include "../include/half_open_scan_tcp.h"

void set_raw_socket(void)
{
	g_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (g_sockfd == -1) {
		perror_exit("[#] Unable to create socket\n");
	} else {
		printf("[*] Socket created successfully\n");
	}
}

void set_socket_options(void)
{
	/* Tell the system that we are providing the IP header */
	if (setsockopt(g_sockfd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0) {
		perror_exit("[#] Unable to set socket option\n");
	} else {
		printf("[*] Succesfully set IP_HDRINCL option\n");
	}

	if (setsockopt(g_sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0){
		perror_exit("[#] setsockopt(SO_REUSEADDR) failed");
	} else {
		printf("[*] setsockopt(SO_REUSEADDR) successful.\n");
	}
}