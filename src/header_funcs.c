#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../include/my_headers.h"
#include "../include/half_open_scan_tcp.h"

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
			snd_iph->src_addr = ((struct sockaddr_in *)(ifa->ifa_addr->sa_data))->sin_addr.s_addr;
		}
	}	
}

void set_dest_ip(void) 
{
	struct addrinfo hints;
	struct addrinfo *dest_info, *p;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;    /* Get only IPv4 addresses */ 
	hints.ai_socktype = SOCK_STREAM;

	/* __Destination_resolution__ */
	int status = getaddrinfo(dest_host_name, NULL, &hints, &dest_info);
	if (status != 0) {
		printf("getaddrinfo: %s\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}

	printf("[*] Destination's IP address for %s:\n\t", dest_host_name);
    
	/* Loop through the results and use the first (dest addr) we can */
	char ipstr[INET6_ADDRSTRLEN] = {0};
	for(p = dest_info;p != NULL; p = p->ai_next) {
		void *addr = NULL;
		char *ipver = NULL;

		/* Get the pointer to the address itself */
		if (p->ai_family == AF_INET) { 
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			addr = &(ipv4->sin_addr);
			
			/* Set the destination IP address */
			snd_iph->dst_addr = ipv4->sin_addr.s_addr;
			
			
			/* convert the IP to a string and print it */
			ipver = "IPv4";
			inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
			if (ipstr[0] != 0) { // probably invalid check; need to verify
				printf("  %s: %s\n", ipver, ipstr);
			}
			
			break;
		}
	}
	free(dest_info);
}


void set_ip_hdr(void)
{
	snd_iph->version = 4;			/* IPv4 */
	snd_iph->hdr_len = 5;			/* (5 * 4) = 20 bytes; no options */
	
	snd_iph->tos_precedence = 0x01;		/* priority */
	snd_iph->tos_throughput = 0x01;		/* low delay */
	snd_iph->tos_reliability = 0x01;	/* high priority */
	snd_iph->tos_reserved = 0x0;

	snd_iph->tot_len = sizeof(struct my_iph) + sizeof(struct my_tcph);	/* No payload */			/* calc later */
	snd_iph->identification = htonl(54321); // test value;
	
	snd_iph->flg_rsrvd = 0x0;
	snd_iph->flg_DF = 0x0;
	snd_iph->flg_MF = 0x0;

	snd_iph->frg_offset = 0; //htons(0x4000);	/* Don't fragment */
	snd_iph->ttl = 255;		/* Max TTL */
	snd_iph->protocol = IPPROTO_TCP;		/* TCP */ /* Assigned numbers https://tools.ietf.org/html/rfc790 */
	snd_iph->hdr_chk_sum = 0;	/* calc later */
	
	//snd_iph->src_addr = atoi("192.168.1.5");
	set_interface_ip("wifi0");
	set_dest_ip();
}

void set_tcp_hdr(void)
{
	snd_tcph->src_port = htons(1234);//htons(atoi(COMMS_PORT));
	snd_tcph->dst_port = 0;		/* Iterate through later */

	snd_tcph->seq_no = 0;	//rand();	
	snd_tcph->ack_no = 0;		/* TCP ack is 0 in first packet */
	
	snd_tcph->rsvrd1 = 0x0;
	snd_tcph->data_offset = 5;	/* Assuming the minimal header length */

	snd_tcph->syn = 1;
	snd_tcph->urg = 0;
	snd_tcph->psh = 0;
	snd_tcph->rst = 0;
	snd_tcph->fin = 0;
	snd_tcph->ack = 0;

	snd_tcph->window = htons(5840); //htons(29200);
	snd_tcph->chksum = 0;		/* Will compute after header is completly set */
	
	snd_tcph->urg_ptr = 0; 
}

