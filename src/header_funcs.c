#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "../include/my_headers.h"
#include "../include/half_open_scan_tcp.h"

/* Hacky code; need to find a better way */
bool INTERFACE_PRINTED = false;
bool TARGET_RESOLVED =	false;

void set_interface_ip(const char *interface_name, struct my_iph *snd_iph)
{
	struct ifaddrs *ifaddr, *ifa;
	char host[NI_MAXHOST];

	/* Get all interfaces addresses */
	if (getifaddrs(&ifaddr) == -1) {
		perror_exit("getifaddrs");
	}

	/* Walk the linked list of interface addresses to get the specified interface's address */
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}

		/* Address to name translation */	 
		int s = -1; 
		s = getnameinfo(ifa->ifa_addr, 
				sizeof(struct sockaddr_in),
				host, 
				NI_MAXHOST, 
				NULL, 
				0, 
				NI_NUMERICHOST);

		/* Get only the specified interface's name */
		if((strcmp(ifa->ifa_name, interface_name)==0)&&(ifa->ifa_addr->sa_family==AF_INET)) {
			if (s != 0) {
				perror_exit("getnameinfo()");
			}
			
			if (INTERFACE_PRINTED == false) {
				printf("\tInterface : <%s>\n",ifa->ifa_name );
				printf("\t  Address : <%s>\n", host);

				INTERFACE_PRINTED = true;
			}

			/* Set the source IP address of the given interface */
			struct sockaddr_in sa;
			inet_pton(AF_INET, host, &(sa.sin_addr));
			snd_iph->src_addr = sa.sin_addr.s_addr;
		}
	}	
}

void set_dest_ip(struct my_iph *snd_iph) 
{
	struct addrinfo hints;
	struct addrinfo *dest_info, *p;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;    		/* Get only IPv4 addresses */ 
	hints.ai_socktype = SOCK_STREAM;

	/* __Destination_resolution__ */
	int status = getaddrinfo(dest_host_name, NULL, &hints, &dest_info);
	if (status != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}

	printf("[*] Destination's IP address for %s:\n\t", dest_host_name);
    
	/* Loop through the results and use the first (dest addr) we can */
	char ip_str[INET_ADDRSTRLEN];
	for(p = dest_info; p != NULL; p = p->ai_next) {
		/* Get the pointer to the address itself */
		if (p->ai_family == AF_INET) { 
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			
			/* Set the destination IP address */
			snd_iph->dst_addr = ipv4->sin_addr.s_addr;
			
			/* Convert the IP to a string and print it */
			if (inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN) != NULL) {
				printf("  IPv4: %s\n", ip_str);
			} else {
				perror_exit("[#] Passed address is not in presentation format.");
			}
			
			break;
		}
	}
	free(dest_info);
}


void set_ip_hdr(struct my_iph *snd_iph)
{
	snd_iph->version = 4;			/* IPv4 */
	snd_iph->hdr_len = 5;			/* (5 * 4) = 20 bytes; no options */
	
	snd_iph->tos_precedence = 0x0;		// /* priority */
	snd_iph->tos_throughput = 0x0;		// /* low delay */
	snd_iph->tos_reliability = 0x0;		// /* high priority */
	snd_iph->tos_reserved = 0x0;

	snd_iph->tot_len = sizeof(struct my_iph) + sizeof(struct my_tcph);	/* No payload */
	snd_iph->identification = htons(54321); // test value;
	
	snd_iph->flg_rsrvd = 0x0;
	snd_iph->flg_DF = 0x0;
	snd_iph->flg_MF = 0x0;

	snd_iph->frg_offset = 0; 			/* Don't fragment */
	snd_iph->ttl = 255;				/* Max TTL */
	snd_iph->protocol = IPPROTO_TCP;	
	snd_iph->hdr_chk_sum = 0;			/* calc later */
	
	set_interface_ip("ens33", snd_iph);
	
	if (TARGET_RESOLVED == false) {
		set_dest_ip(snd_iph);
		TARGET_RESOLVED = true;
	}
}

void set_tcp_hdr(struct my_tcph *snd_tcph)
{
	snd_tcph->src_port = htons(atoi(COMMS_PORT));	
	snd_tcph->dst_port = htons(0);		/* Iterate through later */

	snd_tcph->seq_no = 0;	
	snd_tcph->ack_no = 0;			/* TCP ack is 0 in first packet */
	
	snd_tcph->rsvrd1 = 0x0;
	snd_tcph->data_offset = 5;		/* Assuming the minimal header length */

	snd_tcph->syn = 1;
	snd_tcph->urg = 0;
	snd_tcph->psh = 0;
	snd_tcph->rst = 0;
	snd_tcph->fin = 0;
	snd_tcph->ack = 0;

	snd_tcph->window = htons(5840);  
	snd_tcph->chksum = 0;			/* Will compute after header is completly set */
	
	snd_tcph->urg_ptr = 0; 
}

