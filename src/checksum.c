#include <netinet/in.h>

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "../include/my_headers.h"

uint16_t csum(const void *ip_header, const size_t length)
{
	/*  Checksum Algorithm (http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html)
	1. Set the sum to 0,
	2. Pad the data to an even number of bytes,
	3. Reinterpret the data as a sequence of 16-bit unsigned integers that are
		in network byte order,
	4. Calculate the sum of the integers, subtracting 0xffff whenever
		the sum => 0x10000, and
	5. Calculate the bitwise complement of the sum and set it as the checksum.
	*/
	uint16_t *accumalator = (uint16_t *)ip_header;
	uint32_t sum = 0;

	/* Take care of the first 16-bit even blocks */
	for (int i = 0; i < length/2; ++i) {
		sum += *(accumalator+i);
		if (sum >= 0x10000) {
			sum -= 0xffff;
		}
	}

	/* Handle the ending partial block */
	if (length % 2 != 0) {
		accumalator = accumalator+ length/2; /* Point accumalator to the end block */
		uint16_t end_block = 0;
		memcpy(&end_block, accumalator, sizeof(length));
		sum += ntohs(end_block);
		if (sum >= 0x10000) {
			sum -= 0xffff;
		}
	}

	/* Return the one's complement of the checksum in network byte order */
	return htons(~sum);
}

uint16_t tcp_chksum(struct my_iph *snd_iph, struct my_tcph *snd_tcph)
{
	struct psuedo_header psh;
	psh.src_addr = ntohl(snd_iph->src_addr);
	psh.dst_addr = ntohl(snd_iph->dst_addr);
	psh.rsvd = 0;
	psh.proto = IPPROTO_TCP;
	psh.len_tcp = htons(sizeof(struct my_iph));	/* No options, and no data */

	unsigned char *temp_tcp = malloc(sizeof(struct my_tcph) + sizeof(struct psuedo_header));
	memcpy(temp_tcp, (unsigned char *)&psh, sizeof(struct psuedo_header));
	long long index = sizeof(struct psuedo_header);
	memcpy(temp_tcp+index, (unsigned char *)snd_tcph, sizeof(struct my_tcph));

	return(csum(temp_tcp, sizeof(struct my_tcph) + sizeof(struct psuedo_header)));
}

