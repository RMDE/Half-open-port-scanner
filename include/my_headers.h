#ifndef MY_HEADERS_H
#define MY_HEADERS_H

#include <inttypes.h>

struct my_iph 
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t 	hdr_len:        4;      /* in multiples of 5 */
	uint8_t		version:        4;      /* 4 for IPv4, 6 for IPv6 */
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t		version:        4;      /* 4 for IPv4, 6 for IPv6 */
	uint8_t 	hdr_len:        4;      /* in multiples of 5 */
#endif

	/*     
                --------IP Type of Service-------- 
		
                	Precedence
		111 - Network Control
		110 - Internetwork Control
		101 - CRITIC/ECP
		100 - Flash Override
		011 - Flash
		010 - Immediate
		001 - Priority
		000 - Routine

			Throughput
		0 = Normal Delay
		1 = Low Delay

			Reliability
		0 = Normal Throughput
		1 = High Throughput
	*/
/* Can simplify this by just using one var to store flags but trying this for fun */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t		tos_reserved:	 	2;
	uint8_t		tos_reliability: 	1;
	uint8_t		tos_throughput: 	1;
        uint8_t         tos_delay:              1;
	uint8_t		tos_precedence: 	3;
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t		tos_precedence: 	3;
        uint8_t         tos_delay:              1;
	uint8_t		tos_throughput: 	1;
	uint8_t		tos_reliability: 	1;
	uint8_t		tos_reserved:	 	2;
#endif

	uint16_t	tot_len;
	uint16_t	identification;		/* used to aid in assembling the fragments of a datagram */

#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t		flg_rsrvd: 	1;	/* must be zero */
	uint8_t		flg_DF: 	1;	/* Don't Fragment */
	uint8_t		flg_MF: 	1;	/* More Fragments */
	uint16_t 	frg_offset: 	13;	/* measured in units of 8 octets (64 bits).  The first fragment has offset zero. */
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t		flg_rsrvd: 	1;	/* must be zero */
	uint8_t		flg_DF: 	1;	/* Don't Fragment */
	uint8_t		flg_MF: 	1;	/* More Fragments */
	uint16_t 	frg_offset: 	13;	/* measured in units of 8 octets (64 bits).  The first fragment has offset zero. */
#endif

	uint8_t		ttl;
	uint8_t		protocol;	/* next level protocol used in the data portion of the internet datagram. */
	uint16_t	hdr_chk_sum;	/* checksum of header only */

	uint32_t	src_addr;
	uint32_t	dst_addr;
	
	/* optional data & padding should be below */
};

struct my_tcph
{
	uint16_t	src_port;
	uint16_t	dst_port;

	uint32_t	seq_no;
	uint32_t	ack_no;

# if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t		rsvrd1:		4;	/* must be zero */
	uint8_t		data_offset:	4;
#endif 

# if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t		data_offset: 	4;
	uint8_t		rsvd1:		4;
#endif
	/*
				flags
		---------------------------------------------------
			Control Bits:  6 bits (from left to right):
		URG:  Urgent Pointer field significant
		ACK:  Acknowledgment field significant
		PSH:  Push Function
		RST:  Reset the connection
		SYN:  Synchronize sequence numbers
		FIN:  No more data from sender
	*/
/* Can simplify this by just using one var to store flags but trying this for fun */
# if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t		fin:	1;      
	uint8_t		syn:	1;
	uint8_t		rst:	1;
	uint8_t		psh:	1;
	uint8_t		ack:	1;
	uint8_t		urg:	1;
	uint8_t		rsvrd2:	2;
#endif 

# if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t		rsvrd2:	2;
	uint8_t		urg:	1;
	uint8_t		ack:	1;
	uint8_t		psh:	1;
	uint8_t		rst:	1;
	uint8_t		syn:	1;
	uint8_t		fin:	1;      /* need to look into padding (reserved as total is 6 bits) */
#endif

	uint16_t	window;
	uint16_t	chksum;		/* The checksum also covers a 96 bit pseudo header
						conceptually prefixed to the TCP header. */
        uint16_t        urg_ptr;

	/* Options and data should be added below. */
};

struct psuedo_header
{
	uint32_t 	src_addr;
	uint32_t 	dst_addr;
	uint8_t 	rsvd;
	uint8_t 	proto;
	uint16_t 	len_tcp;
};

#endif