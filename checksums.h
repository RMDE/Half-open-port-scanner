#ifndef CHECKSUM_H
#define CHECKSUM_H

#include<inttypes.h>

uint16_t csum(uint16_t *buf, int len);
short checksum_calc(unsigned short *addr, unsigned int count);
short temp_tcp_checsum();

#endif