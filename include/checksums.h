#ifndef CHECKSUMS_H
#define CHECKSUMS_H

#include <stdlib.h>
#include <inttypes.h>

uint16_t tcp_chksum(struct my_iph *snd_iph, struct my_tcph *snd_tcph);
uint16_t csum(const void *ip_header, const size_t length);

#endif