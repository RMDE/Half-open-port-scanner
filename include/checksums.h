#ifndef CHECKSUMS_H
#define CHECKSUMS_H

#include <stdlib.h>
#include <inttypes.h>

uint16_t ip_chksum(const void *ip_header, const size_t length);

#endif