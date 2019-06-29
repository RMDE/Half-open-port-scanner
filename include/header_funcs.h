#ifndef HEADER_FUNCS_H
#define HEADER_FUNCS_H

#include "../include/my_headers.h"

void set_ip_hdr(struct my_iph *snd_iph);
void set_tcp_hdr(struct my_tcph *snd_tcph);
void set_dest_ip(struct my_iph *snd_iph);
void set_interface_ip(const char *interface_name, struct my_iph *snd_iph);



#endif