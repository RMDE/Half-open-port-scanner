#ifndef HALF_OPEN_SCAN_TCP
#define HALF_OPEN_SCAN_TCP

#define COMMS_PORT "9897"

extern struct my_iph *snd_iph;
extern struct my_tcph *snd_tcph;

extern char *dest_host_name;

extern int g_sockfd;

void scan_tcp_ports(int argc, char **argv);
void perror_exit(const char *s);

void* scanner(void *);
void* listener(void *);

#endif