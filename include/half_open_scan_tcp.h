#ifndef HALF_OPEN_SCAN_TCP
#define HALF_OPEN_SCAN_TCP

#define COMMS_PORT "9897"

extern char *dest_host_name;

extern int g_sockfd;

void scan_tcp_ports(int argc, char **argv);
void perror_exit(const char *s);

void* scanner(void *);
void* listener(void *);

#endif