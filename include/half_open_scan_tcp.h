#ifndef HALF_OPEN_SCAN_TCP
#define HALF_OPEN_SCAN_TCP

void scan_tcp_ports(int argc, char **argv);

void *scanner();
void *listener();

#endif