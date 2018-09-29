#ifndef HALF_OPEN_SCAN_H
#define HALF_OPEN_SCAN_H

void portScanner(int argc, char *argv[]);
void error(const char* msg);

/* For sending */
extern struct ipheader *ip;
extern struct tcpheader *tcp;

extern struct sockaddr_in src_in, dst_in;

#endif 