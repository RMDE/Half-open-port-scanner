#include "../include/half_open_scan_tcp.h"

/*
  Usage:
    1. port_scanner_test <target hostname/IP>
*/
int main(int argc, char *argv[]){
    scan_tcp_ports(argc, argv);
    return 0;
}