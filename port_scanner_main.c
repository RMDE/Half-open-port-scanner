/* For header structs, macros, and variables */
/*
#include<netinet/ip.h>
#include<netinet/ip_icmp.h>

*/
#include<netinet/tcp.h>

#include"packet_headers.h"
#include"half_open_scan.h"

/*
  Usage: 
    1. port_scanner_test <target hostname/IP>
    2. port_scanner_test <source hostname/IP> <source port> <target hostname/IP>  
*/
int main(int argc, char *argv[]){
    portScanner(argc, argv);
    return 0;
}