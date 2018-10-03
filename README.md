# Half-open-port-scanner
The application uses a raw socket to send out syn packets to check if a port is open on the specified target host.
It works in the following way:
  1. Send out SYN packet to target host,
  2. Upon receiving a ACK packet from the target, send out a FIN packet to close the connection immediately.

For sending, the application uses the packet_headers.h for the structs and for receiving, the appication uses 
the OS's Network-stack provided structs.

## Note 
To run this program, User must have root privileges. This is becauses the program uses raw sockets.
 
