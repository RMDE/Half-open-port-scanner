# Half-open-port-scanner
The application uses a raw socket to send out syn packets to check if a port is open on the specified target host.
It works in the following way:
  1. Send out SYN packet to target host,
  2. Upon receiving an ACK packet from the target, a FIN packet is sent automatically to close the connection.

For sending, the application uses the packet_headers.h for the structs and for receiving, the application uses 
the OS's Network-stack provided structs.

# Output
## Verbose and without timeout, i.e, recvfrom() is blocking
To see for which ports a response has been received, uncomment half_open_scan.c : 74.
![](/imgs/output1.png)
![](/imgs/wireshark1.png)

## Non verbose and with timeout, i.e, recvfrom is non-blocking when there is no data to be read

![](/imgs/output_with_timeout.png)
![](/imgs/wireshark2.png)

## Note 
1. To run this program, User must have root privileges. This is becauses the program uses raw sockets.
2. Your system must be little endian. If not you will have to modify the packet header formats.

## Dev notes
1. Must change the packet header definitions to allow headersInit() to set flags through enums instead of manually setting them.  
