# Half-open-port-scanner
The application uses a raw socket to send out syn packets to check if a port is open on the specified target host.
It works in the following way:
  1. Send out SYN packet to target host,
  2. Upon receiving an ACK packet from the target, a FIN packet is sent automatically to close the connection.

For sending, the application uses the packet_headers.h for the structs and for receiving, the application uses 
the OS's Network-stack provided structs.

# Output
## Verbose and without timeout, i.e, recvfrom() is blocking

![](/imgs/output1.png)
![](/imgs/wireshark1.png)

## Non verbose

![](/imgs/output2.png)


## Note 
To run this program, User must have root privileges. This is becauses the program uses raw sockets.
