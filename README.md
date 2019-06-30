# Half-open-port-scanner 
The application uses a raw socket to send out SYN packets to check if a port is open on the specified target host.
It works in the following way:
  1. Send out SYN packet to target host,
  2. Upon receiving an ACK packet from the target, a FIN packet is sent automatically to close the connection.

The application uses custom IP and TCP headers defined in include/my_headers.h

# Output
## My Application 
![](port_scanner.PNG)

## NMAP Result
![](nmap.PNG)

## Note 
To run this program, User must have root privileges. This is becauses the program sends out raw packets .
