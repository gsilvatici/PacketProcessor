# About the Project
A simple c++ console application for filtering network packets using pcapplusplus library
## Built with
- [pcapplusplus](https://pcapplusplus.github.io/docs/) 
# Getting started
## Prerequisites
This software is intended to run un Ubuntu Server 20.4  
    
Uses pcapplusplus library, See [installation](https://pcapplusplus.github.io/docs/install). 

## Installation

To compile the project from root directory:
```
cd build

cmake ..

make
```

# Usage
On build directory run the executable file pcap-convert:

```
./pcap-convert -h

./pcap-convert --vlan 5 -ip-version 4 --ttl 2 --dns-addr 10.0.0.1 --dns-port 5353 -i input.pcap -o output.pcap
```


# Author

Gabriel Silvatici.