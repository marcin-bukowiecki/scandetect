scandetect
==========================

This version is currently in tests...

## Overview

Scandetect detects network and port scan. Its written in Scala and Java. 
It can run as a standalone application where you can detect port scans or with 
another machine which acts as a honeypot where you can detect network scans.

## Requirements

Scandetect requires MongoDB as a backend database. It also requires jNetPcap library
which you can download from http://jnetpcap.com/download or find it in the lib folder. After downloading it you must 
put the jnetpcap.dll file in your Windows/System and Windows/System32 folder. This program
was tested only on Windows 7 64 bit.

## Supported protocols

Scandetect supports detecting scans of following protocols:

- TCP
- SCTP (only if you installed the SCTP driver for Windows)
- IP
- UDP
- ARP
- ICMP

## Detecting scanning tools

Scandetect will also try to detect software which was used in scanning your PC. 
Actually it detects from 5: 

- NMAP
- ZMAP
- Masscan
- Evilscan
- Angry IP Scanner

## How it works?

Scandetect is using jNetPcap to capture incoming and outcoming packets on host machine. Then it extracts packet data
and saves it in the Mongo database. While program is running Scandetect will analyze saved packets to check is there was a
port scan.

The detection is done using simple Random Forest classification according to 7 features.

1. Out machine was initializing the connection - this can be 1 or 0. 1 when our machine initialized the connection.
This is checked because typically unknown IP addresses are scanning our ports (so they are initializing the connection).

2. Data transfer - 1 when data was transferred from given IP address, 3 when no data was transferred from given IP address,
2 for both conditions.

3. Tried to connect to an closed port after open - typically network services are searching for an open port 
so they should not check the next port while a port scan is scanning a range of ports. Value 1 or 0.

4. Connection attempts to closed ports threshold - 1 below threshold, 2 at threshold, 3 over threshold

5. Neighboring port factor

6. Used open ports to transferred packets factor

7. Connection attempts to closed ports factor

