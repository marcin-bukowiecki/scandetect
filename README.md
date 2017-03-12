scandetect
==========================

This version is currenlty in tests...

## Overview

Scandetect detects network and port scan. Its writen in Scala and Java. 
It can run as a standalone application where you can detect port scans or with 
another machine which acts as a honeypot where you can detect network scans.

## Requirements

Scandetect requires MongoDB as a backend database. It also requires jNetPcap library
which you can download from http://jnetpcap.com/download. After downloading it you must 
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
