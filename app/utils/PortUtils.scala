package utils

object PortUtils {

  val NO_PORT = -1

  val SPECIAL_PORTS_DATA = Seq(
    "1,true,true,false,TCP Port Service Multiplexer (TCPMUX)",
    "5,true,true,false,Remote job entry",
    "7,true,true,false,Echo Protocol",
    "18,true,true,false,Message Send Protocol",
    "20,true,true,false,FTP data transfer",
    "21,true,true,true,FTP control",
    "22,true,true,true,Secure shell",
    "23,true,true,false,Telnet protocol—unencrypted text communications",
    "25,true,true,false,Simple Mail Transfer Protocol (SMTP), used for e-mail routing between mail servers",
    "29,true,true,false,MSG ICP",
    "37,true,true,false,Time Protocol",
    "42,true,true,false,Host Name Server Protocol",
    "43,true,true,false,WHOIS protocol",
    "49,true,true,false,TACACS+ Login Host protocol",
    "53,true,true,false,Domain Name System",
    "69,true,true,false,Trivial File Transfer Protocol (TFTP)",
    "70,true,true,false,Gopher protocol",
    "79,true,true,false,Finger protocol",
    "80,false,true,true,QUIC",
    "108,true,true,false,SNA Gateway Access Server",
    "109,true,true,false,Post Office Protocol v2",
    "110,true,true,false,Post Office Protocol v3",
    "115,true,false,false,Simple File Transfer Protocol",
    "118,true,true,false,Structured Query Language (SQL) Services",
    "119,true,false,false,Network News Transfer Protocol (NNTP), retrieval of newsgroup messages",
    "137,true,true,false,NetBIOS Name Service",
    "139,true,true,false,NetBIOS Session Service",
    "143,true,false,false,Internet Message Access Protocol (IMAP), management of email messages",
    "156,true,true,false,SQL Service",
    "161,false,true,false,Simple Network Management Protocol (SNMP)",
    "179,true,false,false,Border Gateway Protocol (BGP)",
    "194,true,true,false,Internet Relay Chat (IRC)",
    "389,true,true,false,Lightweight Directory Access Protocol (LDAP)",
    "443,true,true,true,Hypertext Transfer Protocol over TLS/SSL",
    "444,true,true,false,Simple Network Paging Protocol (SNPP)",
    "445,true,false,false,Microsoft-DS Active Directory, Windows shares",
    "546,true,true,false,DHCPv6 client",
    "547,true,true,false,DHCPv6 server",
    "563,true,true,false,NNTP over TLS/SSL (NNTPS)",
    "1080,true,true,false,SOCKS proxy"
  )

}
