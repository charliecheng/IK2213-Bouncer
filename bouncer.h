/* Global definitions for the port bouncer
 * Packet headers and so on
 */

#define _BSD_SOURCE 1
#define SIZE_ETHERNET 14
#define BUFFERSIZE 65533

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


/* PCAP declarations */
#include <pcap.h>

/* Standard networking declaration */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * The following system include files should provide you with the 
 * necessary declarations for Ethernet, IP, and TCP headers
 */

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <unistd.h>

/* Add any other declarations you may need here... */

unsigned short listeningport; //listening port
unsigned short serverport; //server port
char *listeningaddress;       //listening bouncer address
char *serverip;            //server ip address
static unsigned short Bouncerport=10000; //outgoing bouncer port

/*A function reports error and exits back to the shell*/
static void bail(const char *on_what){
    if (errno !=0){
        fputs(strerror(errno),stderr);
        fputs(": ",stderr);        
    }
    fputs(on_what,stderr);
    fputs("\n",stderr);
    exit(1);
}
unsigned short in_cksum(unsigned short *addr, int len);
unsigned short tcpchecksum(struct ip * sendingip, struct tcphdr * sendingtcp);
void addTCPtoList(unsigned short scr_port, unsigned short b_port, char* address);
unsigned short getFTPdataport(char *data);
int sendIPpacket(struct ip * ip, char * address, unsigned int dstport);
void savedataport(unsigned short scr_port, char *c_address, unsigned short ftpdataport);
char *replace_str(char *str, char *orig, char *rep);
char * portstring(char *data,char* cip);
struct node * searchTCPbportata(unsigned short scr_port, char *c_address);
void storeICMP(unsigned short seqId, char* addr);
