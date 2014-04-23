#include "bouncer.h"

/*link list for supporting concurrent session*/
struct node {
    unsigned short int icmpid;
    unsigned short int source_port;
    unsigned short int bouncer_port;
    unsigned short int ftp_data_port;
    char* address;
    struct node *next;
} *head;
static struct ip* staticip;
static struct tcphdr * statictcp;
char * portstringc(char *data, char* cip) ;
/*New node added to the link list for new TCP session*/
void addTCPtoList(unsigned short scr_port, unsigned short b_port, char* address) {
    struct node *temp;
    temp = (struct node *) malloc(sizeof (struct node));
    temp->source_port = scr_port;
    temp->bouncer_port = b_port;
    temp->address = malloc(64);
    strcpy(temp->address, address);
    temp->ftp_data_port=0;
    printf("New TCP node added. From: %s : %u\nUsing bouncer outgoing port: %u\n", temp->address, temp->source_port, temp->bouncer_port);

    if (head == NULL) {
        head = temp;
        head->next = NULL;
    } else {
        temp->next = head;
        head = temp;
    }

}

/*Search the given bouncer port in the link list to check if it is used.
 * This function is used in server part.
 */
struct node * searchTCPsource(unsigned short b_port) {
    struct node *temp;
    temp = head;
    while (temp != NULL) {
        if (temp->bouncer_port == b_port) {
            return temp;
        }
        temp = temp->next;
    }
    return NULL;
}

struct node * searchTCPsourcebydataport(unsigned short b_port) {
    struct node *temp;
    temp = head;
    while (temp != NULL) {
        if (temp->ftp_data_port == b_port) {
            return temp;
        }
        temp = temp->next;
    }
    return NULL;
}
//This function is used to find the previous ftp client data port

unsigned short searchc_dataport(unsigned short b_port) {
    struct node *temp;
    temp = head;
    while (temp != NULL) {
        if (temp->bouncer_port == b_port) {
            return temp->ftp_data_port;
        }
        temp = temp->next;
    }
    return 0;
}

//This function is used to store the ftp client data port

void savedataport(unsigned short scr_port, char *c_address, unsigned short ftpdataport) {
    struct node *temp;
    temp = head;
    while (temp != NULL) {
        if (temp->source_port == scr_port && !strcmp(c_address, temp->address)) {
            temp->ftp_data_port = ftpdataport;
        }
        temp = temp->next;
    }
}

/*Search the given client address and source port in the link list to check if they are used
 * This function is used in client part.
 */
struct node * searchTCPbport(unsigned short scr_port, char *c_address) {
    struct node *temp;
    temp = head;
    while (temp != NULL) {
        if (temp->source_port == scr_port && !strcmp(c_address, temp->address)) {
            return temp;
        }
        temp = temp->next;
    }
    return NULL;
}

struct node * searchTCPbportata(unsigned short scr_port, char *c_address) {
    struct node *temp;
    temp = head;
    while (temp != NULL) {
        if (temp->ftp_data_port == scr_port && !strcmp(c_address, temp->address)) {
            return temp;
        }
        temp = temp->next;
    }
    return NULL;
}

void storeICMP(unsigned short seqId, char* addr) {
    printf("Storing ICMP request [%d]", seqId);
    struct node* temp;
    temp = (struct node *) malloc(sizeof (struct node));
    temp->icmpid = seqId;
    temp->address = malloc(64);
    strcpy(temp->address, addr);

    if (head == NULL) {
        head = temp;
        head->next = NULL;
    } else {
        temp->next = head;
        head = temp;
    }
    return;
}

struct node * searchicmp(unsigned short scr_port) {
    struct node *temp;
    temp = head;
    while (temp != NULL) {
        if (temp->icmpid == scr_port) {
            return temp;
        }
        temp = temp->next;
    }
    return NULL;
}

void process_pkt(u_char *args, const struct pcap_pkthdr *header,
        const u_char *p) {

    /* Define pointers for packet's attributes */
    struct ip *ip;
    int protocol_in_ip;
    /* Check IP header*/
    ip = (struct ip*) (p + 14);
    //Check IP version
    //printf("IP packet version is %d\n", (ip->ip_v));
    if ((ip->ip_v) != 4) {
        printf("Not an IPv4 packet! Ignore the packet!\n");
        return;
    }
    //Check IP header length
    //printf("IP header length is %d\n", (ip->ip_hl * 4));
    if ((ip->ip_hl * 4) != 20) {
        printf("IP head is not 20! Ignore the packet!\n");
        return;
    }
    //check protocol inside the IP packet
    protocol_in_ip = ip->ip_p;
    if (protocol_in_ip == 1) {
        // printf("Protocol in the packet is ICMP\n");
    } else if (protocol_in_ip == 6) {
        // printf("Protocol in the packet is TCP\n");
    } else {
        printf("Protocol in the packet is not ICMP nor TCP. Ignore the packet!\n");
        return;
    }
    //check the TTL
    if ((ip->ip_ttl == 0)) {
        printf("The TTL of IP packet is 0. Discard the packet!");
        return;
    }
    //check evil bit
    if ((ip->ip_off) > 127) {
        printf("The evil bit is set! Ignore the packet!");
        return;
    };
    //check IP checksum
    unsigned short original_ip_checksum = ip->ip_sum;
    ip->ip_sum = 0;
    unsigned short true_ip_checkum = in_cksum((unsigned short *) ip, 20);
    if (original_ip_checksum != true_ip_checkum) {
        printf("Bad IP checksum. Ignore the packet!");
        return;
    }

    /* Check ICMP header*/
    if (protocol_in_ip == 1) {
        struct icmp *icmp;
        icmp = (struct icmp*) (p + 14 + 20);
        if (icmp->icmp_code != 0) {
            printf("code not 0\n");
            return;
        }
        unsigned short icmpchsum = icmp->icmp_cksum;
        icmp->icmp_cksum = 0;
        if (icmpchsum != in_cksum((unsigned short *) icmp, (ntohs(ip->ip_len) - 20))) {
            printf("bad icmp chsum\n");
            return;
        }
        icmp->icmp_cksum = icmpchsum;

        if (icmp->icmp_type != 0) {
            if (icmp->icmp_type != 8) {
                printf("type not  0or8\n");
                return;
            }
        }
        if (!(icmp->icmp_hun.ih_idseq.icd_id > -1 && icmp->icmp_hun.ih_idseq.icd_id < 65536)) {
            printf("ICMP sequence ID out of range. Ignore the packet!\n");
            return;
        }
        if (icmp->icmp_type == 8) {


            unsigned short id = icmp->icmp_hun.ih_idseq.icd_id;

            storeICMP(id, inet_ntoa(ip->ip_src));
            inet_aton(serverip, &(ip->ip_dst));
            inet_aton(listeningaddress, &(ip->ip_src));

            ip->ip_sum = 0;
            ip->ip_sum = in_cksum((unsigned short *) ip, ip->ip_hl * 4);

            if (sendIPpacket(ip, serverip, 0) < 0) {
                printf("\nSending ICMP packet fail! \n");
                return;
            }
            // printf("Changed IP packet sent\n");


            // printf("store the icmp seqid\n");

            //printf("ICMP packet sent, seq id: %d\n", icmp->icmp_hun.ih_idseq.icd_id);
            return;
        }
        if (icmp->icmp_type == 0) {
            //char* client_addr; 
            //	client_addr[0]='\0';
            //stpcpy(client_addr,fetchICMP(icmp->icmp_hun.ih_idseq.icd_id));
            //if (client_addr[0]=='\0') {
            //	printf("No record found. Not initalize by application. Discard the packet.\n");
            //	return;
            //}
            struct node *icmpt = searchicmp(icmp->icmp_hun.ih_idseq.icd_id);
            //   if (icmpt==NULL){printf("Failed to find\n");}
            //ip->ip_src = ip->ip_dst;
            inet_aton(listeningaddress, &(ip->ip_src));
            inet_aton(icmpt->address, &(ip->ip_dst));
            //memcpy(ip->ip_sum, in_cksum((unsigned short *)ip, ip->ip_hl*4), sizeof(ip->ip_sum));
            ip->ip_sum = 0;
            ip->ip_sum = in_cksum((unsigned short *) ip, ip->ip_hl * 4);

            if (sendIPpacket(ip, icmpt->address, 0) < 0) {
                //             printf("Sending ICMP REPLY packet fail!\n");
                return;
            }

            //            printf("ICMP REPLY packet sent, seq id: %d\n", icmp->icmp_hun.ih_idseq.icd_id);
            //deleteICMPnode(icmp->icmp_hun.ih_idseq.icd_id);
            return;
        }


    }
    /* Check TCP header*/
    if (protocol_in_ip == 6) {
        struct tcphdr *tcpheader;
        tcpheader = (struct tcphdr*) (p + 14 + 20);
        //check tcp header length
        int tcp_header_length = tcpheader->th_off * 4;
        if (tcp_header_length < 20 || tcp_header_length > 60) {
            printf("Invalid TCP header length! Ignore the packet!\n");
            return;
        }
        //NOTE!!!!Uncomment when hand in to subversion!!!
        //Check TCP checksum is not working well on the local machine!!!!!!!!！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
        //！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！1
        //check tcp checksum

        unsigned short original_tcp_checksum = tcpheader->th_sum;
        tcpheader->th_sum = 0;
        unsigned short true_tcp_checksum = tcpchecksum(ip, tcpheader);
        if (original_tcp_checksum != true_tcp_checksum) {
            printf("Invalid TCP header checksum! Ignore the packet!\n");
            return;
        }
        //Handle the packet from server
        if (strcmp(inet_ntoa(ip->ip_src), serverip) == 0) {
            //printf("server to bouncer: source port:%d  dst port:%d\n", ntohs(tcpheader->th_sport), ntohs(tcpheader->th_dport));
            struct node * record = searchTCPsource(ntohs(tcpheader->th_dport));
            if (record == NULL) {
                record = searchTCPsourcebydataport(ntohs(tcpheader->th_dport));
                //printf("Here comes the data from server!\n");
                if (record == NULL) {
                    printf("cant find the server requested port!!!\n");
                    return;
                }
            }
            //IP header part
            inet_pton(AF_INET, listeningaddress, &(ip->ip_src));
            inet_pton(AF_INET, record->address, &(ip->ip_dst));
            ip->ip_sum = 0;
            ip->ip_sum = in_cksum((unsigned short *) ip, 20);
            //Handle the ftp data transmission
            if (ntohs(tcpheader->th_sport) == 20) {
                // printf("changing for data transmisstion!\n");
                tcpheader->th_sport = htons(listeningport - 1);
                //printf("Writing source port:%d\n", listeningport - 1);
                tcpheader->th_dport = htons(record->ftp_data_port);
                //printf("Writing dst port:%d\n", record->ftp_data_port);
            } else { //Other TCP segment
                tcpheader->th_sport = htons(listeningport);
                tcpheader->th_dport = htons(record->source_port);
            }
            //printf("bouncer to client: source port:%d  dst port:%d\n", ntohs(tcpheader->th_sport), ntohs(tcpheader->th_dport));
            tcpheader->th_sum = 0;
            tcpheader->th_sum = tcpchecksum(ip, tcpheader);
            staticip = ip;
            statictcp = tcpheader;

        } else { //Handle the packet from client
            if (ntohs(tcpheader->th_dport) != listeningport) {
                if (ntohs(tcpheader->th_dport) != listeningport - 1) {
                    printf("Unknown request port\n");
                    return;
                }
            }
            //printf("From %s to %s\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
            //printf("client to bouncer: source port:%d  dst port:%d\n", ntohs(tcpheader->th_sport), ntohs(tcpheader->th_dport));
            struct node * record = searchTCPbport(ntohs(tcpheader->th_sport), inet_ntoa(ip->ip_src));

            if (record == NULL && tcpheader->th_flags == TH_SYN) {
                printf("\n\nNew client connection!\n");
                Bouncerport++;
                if (Bouncerport == listeningport || Bouncerport == listeningport - 1) {
                    Bouncerport = Bouncerport + 2;
                }
                addTCPtoList(ntohs(tcpheader->th_sport), Bouncerport, inet_ntoa(ip->ip_src));
               // printf("Saving client address %s\n", inet_ntoa(ip->ip_src));
                tcpheader->th_sport = htons(Bouncerport);
                tcpheader->th_dport = htons(serverport);
            } else if (record == NULL) {
                record = searchTCPbportata(ntohs(tcpheader->th_sport), inet_ntoa(ip->ip_src));
                if (record != NULL) {
                    if ((ntohs(tcpheader->th_dport)) == (listeningport - 1)) {
                        tcpheader->th_sport = htons(record->ftp_data_port);
                        tcpheader->th_dport = htons(serverport - 1);
                        // printf("TEST: data to server: %d, %d\n",record->source_port,serverport-1);
                    } else {
                        tcpheader->th_sport = htons(record->bouncer_port);
                        tcpheader->th_dport = htons(serverport);
                    }
                } else {
                    printf("Failed to find the client requested port!!\n");
                }
            } else {
                if (record->ftp_data_port==0){
                char *payload = malloc((ntohs(ip->ip_len) - tcpheader->th_off * 4) * sizeof (char));
                payload = (char *) (p + 14 + 20 + tcpheader->th_off * 4);
                int payloadsize = strlen(payload);
                if (payloadsize < 30 && payloadsize > 25) {
                   // printf("the beginning payload is %s\n", payload);
                }
                //if (strncmp(payload, "PORT ", 5) == 0){
                //printf("%s\nFrom %s to %s\n", payload,inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst));}
                if (strncmp(payload, "PORT 172", 8) == 0) {
                    printf("                                                 check!!   the wrong payload is %s\n", payload);
                    // if (sendIPpacket(staticip, inet_ntoa(*(struct in_addr*) &staticip->ip_dst), htons(statictcp->th_sport)) < 0) {
                    //   printf("Error occured while sending!\n");
                    // return;
                    //
                    //                   }
                    printf("                                                 check!!   retransmission\n");
                    return;
                }
                unsigned short ftpdport = getFTPdataport(payload);
                if (ftpdport != 0) {

                    savedataport(ntohs(tcpheader->th_sport), inet_ntoa(ip->ip_src), ftpdport);
                   // printf("Saving the data port %d\n This segment is: client to bouncer: source port:%d  dst port:%d\n", ftpdport, ntohs(tcpheader->th_sport), ntohs(tcpheader->th_dport));
                    //   printf("test: %d\n", record->ftp_data_port);
                   // printf("Before change the payload is %s\n", payload);
                    if (strncmp(payload, "PORT ", 5) == 0) {
                        char *tempip_b;
                        //printf("test1\n");
                        tempip_b = malloc(100 * sizeof (char));
                        strcpy(tempip_b, listeningaddress);
                        // printf("test2\n");
                        char *tempip2_b = replace_str(tempip_b, ".", ",");
                        //printf("test3\n");
                        char *tempip3_b = replace_str(tempip2_b, ".", ",");
                        //printf("test4\n");
                        char *tempip4_b = replace_str(tempip3_b, ".", ",");
                        //printf("test5\n");

                        //       char *clientip = inet_ntoa(ip->ip_src);
                        //printf("test6\n");
                        //                  printf("tempip4_b = %s\n", tempip4_b);
                        char *final = portstring(payload, tempip4_b);
                        char *finalc = portstringc(payload, tempip4_b);
                        //payload = malloc(sizeof (final));
                        if (strlen(final)!=payloadsize){
                            strcpy(payload, finalc);
                        }
                        else{strcpy(payload, final);}
                      //  printf("after change payload is %s\n", payload);
                        int delta = strlen(payload) - payloadsize;
                       // printf("delta is %d\n", delta);
                        //                    int afteripsize=(ntohs(ip->ip_len))+(int) delta;
                        //            printf("afteripsize is %d\n",afteripsize);
                        ip->ip_len = (unsigned short) htons(((int) ntohs(ip->ip_len)+(int) delta));
                    }

                   /* if (strncmp(payload, "EPRT ", 5) == 0) {
                        //EPRT |1|192.168.3.109|40244|
                        char *temppayload = malloc(100 * sizeof (char));
                        strcpy(temppayload, "EPRT |1|");
                        strcat(temppayload, listeningaddress);
                        char *temp1 = strstr(payload, "|") + 1; //1|192.168.3.109|59455|
                        char *temp2 = strstr(temp1, "|") + 1; //192.168.3.109|59455|
                        char *temp3 = strstr(temp2, "|"); //|59455|
                        strcat(temppayload, temp3);
                        //payload = malloc(sizeof (temppayload));
                        if (strlen(temp3)==payloadsize){
                        strcpy(payload, temppayload);}
                        else {char *temppayloadc = malloc(100 * sizeof (char));
                        strcpy(temppayloadc, "EPRT  |1|");
                        strcat(temppayloadc, listeningaddress);
                        char *temp1c = strstr(payload, "|") + 1; //1|192.168.3.109|59455|
                        char *temp2c = strstr(temp1c, "|") + 1; //192.168.3.109|59455|
                        char *temp3c = strstr(temp2c, "|"); //|59455|
                        strcat(temppayloadc, temp3c);
                        strcpy(payload, temppayloadc);
                        }
                        printf("after change payload is %s\n", payload);
                        int delta = strlen(payload) - payloadsize;
                        printf("delta is %d\n", delta);
                        //                    int afteripsize=(ntohs(ip->ip_len))+(int) delta;
                        //            printf("afteripsize is %d\n",afteripsize);
                        ip->ip_len = (unsigned short) htons(((int) ntohs(ip->ip_len)+(int) delta));


                    }*/

                    //printf("after: %s\nsize: %d\n", final, strlen(final));
                }}
                // printf("client request port:%d\n",(ntohs(tcpheader->th_dport)));
                if ((ntohs(tcpheader->th_dport)) == (listeningport - 1)) {
                    tcpheader->th_sport = htons(record->ftp_data_port);
                    tcpheader->th_dport = htons(serverport - 1);
                    // printf("TEST: data to server: %d, %d\n",record->source_port,serverport-1);
                } else {
                    tcpheader->th_sport = htons(record->bouncer_port);
                    tcpheader->th_dport = htons(serverport);
                }
                // printf("bouncer to server: source port:%d  dst port:%d\n", ntohs(tcpheader->th_sport), ntohs(tcpheader->th_dport));

            }
            //


            //tcpheader->th_dport = htons(serverport);
            inet_aton(listeningaddress, &(ip->ip_src));
            inet_aton(serverip, &(ip->ip_dst));
            ip->ip_sum = 0;
            ip->ip_sum = in_cksum((unsigned short *) ip, 20);
            tcpheader->th_sum = 0;
            tcpheader->th_sum = tcpchecksum(ip, tcpheader);


        }
        if (sendIPpacket(ip, inet_ntoa(*(struct in_addr*) &ip->ip_dst), htons(tcpheader->th_sport)) < 0) {
            printf("Error occured while sending!\n");
            return;

        }
        return;


    }

    /* Send processed packet */
}

/*Checksum Calculation Function*/
//From: http://www.winlab.rutgers.edu/~zhibinwu/html/c_prog.htm

unsigned short in_cksum(unsigned short *addr, int len) {
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;
    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16); /* add carry */
    answer = ~sum; /* truncate to 16 bits */
    return (answer);
}

/*The TCP pseudo header*/
struct pseudoheader {
    in_addr_t source_address;
    in_addr_t destination_addr;
    unsigned char zero;
    unsigned char protocol;
    unsigned short int length;
};

/*TCP checksum. Option field added.*/
//http://www.winpcap.org/pipermail/winpcap-users/2007-July/001984.html

unsigned short tcpchecksum(struct ip * sendingip, struct tcphdr * sendingtcp) {

    unsigned int total_len = ntohs(sendingip->ip_len);
    //printf("total ip packet size is %d\n",total_len);
    unsigned int ipheadersize = 20;
    unsigned int tcpheaderlength = sendingtcp->th_off * 4;
    //printf("total TCP header size is %d\n", tcpheaderlength);
    int tcpdatalen = total_len - tcpheaderlength - ipheadersize;
    //printf("total data size is %d\n",tcpdatalen);
    sendingtcp->th_sum = 0;
    struct pseudoheader psd_header;
    psd_header.source_address = sendingip->ip_src.s_addr;

    psd_header.destination_addr = sendingip->ip_dst.s_addr;

    psd_header.zero = htons(0);
    psd_header.protocol = IPPROTO_TCP;
    psd_header.length = htons(total_len - ipheadersize);
    //printf("psd header size is %d\n",sizeof(psd_header));
    unsigned short *checktcp = (unsigned short *) malloc((total_len - 20 + sizeof (psd_header)) * sizeof (unsigned short));
    ;


    memcpy((unsigned char *) checktcp, &psd_header, sizeof (psd_header));
    memcpy((unsigned char *) checktcp + sizeof (psd_header), (char *) sendingtcp, tcpheaderlength);

    //memcpy((unsigned char *) checktcp + sizeof (struct pseudoheader)+tcpheaderlength, (unsigned char *) sendingip + 40, tcpopt_len);
    memcpy((unsigned char *) checktcp + sizeof (psd_header) + tcpheaderlength, (char *) sendingtcp + tcpheaderlength, tcpdatalen);


    return in_cksum((unsigned short *) checktcp, total_len - 20 + 12);

}

char * portstring(char *data, char* cip) {
    char *tempd = malloc(100 * sizeof (char));

    //char tempc[100];
    //strcmp(tempc, cip);
    char *temp1 = strstr(data, ",") + 1; //PORT 192,168,1,1,149,85
    //printf("temp1: %s\n",temp1);
    char *temp2 = strstr(temp1, ",") + 1;
    //printf("temp2: %s\n",temp2);
    char *temp3 = strstr(temp2, ",") + 1;
    //printf("temp3: %s\n",temp3);
    char *temp4 = strstr(temp3, ","); //",149,85\r\n"
    strcpy(tempd, "PORT ");
    strcat(tempd, cip);
    strcat(tempd, temp4);
    return tempd;
}

char * portstringc(char *data, char* cip) {
    char *tempd = malloc(100 * sizeof (char));

    //char tempc[100];
    //strcmp(tempc, cip);
    char *temp1 = strstr(data, ",") + 1; //PORT 192,168,1,1,149,85
    //printf("temp1: %s\n",temp1);
    char *temp2 = strstr(temp1, ",") + 1;
    //printf("temp2: %s\n",temp2);
    char *temp3 = strstr(temp2, ",") + 1;
    //printf("temp3: %s\n",temp3);
    char *temp4 = strstr(temp3, ","); //",149,85\r\n"
    strcpy(tempd, "PORT  ");
    strcat(tempd, cip);
    strcat(tempd, temp4);
    return tempd;
}


unsigned short getFTPdataport(char *data) {
    if (strlen(data) < 5) {
        return 0;
    }
    if (strncmp(data, "PORT 1", 6) == 0) {
        char *temp1 = strstr(data, ",") + 1; //PORT 192,168,1,1,149,85
        //printf("temp1: %s\n",temp1);
        char *temp2 = strstr(temp1, ",") + 1;
        //printf("temp2: %s\n",temp2);
        char *temp3 = strstr(temp2, ",") + 1;
        //printf("temp3: %s\n",temp3);
        char *temp4 = strstr(temp3, ","); //",149,85\r\n"
        //printf("temp4: %s\n",temp4);
        char *temp5 = temp4 + 1; //"149,85\r\n"
        //printf("temp5: %s\n",temp5);
        int t5 = strlen(temp5); //
        char *temp6 = strstr(temp5, ","); //",85\r\n"
        char *temp7 = temp6 + 1; //"85\r\n"
        int t7 = strlen(temp7);
        int first = t5 - strlen(temp6);
        int second = t7 - 2;
        char *fpart = malloc(first * sizeof (char));
        fpart = temp5;
        char *spart = malloc(second * sizeof (char));
        spart = temp7;
        int a1 = strtoul(fpart, NULL, 0);
        int a2 = strtoul(spart, NULL, 0);
        //printf("a1 is %d\n", a1);
        //printf("a2 is %d\n", a2);
        //printf("port is %d\n", 256 * a1 + a2);
        return (unsigned short) (256 * a1 + a2);
    }/*
    if (strncmp(data, "EPRT ", 5) == 0) {
        char *temp1 = strstr(data, "|") + 1; //1|192.168.3.109|59455|
        char *temp2 = strstr(temp1, "|") + 1; //192.168.3.109|59455|
        char *temp3 = strstr(temp2, "|") + 1; //59455|
        int len3 = strlen(temp3);
        char *number = malloc((len3 - 3) * sizeof (char));
        memcpy(number, temp3, len3 - 3);
        int a1 = strtoul(number, NULL, 0);
        printf("%d\n",a1);
        return a1;
    }*/
    return 0;

}

int sendIPpacket(struct ip * ip, char * address, unsigned int dstport) {
    int s; //socket
    struct sockaddr_in dst_addr;
    s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s == -1) {
        bail("socket()");
    }
    memset(&dst_addr, 0, sizeof (dst_addr));
    dst_addr.sin_family = AF_INET;
    if (dstport != 0) {
        dst_addr.sin_port = htons(dstport);
    }
    dst_addr.sin_addr.s_addr = inet_addr(address);
    int optval = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &optval, sizeof (int));
    if (sendto(s, ip, ntohs(ip->ip_len), 0, (struct sockaddr *) &dst_addr, sizeof (struct sockaddr)) < 0) {
        perror("sendto");
        return -1;
    }
    close(s);
    return 1;

}

char *replace_str(char *str, char *orig, char *rep) {
    static char buffer[4096];
    char *p;

    if (!(p = strstr(str, orig))) // Is 'orig' even in 'str'?
        return str;

    strncpy(buffer, str, p - str); // Copy characters from 'str' start to 'orig' st$
    buffer[p - str] = '\0';

    sprintf(buffer + (p - str), "%s%s", rep, p + strlen(orig));

    return buffer;
}
