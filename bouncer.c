/* Port Bouncer
 * To be called as nbouncer local_ip local_port remote_ip remote_port
 */

#include "bouncer.h"


void process_pkt(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet);

int main(int argc, char *argv[]) {
    if (argc != 6) {
        bail("Invalid command arguments.");
    }
    listeningaddress = argv[2];
    listeningport = strtoul(argv[3], NULL, 0);
    serverip = argv[4];
    serverport = strtoul(argv[5], NULL, 0);
    if (listeningport == 0 || serverport == 0) {
        bail("Invalid command arguments.");
    }
    printf("Bouncer listening address: %s\n", listeningaddress);
    printf("Bouncer listening port: %u\n", listeningport);
    printf("Server address: %s\n", serverip);
    printf("Server port: %u\n", serverport);
    /* Include here your code to initialize the PCAP capturing process */
    char *dev = "tap0"; /* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
    pcap_t *handle; /* packet capture handle */
    char filter_exp[100] = "dst host "; /* filter expression */
    strcat(filter_exp, listeningaddress);
    struct bpf_program fp; /* compiled filter program (expression) */
    bpf_u_int32 mask; /* subnet mask */
    bpf_u_int32 net; /* ip */
    int num_packets = -1; /* number of packets to capture ,-1 for inf*/
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);
    
    //char test[30];
    //strcpy(test,"P");
    //unsigned short tt=getFTPdataport(test);
    //printf("the size is %d\n",sizeof(struct tcphdr));
    

    /* open capture device */
    handle = pcap_open_live(dev,  BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }


    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* set callback function */
    pcap_loop(handle, num_packets, process_pkt, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    /* Initialize raw socket */
    return 0;
}//End of the bouncer
