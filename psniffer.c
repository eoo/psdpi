#include <pcap.h>
#include <zmq.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h> 
#include <stdlib.h> 
#include <signal.h>
#include <assert.h>
#include "crc.h"
#include "ps_eth.h"
#include "ps_ip.h"
#include "hash.h"

#define MAXBYTES2CAPTURE 2048 

pcap_dumper_t *pdumper;
pcap_t *descr = NULL;

//hash table declaration. Init in main()
ht_table_t ht;

static eth_stats_t eth_stats;

/* processPacket(): Callback function called by pcap_loop() everytime a packet */
/* arrives to the network card. This function prints the captured raw data in  */
/* hexadecimal.                                                             */
void processPacket(u_char *dumpfile, const struct pcap_pkthdr* pkthdr, const u_char * packet){ 
    int i=0;
    static packet_counter = 0; 
    static bytes_counter = 0;
    eth_type_t eth;
    char * protocol;

    l3l4_quin_t quin;
    l3l4_quin_init(&quin);

    
    printf("Packet Count: %d\n", ++(packet_counter));
    bytes_counter += pkthdr->len;
    printf("Received Packet Size: %d\n", pkthdr->len); 
    printf("Cumulative: Packets %d: Bytes %d\n", packet_counter, bytes_counter);
    
    printf("Payload:\n"); 

    eth = ps_parse_eth(&eth_stats, packet);
    printf("ETH TYPE = 0x%04x \n", ntohs(eth));
    
    uint8_t quin_present;

    switch (ntohs(eth)) {
        case PS_ETH_TYPE_IPV4:
            quin_present = ps_parse_ipv4(packet, &quin);
            break;

        case PS_ETH_TYPE_IPV6:
            quin_present = ps_parse_ipv6(packet, &quin);
            break;

        default:
            break;
    }

    //----------------------------------hashing stuff --------------------------------------------------------

    if(quin_present)
        ht_add(&ht, &quin, pkthdr->len);

    /* save the packet on the dump file */
    pcap_dump(dumpfile, pkthdr, packet);

    printf("================================== \n");

    return;
} 


void * zmqserver(void * arg)
{   
    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    int rc = zmq_bind (responder, "tcp://*:5555");
    assert (rc == 0);

    while (1) {
        char buffer [10];
        zmq_recv (responder, buffer, 10, 0);
        printf ("Received message from client to: %s\n", buffer);
        sleep(1);
        zmq_send (responder, "OK", 10, 0);

        if(strcmp(buffer, "close") == 0)
        {   
            printf("Closing app...\n");
            pcap_breakloop(descr);
            pcap_close(descr);
            ps_eth_stats_print(&eth_stats);
            ht_print(&ht);
        }
    }
    
    return (int *)0;
}


int main(int argc, char *argv[]) {

    pthread_t zmq_thread;
    pthread_create(&zmq_thread, NULL, zmqserver, NULL);
    



    char errbuf[PCAP_ERRBUF_SIZE], *device=NULL; 
    memset(errbuf,0,PCAP_ERRBUF_SIZE); 

    ps_eth_stats_init(&eth_stats);
    ht_init(&ht);

    if( argc > 1){  /* If user supplied interface name, use it. */
        device = argv[1];
    }
    else {  /* Get the name of the first device suitable for capture */ 
        if ( (device = pcap_lookupdev(errbuf)) == NULL){
            fprintf(stderr, "ERROR: %s\n", errbuf);
            exit(1);
        }
    }

    printf("Opening device %s\n", device); 
 
    /* Open device in promiscuous mode */ 
    if ( (descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL) {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }
    pdumper = pcap_dump_open(descr, "test.pcap");//save to file

    /* Loop forever & call processPacket() for every received packet*/ 
    if ( pcap_loop(descr, 0, processPacket, (unsigned char *)pdumper) == -1){
       fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
       exit(1);
    }
    return 0; 
} 