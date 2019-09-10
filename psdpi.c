#include <pcap.h>
#include <zmq.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <libconfig.h>
#include "crc.h"
#include "ps_eth.h"
#include "ps_ip.h"
#include "hash.h"
#include "tpool.h"

void wrapper(u_char *dumpfile, const struct pcap_pkthdr* pkthdr, const u_char * packet);

#define MAXBYTES2CAPTURE 2048

pcap_dumper_t *pdumper;
pcap_t *descr = NULL;
ht_table_t ht;
tpool_t thread_pool;
pthread_mutex_t ht_mutex = PTHREAD_MUTEX_INITIALIZER;

static eth_stats_t eth_stats;

void processPacket(packet_data_t * arg){ 
    int i=0;
    static packet_counter = 0; 
    static bytes_counter = 0;
    eth_type_t eth;
    char * protocol;

    printf("Packet Count: %d\n", ++(packet_counter));
    eth = ps_parse_eth(&eth_stats, arg->packet);
    printf("ETH TYPE = 0x%04x \n", ntohs(eth));
    
    l3l4_quin_t quin;
    l3l4_quin_init(&quin);
    uint8_t quin_present = 0;

    switch (ntohs(eth)) {
        case PS_ETH_TYPE_IPV4:
            quin_present = ps_parse_ipv4(arg->packet, &quin);
            break;

        case PS_ETH_TYPE_IPV6:
            quin_present = ps_parse_ipv6(arg->packet, &quin);
            break;

        default:
            break;
    }

    //Add to hash table if valid packet
    if(quin_present)
        pthread_mutex_lock(&ht_mutex);
        ht_add(&ht, &quin, arg->pkthdr->len);
        pthread_mutex_unlock(&ht_mutex);

    /* save the packet on the dump file */
    pcap_dump(arg->dumpfile, arg->pkthdr, arg->packet);
    printf(" ================================== \n");
    return;
} 


void * zmqserver(void * arg)
{   

    char * zmq_port = (char * )arg;
    char endpoint[20] = "tcp://*:";
    strcat(endpoint, zmq_port);


    void *context = zmq_ctx_new ();
    void *responder = zmq_socket (context, ZMQ_REP);
    int rc = zmq_bind (responder, endpoint);
    assert (rc == 0);
    int stop = 1;

    while (stop) {
        char buffer [10];
        zmq_recv (responder, buffer, 10, 0);
        printf ("Received message from client to: %s\n", buffer);
        sleep(1);
        zmq_send (responder, "OK", 10, 0);

        if(strcmp(buffer, "close") == 0)
        {   
            printf("Closing zmqserver thread...\n");
            pcap_breakloop(descr);
            ps_eth_stats_print(&eth_stats);
            ht_print(&ht);
            stop = 0;
        }

        if(strcmp(buffer, "clear") == 0)
        {
            printf("Clearing Hash Table...\n");
            ht_clear(&ht);
        }

        if(strcmp(buffer, "print") == 0)
        {
            printf("Printing Hash Table...\n");
            ht_print(&ht);
        }

    }

    zmq_close (responder);
    zmq_ctx_destroy (context); 
   
    return (int *)0;
}


int main(int argc, char *argv[]) {

    //Initialising Thread pool
    tpool_init(&thread_pool, 10, 2048, 0);
    
    //Reading configuration
    config_t cfg;
    config_init(&cfg);

    if(! config_read_file(&cfg, "app.cfg"))
    {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
        config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return(EXIT_FAILURE);
    }

    const char * zmq_port;
    if(config_lookup_string(&cfg, "zmq_port", &zmq_port))
        printf("Setting ZMQ Port as : %s\n\n", zmq_port);
    else{
        fprintf(stderr, "No 'zmqport' setting in configuration file. Using default port 5555\n");
        zmq_port = "5555";
    }

    //ZMQ THREAD
    pthread_t zmq_thread;
    void *pthread_ret;
    pthread_create(&zmq_thread, NULL, zmqserver, (void *)zmq_port);


    char errbuf[PCAP_ERRBUF_SIZE], *device=NULL; 
    memset(errbuf,0,PCAP_ERRBUF_SIZE); 

    ps_eth_stats_init(&eth_stats);
    ht_init(&ht);

    if( argc > 1){                      /* If user supplied interface name, use it. */
        device = argv[1];
    }
    else {                              /* Get the name of the first device suitable for capture */ 
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
    if ( pcap_loop(descr, 0, wrapper, (unsigned char *)pdumper) == -1){
       fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
       exit(1);
    }
    pcap_close(descr);

    if (pthread_join(zmq_thread, &pthread_ret) != 0) {
        perror("pthread_join() error");
        exit(3);
    }
    printf("zmqserver thread exited with '%s'\n", pthread_ret);
    return 0; 
} 


void wrapper(u_char *dumpfile, const struct pcap_pkthdr* pkthdr, const u_char * packet) {
    packet_data_t * arg = malloc(sizeof(packet_data_t));
    arg->dumpfile = dumpfile;
    arg->pkthdr = pkthdr;
    arg->packet = packet;

    tpool_add_work(thread_pool, processPacket, arg);

}