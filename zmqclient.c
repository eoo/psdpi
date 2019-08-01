//  Hello World client
#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <libconfig.h>

int main (int argc, char *argv[])
{      
    //READING CONFIGURATION

    config_t cfg;
    config_init(&cfg);
    config_read_file(&cfg, "app.cfg");
 
    const char * zmq_port;
    if(config_lookup_string(&cfg, "zmq_port", &zmq_port))
        printf("Setting ZMQ Port as : %s\n\n", zmq_port);
    else{
        fprintf(stderr, "No 'zmqport' setting in configuration file. Using default port 5555\n");
        zmq_port = "5555";
    }

    char endpoint[30] = "tcp://localhost:";
    strcat(endpoint, zmq_port);

    char * msg = argv[1];

    printf ("Connecting to psniffer server…\n");
    void *context = zmq_ctx_new ();
    void *requester = zmq_socket (context, ZMQ_REQ);
    zmq_connect (requester, endpoint);

        char buffer [10];
        printf ("Sending %s…\n", msg);
        zmq_send (requester, msg, 5, 0);
        zmq_recv (requester, buffer, 10, 0);
        printf ("Received response: %s\n", buffer);

    zmq_close (requester);
    zmq_ctx_destroy (context);
    config_destroy(&cfg);
    return 0;
}
