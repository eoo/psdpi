//  Hello World client
#include <zmq.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int main (int argc, char *argv[])
{   

    char * msg = argv[1];

    printf ("Connecting to hello world server…\n");
    void *context = zmq_ctx_new ();
    void *requester = zmq_socket (context, ZMQ_REQ);
    zmq_connect (requester, "tcp://localhost:5555");

        char buffer [10];
        printf ("Sending %s…\n", msg);
        zmq_send (requester, msg, 5, 0);
        zmq_recv (requester, buffer, 10, 0);
        printf ("Received response: %s\n", buffer);

    zmq_close (requester);
    zmq_ctx_destroy (context);
    return 0;
}
