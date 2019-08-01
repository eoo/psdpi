# psdpi
Picomass Studio Deep Packet Inspection

**Installation**

psdpi: 
```
$ make
```
Client:
```
$ make client
```


**Usage**

psdpi:
```
$ ./psdpi <interface>
```


client:
```
$ ./client <command>
```
Supported commands for client program:

- *close* : closes the program and displays stats
- *print* : print stats
- *clear* : free all memory and clear hash table


**Configuration**

The utility can be configured using the configuration file app.cfg as follows : 

- *zmq_port* 	: ZeroMQ TCP server port to send/recieve commands from the client program, default port 5555
- *table_size*	: Set Hash Table size, default value 65636