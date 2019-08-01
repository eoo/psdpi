all:
	gcc -o psniffer -lpcap -lzmq -lpthread -lconfig hash.c crc_32.c ps_eth.c ps_ip.c l3l4.c ps_stats.c psniffer.c
clean:
	rm psniffer client
client:
	gcc -o client zmqclient.c -lzmq	-lconfig
