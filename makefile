all:
	gcc -o psdpi -lpcap -lzmq -lpthread -lconfig hash.c crc_32.c ps_eth.c ps_ip.c l3l4.c ps_stats.c psdpi.c
clean:
	rm psdpi client
client:
	gcc -o client zmqclient.c -lzmq	-lconfig
