all:
	gcc -g bouncer.c process_pkt.c -o bouncer -lpcap -Wall

clean:
	rm -f *.o bouncer
