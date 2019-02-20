all: jexec-host

jexec-host: jexec-host.o
	$(CC) -o ${.TARGET} -lelf -ljail ${.ALLSRC}

jexec-host.o: jexec-host.c
	$(CC) $(CFLAGS) -c -o ${.TARGET} ${.ALLSRC}


clean:
	rm -f jexec-host
	rm -f *.o
