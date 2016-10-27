OBJECTSCLIENT = client-zhou.o md5c.o

all:client
client : ${OBJECTSCLIENT}
	cc -o  client ${OBJECTSCLIENT} -lpthread -lm

client-zhou.o : client-zhou.c md5c.h 
	cc -c -g client-zhou.c

md5c.o:md5c.c md5c.h
	cc -c md5c.c 

.PHONY:clean

clean:
	rm -f *.o client