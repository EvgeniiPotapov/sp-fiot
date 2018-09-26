all: server client

server: server.c
	gcc -o server server.c

client: client.o gench.o serialize_fiot.o
	gcc client.o gench.o serialize_fiot.o -L/fiot/krypt_lib -l:libakrypt-static.a -o client

client.o: client.c
	gcc -L/fiot/krypt_lib -l:libakrypt-static.a -c client.c

gench.o : gench.c
	gcc -L/fiot/krypt_lib -l:libakrypt-static.a -c gench.c

serialize_fiot.o: serialize_fiot.c fiot_include/serialize_fiot.h fiot_include/fiot_types.h
	gcc -c serialize_fiot.c

clean:
	rm -rf *.o && rm -rf client server