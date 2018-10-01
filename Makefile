all: server client

server: server.o serialize_fiot.o
	gcc server.o serialize_fiot.o -L krypt_lib -lakrypt-static -o server

server.o: server.c
	gcc -c server.c -L krypt_lib -lakrypt-static -funsigned-char

client: client.o gench.o serialize_fiot.o
	gcc client.o gench.o serialize_fiot.o -L krypt_lib -lakrypt-static -o client

client.o: client.c
	gcc -L krypt_lib -lakrypt-static -c client.c

gench.o: gench.c
	gcc -L krypt_lib -lakrypt-static -c gench.c

serialize_fiot.o: serialize_fiot.c fiot_include/serialize_fiot.h fiot_include/fiot_types.h
	gcc -c serialize_fiot.c

clean:
	rm -rf *.o && rm -rf client server
