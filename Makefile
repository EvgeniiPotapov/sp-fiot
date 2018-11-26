all: server client

server: server.o serialize_fiot.o tl_session.o
	gcc server.o serialize_fiot.o tl_session.o -O0 -L krypt_lib -lakrypt-static -o server

server.o: server.c fiot_include/tl_session.h
	gcc -c server.c -O0 -L krypt_lib -lakrypt-static -funsigned-char

client: client.o gench.o serialize_fiot.o tl_session.o
	gcc client.o gench.o serialize_fiot.o tl_session.o -O0 -L krypt_lib -lakrypt-static -o client

client.o: client.c fiot_include/tl_session.h
	gcc -O0 -L krypt_lib -lakrypt-static -c client.c

gench.o: gench.c
	gcc -O0 -L krypt_lib -lakrypt-static -c gench.c

serialize_fiot.o: serialize_fiot.c fiot_include/serialize_fiot.h fiot_include/fiot_types.h
	gcc -O0 -c serialize_fiot.c

tl_session.o: tl_session.c fiot_include/tl_session.h
	gcc -O0 -c tl_session.c

mac: example-fiot.c
	gcc -O0 example-fiot.c -lakrypt-static -o mac
clean:
	rm -rf *.o && rm -rf client server
