all: main

main: main.o serialize_fiot.o
	gcc main.o serialize_fiot.o -o main

main.o: main.c
	gcc -c main.c

serialize_fiot.o: serialize_fiot.c serialize_fiot.h fiot_types.h
	gcc -c serialize_fiot.c

clean:
	rm -rf *.o && rm -rf main