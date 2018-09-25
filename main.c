#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close

#include "libakrypt.h"

#include "fiot_types.h"
#include "serialize_fiot.h"

void genClientHello(){
    int i;
    ClientHelloMessage clientHello;
    memset(clientHello.random, 0, 32);
    int fd = open("/dev/urandom", O_RDWR);
    for (i=0;i<32;i++) printf("%.2X",clientHello.random[i]);
    printf("\n");
    read(fd, clientHello.random, 32);
    for (i=0;i<32;i++) printf("%.2X",clientHello.random[i]);
    close(fd);
}

int main(){
    KeyMechanismExtension cert;
    cert.mechanism = standard221;
    genClientHello();

    
    OctetString ser = malloc(sizeof(Octet));
    serKeyMechanismExtension(&ser, &cert);
    int i;
    for(i=0;i<1;i++) printf("%x\n",ser[i]);
    free(ser);
}
