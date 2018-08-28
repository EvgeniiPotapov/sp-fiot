#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fiot_types.h"
#include "serialize_fiot.h"

int main(){
    OctetString random = "12345678900987654321123456789033";
    ClientHelloMessage hello;
    hello.algorithm = streebog512;
    memcpy(hello.random, random, 32);
    EllipticCurvePoint point;
    point.id = id_tc26_gost3410_2012_256_paramsetA;
    point.x = "6655";
    point.y = "8877";
    PreSharedKeyID ipsk;
    ipsk.present = notPresent;
    ipsk.length = 3;
    ipsk.id = "994";
    PreSharedKeyID epsk;
    epsk.present = isPresent;
    epsk.length = 2;
    epsk.id = "73";
    hello.point = point;
    hello.iPSK = ipsk;
    hello.ePSK = epsk;
    hello.countOfExtensions = 4;
    OctetString serhello = malloc(sizeof(Octet));
    serClientHelloMessage(&serhello, &hello);
    int i;
    for(i=0;i<49;i++) printf("%x\n",serhello[i]);
    free(serhello);



}


