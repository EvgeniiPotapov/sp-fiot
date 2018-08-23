#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fiot_types.h"
#include "serialize_fiot.h"

int main(){
    IntegrityCode a;
    OctetString c = "abcdef";
    a.present = isPresent;
    a.length = 6;
    a.code = c;
    OctetString b = malloc(sizeof(Octet));
    serIntegrityCode(&b,&a);
    int i;
    for(i=0;i<10;i++) printf("%x\n",b[i]);

}


