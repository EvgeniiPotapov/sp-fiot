#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fiot_types.h"
#include "serialize_fiot.h"

int main(){
    KeyMechanismExtension cert;
    cert.mechanism = standard221;

    
    OctetString ser = malloc(sizeof(Octet));
    serKeyMechanismExtension(&ser, &cert);
    int i;
    for(i=0;i<1;i++) printf("%x\n",ser[i]);
    free(ser);
}
