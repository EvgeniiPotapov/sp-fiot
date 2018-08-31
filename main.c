#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fiot_types.h"
#include "serialize_fiot.h"

int main(){
    RequestCertificateExtension cert;
    cert.certproctype = any;
    cert.identifier = "12234";

    
    OctetString ser = malloc(sizeof(Octet));
    serSetCertificateExtension(&ser, &cert);
    int i;
    for(i=0;i<6;i++) printf("%x\n",ser[i]);
    free(ser);
}
