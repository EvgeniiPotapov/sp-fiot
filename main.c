#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fiot_types.h"
#include "serialize_fiot.h"

int main(){
    AlertMessage alertmessage;
    alertmessage.code = wrongIntegrityCode;
    alertmessage.algorithm = kuznechikAEAD;
    alertmessage.present = notPresent;
    alertmessage.message = "7765";
    
    OctetString seralert = malloc(sizeof(Octet));
    serAlertMessage(&seralert, &alertmessage);
    int i;
    for(i=0;i<9;i++) printf("%x\n",seralert[i]);
    free(seralert);



}


