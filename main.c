#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fiot_types.h"
#include "serialize_fiot.h"

int main(){
    VerifyMessage verify;
    verify.mac.present = isPresent;
    verify.sign.present = isPresent;
    verify.sign.length = 4;
    verify.sign.code = "2468";
    verify.mac.length = 2;
    verify.mac.code = "11";
    OctetString serverify = malloc(sizeof(Octet));
    serVerifyMessage(&serverify, &verify);
    int i;
    for(i=0;i<10;i++) printf("%x\n",serverify[i]);
    free(serverify);



}


