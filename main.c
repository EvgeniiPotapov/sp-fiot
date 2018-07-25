#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fiot_types.h"
#include "serialize_fiot.h"

int main(){
    unsigned short a = 256;
    LengthShortInt len;
    serLengthShortInt(len, a);
    printf("%d %d\n", len[0], len[1]);

}


