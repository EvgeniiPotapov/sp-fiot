#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "fiot_types.h"

/* Serializing EllipticCurvePoint structure */
void serEllipticCurvePoint(OctetString *serpt , EllipticCurvePoint *curve){
    size_t x_len = strlen(curve->x);
    size_t y_len = strlen(curve->y);
/* ID field is one Octet length + 1 byte for terminating symbol  */
    *serpt = realloc(*serpt,  sizeof(Octet) * (x_len + y_len + 2));
    memcpy(*serpt, &(curve->id), sizeof(Octet));
    memcpy(*serpt+1, curve->x,x_len);
    memcpy(*serpt+1+x_len, curve->y,y_len + 1);
}

/* Serializing unsingned short to LengthShortInt */
void serLengthShortInt(Octet *length, unsigned short number){
    length[1] = number % 256;
    printf("hi %x\n", (length[1]));
    (length[0]) = (number - length[1]) / 256;
}
