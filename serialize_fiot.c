#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "fiot_types.h"


/* Serializing unsingned short to LengthShortInt */
void serLengthShortInt(Octet *length, unsigned short number){
    length[1] = number >> 8;
    length[0] = number & 0xff;
}
/* Serializing EllipticCurvePoint structure */
void serEllipticCurvePoint(OctetString *serpt , EllipticCurvePoint *curve){
    size_t len = strlen(curve->x);
/* ID field is one Octet length */
    *serpt = realloc(*serpt,  sizeof(Octet) * (len * 2 + 1));
    memcpy(*serpt, &(curve->id), sizeof(Octet));
    memcpy(*serpt + 1, curve->x, len);
    memcpy(*serpt + 1 + len, curve->y, len);
}
/* Serializing PreSharedKeyID structure */
void serPreSharedKeyID(OctetString *keyid, PreSharedKeyID *pskID){
    if (pskID->present == notPresent){
        memcpy(*keyid, &(pskID->present), sizeof(Octet));
    }
    else{
        *keyid = realloc(*keyid, sizeof(Octet) * (2 + pskID->length));
        memcpy(*keyid, &(pskID->present), sizeof(Octet));
        memcpy(*keyid + 1, &(pskID->length), sizeof(Octet));
        memcpy(*keyid + 2, pskID->id, pskID->length);
    }
}
/* Serializing IntegrityCode structure */
void serIntegrityCode(OctetString *keyid, IntegrityCode *icode){
    if (icode->present == notPresent){
        memcpy(*keyid, &(icode->present), sizeof(Octet));
    }
    else{
        *keyid = realloc(*keyid, sizeof(Octet) * (2 + icode->length));
        memcpy(*keyid, &(icode->present), sizeof(Octet));
        memcpy(*keyid + 1, &(icode->length), sizeof(Octet));
        memcpy(*keyid + 2, icode->code, icode->length);
    }
}
/* Serializing Frame structure */
void serFrame(OctetString *serframe, Frame *frame){
    OctetString icode_serialized = malloc(sizeof(Octet));
    serIntegrityCode(&icode_serialized, &(frame->icode));
    unsigned short frame_len = frame->length[1];
    frame_len = (frame_len << 8) & frame->length[0];
    *serframe = realloc(*serframe, sizeof(Octet) * frame_len);
    memcpy(*serframe, &(frame->tag), sizeof(Octet));
    memcpy(*serframe + 1, &(frame->length), sizeof(Octet) * 2);
    memcpy(*serframe + 3, &(frame->number), sizeof(Octet) * 5);


}