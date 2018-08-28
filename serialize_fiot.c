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
    LengthOctet len = strlen(curve->x);
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
    unsigned short framelen = frame->length[1];
    framelen = (framelen << 8) | frame->length[0];
    *serframe = realloc(*serframe, sizeof(Octet) * framelen);
    memcpy(*serframe, &(frame->tag), sizeof(Octet));
    memcpy(*serframe + 1, &(frame->length), sizeof(Octet) * 2);
    memcpy(*serframe + 3, &(frame->number), sizeof(Octet) * 5);
    memcpy(*serframe + 8, &(frame->type), sizeof(Octet));
    unsigned short meslen = frame->meslen[1];
    meslen = (meslen << 8) | frame->meslen[0];
    memcpy(*serframe + 9, &(frame->meslen), sizeof(Octet) * 2);
    memcpy(*serframe + 11, frame->message, sizeof(Octet) * meslen);
    unsigned short padlen = framelen - (11 + meslen + 2 + frame->icode.length);
    memcpy(*serframe + 11 + meslen, frame->padding, sizeof(Octet) * padlen);
    OctetString icode_serialized = malloc(sizeof(Octet));
    serIntegrityCode(&icode_serialized, &(frame->icode));
    memcpy(*serframe + 11 + meslen + padlen, icode_serialized, sizeof(Octet) * (2 + frame->icode.length));
    free(icode_serialized);
}
/* Session layer structures */
/* Serializing ClientHelloMessage */
void serClientHelloMessage(OctetString *clienthello, ClientHelloMessage *clientmessage){
    LengthShortInt algorithm;
    serLengthShortInt(algorithm, clientmessage->algorithm);
    OctetString serpoint = malloc(sizeof(Octet));
    serEllipticCurvePoint(&serpoint, &(clientmessage->point));
    LengthOctet pointlen = strlen(clientmessage->point.x) * 2 + sizeof(Octet);
    OctetString ikeyid = malloc(sizeof(Octet));
    serPreSharedKeyID(&ikeyid, &(clientmessage->iPSK));
    LengthOctet iPSKlen = sizeof(Octet);
    if (clientmessage->iPSK.present == isPresent)
        iPSKlen = iPSKlen * 2 + clientmessage->iPSK.length;
    OctetString ekeyid = malloc(sizeof(Octet));
    serPreSharedKeyID(&ekeyid, &(clientmessage->ePSK));
    LengthOctet ePSKlen = sizeof(Octet);
    if (clientmessage->ePSK.present == isPresent)
        ePSKlen = ePSKlen * 2 + clientmessage->ePSK.length;
    *clienthello = realloc(*clienthello, sizeof(Octet) * (35 + pointlen + iPSKlen + ePSKlen));
    printf("point %d\n", pointlen);
    memcpy(*clienthello, algorithm, 2 * sizeof(Octet));
    memcpy(*clienthello +2, &(clientmessage->random), 32 * sizeof(Octet));
    memcpy(*clienthello +34, serpoint, pointlen * sizeof(Octet));
    free(serpoint);
    memcpy(*clienthello + 34 + pointlen, ikeyid, iPSKlen * sizeof(Octet));
    free(ikeyid);
    memcpy(*clienthello + 34 + pointlen + iPSKlen, ekeyid, ePSKlen * sizeof(Octet));
    free(ekeyid);
    memcpy(*clienthello + 34 + pointlen + iPSKlen + ePSKlen, &(clientmessage->countOfExtensions), sizeof(Octet));
    
    

}