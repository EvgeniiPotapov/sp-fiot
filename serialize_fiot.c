#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fiot_include/fiot_types.h"


/* Serializing unsingned short to LengthShortInt */
void serLengthShortInt(Octet *length, unsigned short number){
    length[1] = number >> 8;
    length[0] = number & 0xff;
}
/* Serializing EllipticCurvePoint structure */
void serEllipticCurvePoint(OctetString *serpt , EllipticCurvePoint *curve){
    LengthOctet len = 32;
/* ID field is one Octet length */
    *serpt = realloc(*serpt,  sizeof(Octet) * (len * 2 + 1));
    memmove(*serpt, &(curve->id), sizeof(Octet));
    memmove(*serpt + 1, curve->x, len);
    memmove(*serpt + 1 + len, curve->y, len);
}
/* Serializing PreSharedKeyID structure */
void serPreSharedKeyID(OctetString *keyid, PreSharedKeyID *pskID){
    if (pskID->present == notPresent){
        memmove(*keyid, &(pskID->present), sizeof(Octet));
    }
    else{
        *keyid = realloc(*keyid, sizeof(Octet) * (2 + pskID->length));
        memmove(*keyid, &(pskID->present), sizeof(Octet));
        memmove(*keyid + 1, &(pskID->length), sizeof(Octet));
        memmove(*keyid + 2, pskID->id, pskID->length);
    }
}
/* Serializing IntegrityCode structure */
void serIntegrityCode(OctetString *keyid, IntegrityCode *icode){
    if (icode->present == notPresent){
        memmove(*keyid, &(icode->present), sizeof(Octet));
    }
    else{
        *keyid = realloc(*keyid, sizeof(Octet) * (2 + icode->length));
        memmove(*keyid, &(icode->present), sizeof(Octet));
        memmove(*keyid + 1, &(icode->length), sizeof(Octet));
        memmove(*keyid + 2, icode->code, icode->length);
    }
}
/* Serializing Frame structure */
void serFrame(OctetString *serframe, Frame *frame){
    unsigned short framelen = frame->length[1];
    framelen = (framelen << 8) | frame->length[0];
    *serframe = realloc(*serframe, sizeof(Octet) * framelen);
    memmove(*serframe, &(frame->tag), sizeof(Octet));
    memmove(*serframe + 1, &(frame->length), sizeof(Octet) * 2);
    memmove(*serframe + 3, &(frame->number), sizeof(Octet) * 5);
    memmove(*serframe + 8, &(frame->type), sizeof(Octet));
    unsigned short meslen = frame->meslen[1];
    meslen = (meslen << 8) | frame->meslen[0];
    memmove(*serframe + 9, &(frame->meslen), sizeof(Octet) * 2);
    memmove(*serframe + 11, frame->message, sizeof(Octet) * meslen);
    unsigned short padlen = framelen - (11 + meslen + 2 + frame->icode.length);
    memmove(*serframe + 11 + meslen, frame->padding, sizeof(Octet) * padlen);
    OctetString icode_serialized = malloc(sizeof(Octet));
    serIntegrityCode(&icode_serialized, &(frame->icode));
    memmove(*serframe + 11 + meslen + padlen, icode_serialized, sizeof(Octet) * (2 + frame->icode.length));
    free(icode_serialized);
}
/* Session layer structures */
/* Serializing ClientHelloMessage structure */
void serClientHelloMessage(OctetString *clienthello, ClientHelloMessage *clientmessage){
    LengthShortInt algorithm;
    serLengthShortInt(algorithm, clientmessage->algorithm);
    OctetString serpoint = malloc(sizeof(Octet));
    serEllipticCurvePoint(&serpoint, &(clientmessage->point));
    LengthOctet pointlen = 65;
    OctetString ikeyid = malloc(sizeof(Octet));
    serPreSharedKeyID(&ikeyid, &(clientmessage->idipsk));
    LengthOctet iPSKlen = sizeof(Octet);
    if (clientmessage->idipsk.present == isPresent)
        iPSKlen = iPSKlen * 2 + clientmessage->idipsk.length;
    OctetString ekeyid = malloc(sizeof(Octet));
    serPreSharedKeyID(&ekeyid, &(clientmessage->idepsk));
    LengthOctet ePSKlen = sizeof(Octet);
    if (clientmessage->idepsk.present == isPresent)
        ePSKlen = ePSKlen * 2 + clientmessage->idepsk.length;
    *clienthello = realloc(*clienthello, sizeof(Octet) * (35 + pointlen + iPSKlen + ePSKlen));
    memmove(*clienthello, algorithm, 2 * sizeof(Octet));
    memmove(*clienthello + 2, ikeyid, iPSKlen * sizeof(Octet));
    free(ikeyid);
    memmove(*clienthello + 2 + iPSKlen, ekeyid, ePSKlen * sizeof(Octet));
    free(ekeyid);
    memmove(*clienthello +2 + iPSKlen + ePSKlen, &(clientmessage->random), 32 * sizeof(Octet));
    memmove(*clienthello +34 + iPSKlen + ePSKlen, serpoint, pointlen * sizeof(Octet));
    free(serpoint);
    memmove(*clienthello + 34 + pointlen + iPSKlen + ePSKlen, &(clientmessage->countOfExtensions), sizeof(Octet));
}
/* Serializing ServerHelloMessage structure */
void serServerHelloMessage(OctetString *serverhello, ServerHelloMessage *servermessage){
    LengthShortInt algorithm;
    serLengthShortInt(algorithm, servermessage->algorithm);
    OctetString serpoint = malloc(sizeof(Octet));
    serEllipticCurvePoint(&serpoint, &(servermessage->point));
    LengthOctet pointlen = strlen(servermessage->point.x) * 2 + sizeof(Octet);
    *serverhello = realloc(*serverhello, sizeof(Octet) * (35 + pointlen));
    memmove(*serverhello, algorithm, 2 * sizeof(Octet));
    memmove(*serverhello +2, &(servermessage->random), 32 * sizeof(Octet));
    memmove(*serverhello +34, serpoint, pointlen * sizeof(Octet));
    free(serpoint);
    memmove(*serverhello + 34 + pointlen, &(servermessage->countOfExtensions), sizeof(Octet));
}
/* Serializing  VerifyMessage structure */
void serVerifyMessage(OctetString *message, VerifyMessage *verify){
    OctetString mac = malloc(sizeof(Octet));
    serIntegrityCode(&mac, &(verify->mac));
    OctetString sign = malloc(sizeof(Octet));
    serIntegrityCode(&sign, &(verify->sign));
    unsigned short maclen = 0;
    if (verify->mac.present == notPresent){
        maclen++;
    }
    else{
        maclen = 2 + verify->mac.length;
    }
    unsigned short signlen = 0;
    if (verify->sign.present == notPresent){
        signlen++;
    }
    else{
        signlen = 2 + verify->sign.length;
    }
    *message = realloc(*message, sizeof(Octet) * (maclen + signlen));
    memmove(*message, mac, maclen * sizeof(Octet));
    memmove(*message + maclen, sign, signlen * sizeof(Octet));
}
/* Serializing  AlertMessage structure */
void serAlertMessage(OctetString *alert, AlertMessage *alertmessage){
    LengthShortInt code;
    serLengthShortInt(code, alertmessage->code);
    LengthShortInt algorithm;
    serLengthShortInt(algorithm, alertmessage->algorithm);
    *alert = realloc(*alert, sizeof(Octet) * 5);
    memmove(*alert, code, 2 * sizeof(Octet));
    memmove(*alert + 2, algorithm, 2 * sizeof(Octet));
    memmove(*alert + 4, &(alertmessage->present), sizeof(Octet));
    int meslen = 0;
    if (alertmessage->present == isPresent){
        meslen = strlen(alertmessage->message) + 1;
        *alert = realloc(*alert, sizeof(Octet) * (5 + meslen));
        memmove(*alert + 5, alertmessage->message, sizeof(Octet) * meslen);
    }
}
/* Serializing  GeneratePSKMessage structure */
void serGeneratePSKMessage(OctetString *pskmessage, GeneratePSKMessage *genpskmessage){
    unsigned short idlen = sizeof(Octet);
    if (genpskmessage->id.present == isPresent){
        idlen = (2 + genpskmessage->id.length) * sizeof(Octet);
    }
    *pskmessage = realloc(*pskmessage, sizeof(Octet) * (34 + idlen));
    memmove(*pskmessage, genpskmessage->random, 32 * sizeof(Octet));
    OctetString id = malloc(sizeof(Octet));
    serPreSharedKeyID(&id, &(genpskmessage->id));
    memmove(*pskmessage + 32, id, idlen);
    free(id);
}
/* Extension structures */
/* Serializing  RequestCertificateExtension structure */
void serRequestCertificateExtension(OctetString *reqcertext, RequestCertificateExtension *extension){
    unsigned short identifierlen = strlen(extension->identifier) + 1;
    *reqcertext = realloc(*reqcertext, sizeof(Octet) * (1 + identifierlen));
    memmove(*reqcertext, &(extension->certproctype), 1);
    memmove(*reqcertext + 1, extension->identifier, sizeof(Octet) * identifierlen);
}
/* Serializing CertificateExtension structure */
void serCertificateExtension(OctetString *certext, CertificateExtension *extension){
    unsigned short certlen = strlen(extension->certificate);
    *certext = realloc(*certext, sizeof(Octet) * (1 + certlen));
    memmove(*certext, &(extension->format), 1);
    memmove(*certext + 1, extension->certificate, sizeof(Octet) * certlen);
}
/* Serializing  RequestIdentifierExtension structure */
void serRequestIdentifierExtension(OctetString *reqidext, RequestIdentifierExtension *extension){
    unsigned short idlen = strlen(extension->identifier) + 1;
    *reqidext = realloc(*reqidext, sizeof(Octet) * (1 + idlen));
    memmove(*reqidext, &(extension->request), 1);
    memmove(*reqidext + 1, extension->identifier, idlen);
}
/* serializing KeyMechanismExtension */
void serKeyMechanismExtension(OctetString *serext, KeyMechanismExtension *extension){
    memmove(*serext, &(extension->mechanism), sizeof(Octet));
}