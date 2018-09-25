#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
/* Serializing ClientHelloMessage structure */
void serClientHelloMessage(OctetString *clienthello, ClientHelloMessage *clientmessage){
    LengthShortInt algorithm;
    serLengthShortInt(algorithm, clientmessage->algorithm);
    OctetString serpoint = malloc(sizeof(Octet));
    serEllipticCurvePoint(&serpoint, &(clientmessage->point));
    LengthOctet pointlen = strlen(clientmessage->point.x) * 2 + sizeof(Octet);
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
/* Serializing ServerHelloMessage structure */
void serServerHelloMessage(OctetString *serverhello, ServerHelloMessage *servermessage){
    LengthShortInt algorithm;
    serLengthShortInt(algorithm, servermessage->algorithm);
    OctetString serpoint = malloc(sizeof(Octet));
    serEllipticCurvePoint(&serpoint, &(servermessage->point));
    LengthOctet pointlen = strlen(servermessage->point.x) * 2 + sizeof(Octet);
    *serverhello = realloc(*serverhello, sizeof(Octet) * (35 + pointlen));
    memcpy(*serverhello, algorithm, 2 * sizeof(Octet));
    memcpy(*serverhello +2, &(servermessage->random), 32 * sizeof(Octet));
    memcpy(*serverhello +34, serpoint, pointlen * sizeof(Octet));
    free(serpoint);
    memcpy(*serverhello + 34 + pointlen, &(servermessage->countOfExtensions), sizeof(Octet));
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
    memcpy(*message, mac, maclen * sizeof(Octet));
    memcpy(*message + maclen, sign, signlen * sizeof(Octet));
}
/* Serializing  AlertMessage structure */
void serAlertMessage(OctetString *alert, AlertMessage *alertmessage){
    LengthShortInt code;
    serLengthShortInt(code, alertmessage->code);
    LengthShortInt algorithm;
    serLengthShortInt(algorithm, alertmessage->algorithm);
    *alert = realloc(*alert, sizeof(Octet) * 5);
    memcpy(*alert, code, 2 * sizeof(Octet));
    memcpy(*alert + 2, algorithm, 2 * sizeof(Octet));
    memcpy(*alert + 4, &(alertmessage->present), sizeof(Octet));
    int meslen = 0;
    if (alertmessage->present == isPresent){
        meslen = strlen(alertmessage->message) + 1;
        *alert = realloc(*alert, sizeof(Octet) * (5 + meslen));
        memcpy(*alert + 5, alertmessage->message, sizeof(Octet) * meslen);
    }
}
/* Serializing  GeneratePSKMessage structure */
void serGeneratePSKMessage(OctetString *pskmessage, GeneratePSKMessage *genpskmessage){
    unsigned short idlen = sizeof(Octet);
    if (genpskmessage->id.present == isPresent){
        idlen = (2 + genpskmessage->id.length) * sizeof(Octet);
    }
    *pskmessage = realloc(*pskmessage, sizeof(Octet) * (34 + idlen));
    memcpy(*pskmessage, genpskmessage->random, 32 * sizeof(Octet));
    OctetString id = malloc(sizeof(Octet));
    serPreSharedKeyID(&id, &(genpskmessage->id));
    memcpy(*pskmessage + 32, id, idlen);
    free(id);
}
/* Extension structures */
/* Serializing  RequestCertificateExtension structure */
void serRequestCertificateExtension(OctetString *reqcertext, RequestCertificateExtension *extension){
    unsigned short identifierlen = strlen(extension->identifier) + 1;
    *reqcertext = realloc(*reqcertext, sizeof(Octet) * (1 + identifierlen));
    memcpy(*reqcertext, &(extension->certproctype), 1);
    memcpy(*reqcertext + 1, extension->identifier, sizeof(Octet) * identifierlen);
}
/* Serializing CertificateExtension structure */
void serCertificateExtension(OctetString *certext, CertificateExtension *extension){
    unsigned short certlen = strlen(extension->certificate);
    *certext = realloc(*certext, sizeof(Octet) * (1 + certlen));
    memcpy(*certext, &(extension->format), 1);
    memcpy(*certext + 1, extension->certificate, sizeof(Octet) * certlen);
}
/* Serializing  RequestIdentifierExtension structure */
void serRequestIdentifierExtension(OctetString *reqidext, RequestIdentifierExtension *extension){
    unsigned short idlen = strlen(extension->identifier) + 1;
    *reqidext = realloc(*reqidext, sizeof(Octet) * (1 + idlen));
    memcpy(*reqidext, &(extension->request), 1);
    memcpy(*reqidext + 1, extension->identifier, idlen);
}
/* serializing KeyMechanismExtension */
void serKeyMechanismExtension(OctetString *serext, KeyMechanismExtension *extension){
    memcpy(*serext, &(extension->mechanism), sizeof(Octet));
}