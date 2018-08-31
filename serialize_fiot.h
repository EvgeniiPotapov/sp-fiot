#define  serSetCertificateExtension serRequestCertificateExtension
void serLengthShortInt(Octet *length, unsigned short number);
void serEllipticCurvePoint(OctetString *point, EllipticCurvePoint *curve);
void serPreSharedKeyID(OctetString *keyid, PreSharedKeyID *pskID);
void serIntegrityCode(OctetString *keyid, IntegrityCode *icode);
void serFrame(OctetString *serframe, Frame *frame);
void serClientHelloMessage(OctetString *clienthello, ClientHelloMessage *clientmessage);
void serServerHelloMessage(OctetString *serverhello, ServerHelloMessage *servermessage);
void serVerifyMessage(OctetString *message, VerifyMessage *verify);
void serAlertMessage(OctetString *alert, AlertMessage *alertmessage);
void serGeneratePSKMessage(OctetString *pskmessage, GeneratePSKMessage *genpskmessage);
void serRequestCertificateExtension(OctetString *reqcertext, RequestCertificateExtension *extension);
void serCertificateExtension(OctetString *certext, CertificateExtension *extension);
void serRequestIdentifierExtension(OctetString *certext, RequestIdentifierExtension *extension);

