void serLengthShortInt(Octet *length, unsigned short number);
void serEllipticCurvePoint(OctetString *point, EllipticCurvePoint *curve);
void serPreSharedKeyID(OctetString *keyid, PreSharedKeyID *pskID);
void serIntegrityCode(OctetString *keyid, IntegrityCode *icode);
void serFrame(OctetString *serframe, Frame *frame);
