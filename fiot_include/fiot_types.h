/* Base data types */
#pragma pack(push, 1)
/* Octet - minimal amount of data that could be transferred */
typedef unsigned char Octet;
/* OctetString - a finite sequence of Octets */
typedef Octet *OctetString;
/* LengthOctet is desired to define non-negative integers in range [0, 255], sequence length as usual */
typedef Octet LengthOctet;
/* LengthShortInt is desired to define non-negative integers in range [0, 65535], sequence length as usual */
typedef Octet LengthShortInt[2];
/* RandomOctetString defines fixed-length sequence containing random generated data */
typedef Octet RandomOctetString[32];

/*-------------------------------------------------------------------*/
/* Enumerated and service data types */

/* FrameType defines if the transferred data frame is encrypted or not */
typedef enum {
    plainFrame = 0xA0,
    encryptedFrame = 0xA2
} FrameType;

/* PresentType defines if some optional variable is specified or not */
typedef enum {
    notPresent = 0xB0,
    isPresent = 0xB1
} PresentType;

/* RequestType defines if user ID is requested or not */
typedef enum {
    notRequested = 0xB0,
    isRequested = 0xB1
} RequestType;

/* CertificateFormat defines the electronic signature verification key certificate type */
typedef enum {
/* Serialized EllipticCurvePoint data type (OctetString) */
    plain = 0x10,
/* x.509 certificate type */
    x509 = 0x19,
/* cvc certificate type */
    cvc = 0x20
} CertificateFormat;

/* CertificateProcessedType defines which electronic signature verification key certificate will be provided */
typedef enum {
/* any valid certificate */
    any = 0x00,
/* valid certificate with specified number */
    number = 0x10,
/* valid certificate with specified Certification Authority (CA) */
    issuer = 0x20
} CertificateProcessedType;

/* Certificate defines the finite-length Octet sequence for certificate containing */
typedef OctetString Certificate;

/* MessageType defines current transferring frame type */
typedef enum {
/* ClientHelloMessage structure defines the message format used by client when initializing protected interaction */
    clientHello = 0x11,
/* ServerHelloMessage structure defines the message format used by server to answer the ClientHelloMessage */
    serverHello = 0x12,
/* VerifyMessage structure defines the message format containing one or more authentication codes */
    verifyMessage = 0x13,
/* ApplicationDataMessage structure defines the message format used during application data transfer protocol execution */
    applicationData = 0x14,
/* AlertMessage structure defines the message format containing protocol execution error code */
    alert = 0x15,
/* GeneratePSKMessage structure defines the message format used in authentication key generating process */
    generatePSK = 0x16,
/* RequestCertificateExtension structure defines the extension format used to request the electronic
signature verification key certificate */
    extensionRequestCertificate = 0x21,
/* CertificateExtension structure defines the extension format used to transfer the electronic signature
verification key certificate */
    extensionCertificate = 0x22,
/* SetCertificateExtension structure defines the extension format used to specify the electronic signature
verification key certificate */
    extensionSetCertificate = 0x23,
/* InformCertificateExtension structure defines the extension format used to specify the electronic signature
verification key certificate number */
    extensionInformCertificate = 0x24,
/* RequestIdentifierExtension structure defines the extension format used to request and/or specify user ID */
    extensionRequestIdentifer = 0x25,
/* KeyMechanismExtension structure defines the extension format used to specify derived key generating cryptographic mechanisms */
    extensionKeyMechanism = 0x26
} MessageType;

/* CryptoMechanism is desired to specify cryptographic mechanisms used by client and server */
typedef enum {
    streebog256 = 0x0013,
    streebog512 = 0x0023,
    magmaGOST3413ePSK = 0x2051,
    kuznechikGOST3413ePSK = 0x2052,
    magmaGOST3413iPSK = 0x3101,
    kuznechikGOST3413iPSK = 0x3102,
    hmac256ePSK = 0x2033,
    hmac512ePSK = 0x2043,
    hmac256iPSK = 0x3033,
    hmac512iPSK = 0x3043,
    magmaCTRplusHMAC256 = 0x1131,
    magmaCTRplusGOST3413 = 0x1151,
    kuznechikCTRplusHMAC256 = 0x1132,
    kuznechikCTRplusGOST3413 = 0x1152,
    magmaAEAD = 0x1201,
    kuznechikAEAD = 0x1202
} CryptoMechanism; 

/* EllipticCurveID specifies used elliptic curve parameters */
typedef enum {
    tc26_gost3410_2012_256_paramsetA = 0x01,
    tc26_gost3410_2012_512_paramsetA = 0x02,
    tc26_gost3410_2012_512_paramsetB = 0x03,
    tc26_gost3410_2012_512_paramsetC = 0x04,
    rfc4357_gost3410_2001_paramsetA = 0x05,
    rfc4357_gost3410_2001_paramsetB = 0x06,
    rfc4357_gost3410_2001_paramsetC = 0x07
} EllipticCurveID; 

/*  EllipticCurvePoint defines data structure used to contain elliptic curve point specified by two coordinates */
typedef struct _EllipticCurvePoint{
/* ID of elliptic curve which the point lies on */
    EllipticCurveID id;
/* x(u) point coordinate given in canonical Weierstrass (twisted Edwards) curve form, length = 32(64) Octets for 256(512) bit curve */
    OctetString x;
/* y(v) point coordinate given in canonical Weierstrass (twisted Edwards) curve form, length = 32(64) Octets for 256(512) bit curve */
    OctetString y;
} EllipticCurvePoint;

/* PreSharedKeyID structure is specified to store and transfer the pre-shared symmetric key ID */
typedef struct _PreSharedKeyID{
/* Indicates if ID is specified */
    PresentType present;
    LengthOctet length;
    OctetString id;
} PreSharedKeyID; 

/* IntegrityCode specifies a structure used to transfer message authentication code (MAC) */
typedef struct _IntegrityCode{
/* Indicates if integrity code is specified */
    PresentType present;
    LengthOctet length;
    OctetString code;
} IntegrityCode;

/* FrameNumber defines the five-Octet sequence specified for frame cryptographic number indication */
typedef Octet FrameNumber[5];

/* KeyMechanismType specifies values for key transformation and derive key generating algorithms used by transport protocol */
typedef enum {
    standard221 = 0x01,
    shortKCmagma = 0x02,
    shortKCkuznechik = 0x03,
    longKCmagma = 0x04,
    longKCkuznechik = 0x05,
    shortKAmagma = 0x06,
    shortKAkuznechik = 0x07,
    longKAmagma = 0x08,
    longKAkuznechik = 0x09
} KeyMechanismType;

/* AlertType specifies error codes */
typedef enum { 
    unknownError = 0x1000,
    unsupportedCryptoMechanism = 0x1001,
    wrongExternalPreSharedKey = 0x1002,
    wrongInternalPreSharedKey = 0x1003,
    wrongIntegrityCode = 0x1004,
    lostIntegrityCode = 0x1005,
    wrongCertificateProcessed = 0x100a,
    wrongCertificateNumber = 0x100b,
    expiredCertificate = 0x100c,
    unsupportedCertificateNumber = 0x100d,
    notValidCertificateNumber = 0x100e,
    wrongCertificateApplication = 0x100f,
    wrongCertificateIssuer = 0x1010,
    unsupportedCertificateIssuer = 0x1011,
    unsupportedCertificateFormat = 0x1012,
    wrongCertificateIntegrityCode = 0x1013,
    usupportedKeyMechanism = 0x1020,
    unsupportedEllipticCurveID = 0x1031,
    wrongEllipticCurvePoint = 0x1032,
    wrongInternalPSKIdentifier = 0x1040
} AlertType;

/*-------------------------------------------------------------------*/
/* Transport protocol message format */

/* Frame structure defines the container used for data transmission */
typedef struct _Frame{
/* tag defines type of the frame */
    FrameType tag;
/* length defines the whole Frame length in Octets */
    LengthShortInt length;
/* number defines the Frame cryptographic number */
    FrameNumber number;
/* type defines the message type of frame enclosed data */
    MessageType type;
/* meslen defines the length of the enclosed message */
    LengthShortInt meslen;
/* message is the data itself */
    OctetString message;
/* padding defines the finite-length octet sequence */
    OctetString padding;
/* icode defines the MAC */
    IntegrityCode icode;
} Frame;

/*-------------------------------------------------------------------*/
/*  Session layer message format */

/* ClientHelloMessage defines the initial message from client */
typedef struct _ClientHelloMessage{
/* algorithm defines one of CryptoMechanism used to validate unencrypted data integrity */
    CryptoMechanism algorithm;
/* iPSK specifies the ID of auntication key generated during the previous session. */
    PreSharedKeyID idipsk;
/* ePSK specifies the ID of pre-shared auntication key  */
    PreSharedKeyID idepsk;
/* random defines the fixed-length octets sequence */
    RandomOctetString random;
/* point specifies the elliptic curve point used in Diffie–Hellman key generation protocol */
    EllipticCurvePoint point;

/* countOfExtensions defines the number of extensions that will be sent after ClientHelloMessage */
    LengthOctet countOfExtensions;
} ClientHelloMessage;

/* ServerHelloMessage defines the server-side answer to ClientHelloMessage */
typedef struct _ServerHelloMessage{
/* algorithm defines one of cipher mechanisms with MAC generation option */
    CryptoMechanism algorithm;
/* random defines the fixed-length octets sequence */
    RandomOctetString random;
/* point specifies the elliptic curve point used in Diffie–Hellman key generation protocol */
    EllipticCurvePoint point;
/* countOfExtensions defines the number of extensions that will be sent to the client after ServerHelloMessage */
    LengthOctet countOfExtensions;
} ServerHelloMessage;

/* VerifyMessage defines a message used by both client and server to verify each other during key generation protocol */
typedef struct _VerifyMessage{
/* mac defines the message authentication code value */
    IntegrityCode mac;
/* sign defines the digital signature value */
    IntegrityCode sign;
} VerifyMessage;

/* ApplicationDataMessage contains the application layer data */
typedef OctetString ApplicationDataMessage; 

/* AlertMessage defines the message format used by both client and server in case of errors or incorrect data */
typedef struct _AlertMessage{
/* code defines the error code */
    AlertType code;
/* algorithm defines the cryptographic mechanism ID used to control the message integrity */
    CryptoMechanism algorithm;
/* present specifies if there is an optional text message */
    PresentType present;
/* message defines the optional text message */
    OctetString message;
} AlertMessage;

/* GeneratePSKMessage defines message format used by both client and server during authentication key generation protocol */
typedef struct _GeneratePSKMessage{
/* random defines the fixed-length octets sequence */
    RandomOctetString random;
/* id specifies the generated iPSK ID */
    PreSharedKeyID id;
} GeneratePSKMessage;

/*-------------------------------------------------------------------*/
/* Extensions format */

/* RequestCertificateExtension defines the extension used both by server and client to request digital signature validation certificates */
typedef struct _RequestCertificateExtension{
/* certproctype is used to specify certificate parameters */
    CertificateProcessedType certproctype;
/* identifier is the Octet sequence which specifies the requested certificate */
    OctetString identifier;
} RequestCertificateExtension;

/* CertificateExtension defines the extension used both by server and client to send digital signature validation certificates */
typedef struct _CertificateExtension{
/* format specifies the digital signature validation certificate format */
    CertificateFormat format;
/* certificate defines the Octet sequence containing the certificate */
    Certificate certificate;
} CertificateExtension;

/*  SetCertificateExtension defines extension format used both by server and client to inform each other about chosen certificate */
typedef struct _SetCertificateExtension{
/* certproctype is used to specify certificate parameters */
    CertificateProcessedType certproctype;
/* identifier is the Octet sequence which specifies the requested certificate */
    OctetString identifier;
} SetCertificateExtension;

/* InformCertificateExtension defines the extension format used both by server and client to specify certificate number */
typedef OctetString InformCertificatleExtension;

/* RequestIdentifierExtension defines the extension format used both by server and client to request or send client/server ID */
typedef struct _RequestIdentifierExtension{
/* request specifies if the ID is requested or sent */
    RequestType request;
/* identifier defines the Octet sequence containing ID */
    OctetString identifier;
} RequestIdentifierExtension; 

/* KeyMechanismExtension is used to specify derive key generation cryptographic mechanisms */
typedef struct _KeyMechanismExtension{
    KeyMechanismType mechanism; 
} KeyMechanismExtension;
#pragma pack(pop)
