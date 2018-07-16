/* Base data types */
/* Octet - minimal amount of data that could be transferred */
typedef unsigned char Octet;
/* OctetString - a finite sequence of Octets */
typedef octet *OctetString;
/* LengthOctet is desired to define non-negative integers in range [0, 255], sequence length as usual */
typedef Octet LengthOctet;
/* LengthShortInt is desired to define non-negative integers in range [0, 65535], sequence length as usual */
typedef Octet LengthShortInt[2];
/* RandomOctetString defines fixed-length sequence containing random generated data */
typedef Octet RandomOctetString[32];

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
    verify = 0x13,
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
    streebog256 = 0x0010,
    streebog512 = 0x0020,
    magmaGOST3413ePSK = 0x2051,
    kuznechikGOST3413ePSK = 0x2052,
    magmaGOST3413iPSK = 0x3101,
    kuznechikGOST3413iPSK = 0x3102,
    hmac256ePSK = 0x2030,
    hmac512ePSK = 0x2040,
    hmacStreebog256iPSK = 0x3030,
    hmacStreebog512iPSK = 0x3040,
    magmaCTRplusOMAC = 0x1151,
    kuznechikCTRplusOMAC = 0x1152,
    magmaAEAD = 0x1201,
    kuznechikAEAD = 0x1202,
} CryptoMechanism; 

/* EllipticCurveID specifies used elliptic curve parameters */
typedef enum {
    id-tc26-gost3410-2012-256-paramsetA = 0x01,
    id-tc26-gost3410-2012-512-paramsetA = 0x02,
    id-tc26-gost3410-2012-512-paramsetB = 0x03,
    id-tc26-gost3410-2012-512-paramsetC = 0x04,
    id-rfc4357-gost3410-2001-paramsetA = 0x05,
    id-rfc4357-gost3410-2001-paramsetB = 0x06,
    id-rfc4357-gost3410-2001-paramsetC = 0x07
} EllipticCurveID; 

/*  EllipticCurvePoint defines data structure used to contain elliptic curve point specified by two coordinates */
typedef struct {
/* ID of elliptic curve which the point lies on */
    EllipticCurveID id;
/* x(u) point coordinate given in canonical Weierstrass (twisted Edwards) curve form, length = 32(64) Octets for 256(512) bit curve */
    OctetString x;
/* y(v) point coordinate given in canonical Weierstrass (twisted Edwards) curve form, length = 32(64) Octets for 256(512) bit curve */
    OctetString y;
} EllipticCurvePoint;

/* PreSharedKeyID structure is specified to store and transfer the pre-shared symmetric key ID */
typedef struct {
/* Indicates if ID is specified */
    PresentType present;
    LengthOctet length;
    OctetString id;
} PreSharedKeyID; 

/* IntegrityCode specifies a structure used to transfer message authentication code (MAC) */
typedef struct {
/* Indicates if integrity code is specified */
    PresentType present;
    LengthOctet length;
    OctetString code;
} IntegrityCode;

/* FrameNumber defines the five-Octet sequence specified for frame cryptographic number indication */
typedef Octet FrameNumber[5];





























