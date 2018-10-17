#define maxFrameCount 128 //max L frame number value
#define maxFrameKeysCount 16 // max m frame number value
#define maxApplicationSecretCount 16 // max n frame number value

typedef struct _session_keys{
    unsigned char ATS[64]; // CATS or SATS
    unsigned char eFK[32]; // eCFK or eSFK
    unsigned char T[64];
    unsigned char K[32]; // Ck or SK
    unsigned char CTR[16];
    unsigned char iFK[32]; // iCFK or iSFK
    unsigned char n;
    unsigned short m;
    unsigned short l;
} session_keys;

void init_keys(session_keys *keys, OctetString ATS, OctetString T);