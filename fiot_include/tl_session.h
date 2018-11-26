#define maxFrameCount 512 //max L frame number value
#define maxFrameKeysCount 512 // max m frame number value
#define maxApplicationSecretCount 128 // max n frame number value
#define RAW_PACKET 64000
#define FIOT_PACKET RAW_PACKET + 38
#define PADDING 9

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
OctetString gen_data_frame(Octet * message, int meslen, session_keys* keys, Frame* frame);
int update_keys(session_keys *keys);
int decrypt_frame(Octet * frame, int len, session_keys *keys);