typedef struct _session_keys{
/* Indicates if ID is specified */
    unsigned char ATS[64];
    unsigned char eFK[32];
    unsigned char T[64];
    unsigned char K[32];
    unsigned char CTR[16];
    unsigned char iFK[32];
    unsigned char n;
    unsigned short m;
    unsigned short l;
} session_keys;

void init_keys(session_keys *keys, OctetString ATS, OctetString T);