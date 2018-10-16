#include <string.h>

#include "krypt_include/ak_bckey.h"
#include "krypt_include/ak_parameters.h"

#include "fiot_include/fiot_types.h"
#include "fiot_include/tl_session.h"

void update_iFK(Octet iFK, Octet K, Octet CTR, unsigned short m){
    ak_bckey_init_kuznechik_tables();
    struct bckey Key;
    ak_bckey_create_kuznechik(&Key);
    ak_bckey_context_set_ptr(&Key, K, 32, ak_false);
    unsigned long number = m * 2;
    ak_bckey_context_encrypt_ecb(&Key, iFK, iFK, 1 )
}

void init_keys(session_keys *keys, OctetString ATS, OctetString T){
memcpy(keys->ATS, ATS, 64);
memcpy(keys->T, T, 64);
memcpy(keys->eFK, ATS, 32);
memcpy(keys->K, ATS+32, 32);
memset(keys->CTR, 0xff, 8);
memset(keys->CTR+8, 0x00, 8);
update_iFK(keys->iFK, keys->K, keys->CTR, keys->m);
keys->l = 0;
keys->n = 1;
keys->m = 0;
}