#include <string.h>

#include "krypt_include/ak_bckey.h"
#include "krypt_include/ak_parameters.h"
#include "krypt_include/ak_random.h"
#include "krypt_include/ak_mac.h"

#include "fiot_include/fiot_types.h"
#include "fiot_include/serialize_fiot.h"
#include "fiot_include/tl_session.h"

void update_iFK(Octet* iFK, Octet* K, Octet* CTR, unsigned short m){
    ak_bckey_init_kuznechik_tables();
    struct bckey Key;
    ak_bckey_create_kuznechik(&Key);
    ak_bckey_context_set_ptr(&Key, &K, 32, ak_false);
    
    unsigned long number = m * 2;
    OctetString p_number = (OctetString) &number;
    memcpy(CTR+ 15, p_number, 1);
    memcpy(CTR+ 14, p_number+1, 1);
    memcpy(CTR+ 13, p_number+2, 1);
    ak_bckey_context_encrypt_ecb(&Key, &CTR, &iFK, 16);
    number = m + 1;
    memcpy(CTR+ 15, p_number, 1);
    memcpy(CTR+ 14, p_number+1, 1);
    memcpy(CTR+ 13, p_number+2, 1);
    ak_bckey_context_encrypt_ecb(&Key, &CTR, &iFK + 16, 16);
    memset(CTR+13, 0x00, 3);
    ak_bckey_destroy(&Key);
}


void init_keys(session_keys *keys, OctetString ATS, OctetString T){
memcpy(keys->ATS, ATS, 64);
memcpy(keys->T, T, 64);
memcpy(keys->eFK, ATS, 32);
memcpy(keys->K, ATS+32, 32);
memset(keys->CTR, 0xff, 8);
memset(keys->CTR+8, 0x00, 8);
keys->l = 0;
keys->n = 1;
keys->m = 0;
update_iFK(keys->iFK, keys->K, keys->CTR, keys->m);
}


OctetString gen_data_frame(Octet * message, int meslen, session_keys* keys, Frame* frame){
    frame->message = message;
    serLengthShortInt(frame->meslen, meslen);
    int padlen = 521 - meslen;
    OctetString padding = malloc(padlen);
    struct random random;
    ak_random_create_lcg(&random);
    ak_buffer buf = ak_buffer_new_size(padlen);
    ak_buffer_set_random(buf, &random);
    ak_random_destroy(&random);
    memcpy(padding, buf->data, padlen);
    frame->padding = padding;
    memcpy(&frame->number, &keys->n, 1);
    serLengthShortInt(&frame->number[1], keys->m);
    serLengthShortInt(&frame->number[3], keys->l);
    ak_buffer_delete(buf);
    OctetString serialized = malloc(1);
    serFrame(&serialized, frame);
    free(padding);
    printf("Ser App Frame:\n");
    for(int i=0;i<550;i++) printf("%.2x", serialized[i]);
    printf("\n");
    ak_bckey_init_kuznechik_tables();
    struct bckey Key;
    ak_bckey_create_kuznechik(&Key);
    ak_bckey_context_set_ptr(&Key, keys->iFK, 32, ak_false);
    ak_bckey_context_mac_gost3413( &Key, serialized, 532, serialized + 534);
    ak_bckey_context_set_ptr(&Key, keys->eFK, 32, ak_false);
    ak_bckey_context_xcrypt(&Key, &serialized[8], &serialized[8], 524, serialized, 8);
    return serialized;
}

void update_e_i_FK_lite(session_keys *keys){
    update_iFK(keys->iFK, keys->K, keys->CTR, keys->m);
    ak_bckey_init_kuznechik_tables();
    struct bckey Key;
    ak_bckey_create_kuznechik(&Key);
    ak_bckey_context_set_ptr(&Key, keys->eFK, 32, ak_false);
    OctetString new_eFK = malloc(32);
    unsigned char D[2] = {0x80, 0x81};
    ak_bckey_context_encrypt_ecb(&Key, D, new_eFK, 1);
    ak_bckey_context_encrypt_ecb(&Key, D + 1, new_eFK + 16, 1);
    memcpy(keys->eFK, new_eFK, 32);
    free(new_eFK);

}

void update_ATS(session_keys *keys){
    OctetString data = malloc(33);
    memcpy(data, keys->ATS, 32);
    memcpy(data + 32, &keys->n, 1);
    struct mac mctx;
    ak_mac_create_hmac_streebog512(&mctx);
    ak_mac_context_set_ptr( &mctx, keys->T, 64);
    ak_mac_context_ptr( &mctx, data, 33, keys->ATS);
}


void update_e_i_FK_full(session_keys *keys){
    memcpy(keys->eFK, keys->ATS, 32);
    memcpy(keys->K, keys->ATS + 32, 32);
    update_iFK(keys->iFK, keys->K, keys->CTR, keys->m);
}


int update_keys(session_keys *keys){
    keys->l++;
    if (keys->l != maxFrameCount-1)
        return 0;
    keys->m++;
    if (keys->m != maxFrameKeysCount){
        keys->l = 0;
        update_e_i_FK_lite(keys);
        return 0;}
    keys->n++;
    if (keys->n != maxApplicationSecretCount){
        keys->m = 0;
        update_ATS(keys);
        update_e_i_FK_full(keys);
        return 0;}
    exit(1);
}


int decrypt_frame(Octet * frame, int len, session_keys *keys){
    if (frame[0] != encryptedFrame) exit(1);
    unsigned short framelen = frame[1];
    framelen = (framelen << 8) | frame[2];
    if (framelen != len) exit(2);
    unsigned short num_n = frame[3];
    unsigned short num_m = frame[4];
    num_m = (num_m << 8) | frame[5];
    unsigned short num_l = frame[6];
    num_l = (num_l << 8) | frame[7];
    if (keys->l != num_l || keys->m != num_m || keys->n != num_n) exit(3);
    ak_bckey_init_kuznechik_tables();
    struct bckey Key;
    unsigned char mac[16];
    ak_bckey_create_kuznechik(&Key);
    ak_bckey_context_set_ptr(&Key, keys->eFK, 32, ak_false);
    ak_bckey_context_xcrypt(&Key, &frame[8], &frame[8], framelen- 26, frame, 8);
    ak_bckey_context_set_ptr(&Key, keys->iFK, 32, ak_false);
    ak_bckey_context_mac_gost3413(&Key, frame, framelen - 18, mac);
    if(memcmp(&frame[framelen-16], mac, 16) != 0) exit(3);
    unsigned short meslen = frame[9];
    meslen = (meslen << 8) | frame[10];
    return meslen;
    

}