#include <string.h>

#include "krypt_include/ak_bckey.h"
#include "krypt_include/ak_parameters.h"
#include "krypt_include/ak_random.h"
#include "krypt_include/ak_mac.h"

#include "fiot_include/fiot_types.h"
#include "fiot_include/serialize_fiot.h"
#include "fiot_include/tl_session.h"

void update_iFK(Octet* iFK, Octet* K, Octet* CTR, unsigned short m){
    // fprintf(stderr, "Updating ifk\n");
    // fprintf(stderr, "ifk before update:\n");
    // for(int i=0; i<32; i++) fprintf(stderr, "%.2x", iFK[i]);
    // fprintf(stderr, "\n");
    struct bckey Key_0;
    ak_bckey_create_kuznechik(&Key_0);
    struct bckey Key_1;
    ak_bckey_create_kuznechik(&Key_1);
    Octet K_buf[32];
    memcpy(K_buf, K, 32);
    ak_bckey_context_set_ptr(&Key_0, K_buf, 32, ak_false);
    unsigned long number = m * 2;
    OctetString p_number = (OctetString) &number;
    memcpy(CTR+ 15, p_number, 1);
    memcpy(CTR+ 14, p_number+1, 1);
    memcpy(CTR+ 13, p_number+2, 1);
    ak_bckey_context_encrypt_ecb(&Key_0, CTR, iFK, 16);
    number = m + 1;
    memcpy(CTR+ 15, p_number, 1);
    memcpy(CTR+ 14, p_number+1, 1);
    memcpy(CTR+ 13, p_number+2, 1);
    memcpy(K_buf, K, 32);
    ak_bckey_context_set_ptr(&Key_1, K_buf, 32, ak_false);
    ak_bckey_context_encrypt_ecb(&Key_1, CTR, iFK + 16, 16);
    memset(CTR+13, 0x00, 3);
    ak_bckey_destroy(&Key_0);
    ak_bckey_destroy(&Key_1);
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
    memset(keys->iFK, 0xff, 32);
    update_iFK(keys->iFK, keys->K, keys->CTR, keys->m);
}


OctetString gen_data_frame(Octet * message, int meslen, session_keys* keys, Frame* frame){
    ak_bckey_init_kuznechik_tables();
    Octet current_key[32];
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
    struct bckey Key_mac;
    struct bckey Key_cipher;
    ak_bckey_create_kuznechik(&Key_mac);
    ak_bckey_create_kuznechik(&Key_cipher);
    // fprintf(stderr, "mac on ifk:\n");
    // for(int i=0; i<32; i++) fprintf(stderr, "%.2x", keys->iFK[i]);
    // fprintf(stderr, "\n");
    memcpy(current_key, keys->iFK, 32);
    ak_bckey_context_set_ptr(&Key_mac, current_key, 32, ak_false);
    ak_bckey_context_mac_gost3413( &Key_mac, serialized, 532, serialized + 534);
    // fprintf(stderr, "ifk after cipher:\n");
    // for(int i=0; i<32; i++) fprintf(stderr, "%.2x", keys->iFK[i]);
    // fprintf(stderr, "\n");
    memcpy(current_key, keys->eFK, 32);
    ak_bckey_context_set_ptr(&Key_cipher, current_key, 32, ak_false);
    ak_bckey_context_xcrypt(&Key_cipher, &serialized[8], &serialized[8], 524, serialized, 8);
    // fprintf(stderr, "New frame\n");
    // for(int i=0; i<550; i++) fprintf(stderr, "%.2x", serialized[i]);
    // fprintf(stderr, "\n");
    return serialized;
}

void update_e_i_FK_lite(session_keys *keys){
    // fprintf(stderr, "Updating e_i_FK lite\n");
    // fprintf(stderr, "ifk before:\n");
    // for(int i=0; i<32; i++) fprintf(stderr, "%.2x", keys->iFK[i]);
    // fprintf(stderr, "\n");
    update_iFK(keys->iFK, keys->K, keys->CTR, keys->m);
    // fprintf(stderr, "ifk after:\n");
    // for(int i=0; i<32; i++) fprintf(stderr, "%.2x", keys->iFK[i]);
    // fprintf(stderr, "\n");
    // fprintf(stderr, "efk before:\n");
    // for(int i=0; i<32; i++) fprintf(stderr, "%.2x", keys->eFK[i]);
    // fprintf(stderr, "\n");
    struct bckey Key_d0;
    struct bckey Key_d1;
    Octet key_buf[32];
    ak_bckey_create_kuznechik(&Key_d0);
    ak_bckey_create_kuznechik(&Key_d1);
    memcpy(key_buf, keys->eFK, 32);
    ak_bckey_context_set_ptr(&Key_d0, key_buf, 32, ak_false);
    fprintf(stderr, "\n");
    unsigned char D0[16] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char D1[16] = {0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ak_bckey_context_encrypt_ecb(&Key_d0, D0, D0, 16);
    // fprintf(stderr, "efk buffer: first part cipher\n");
    // for(int i=0; i<16; i++) fprintf(stderr, "%.2x", D0[i]);
    // fprintf(stderr, "\n");
    memcpy(key_buf, keys->eFK, 32);
    ak_bckey_context_set_ptr(&Key_d1, key_buf, 32, ak_false);
    ak_bckey_context_encrypt_ecb(&Key_d1, D1, D1, 16);
    // fprintf(stderr, "efk buffer: second part cipher\n");
    // for(int i=0; i<16; i++) fprintf(stderr, "%.2x", D1[i]);
    // fprintf(stderr, "\n");
    memcpy(keys->eFK, D0, 16);
    memcpy(keys->eFK + 16, D1, 16);
    // fprintf(stderr, "efk after:\n");
    // for(int i=0; i<32; i++) fprintf(stderr, "%.2x", keys->eFK[i]);
    // fprintf(stderr, "\n");
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
    if (keys->l != maxFrameCount)
        return 0;
    keys->m++;
    if (keys->m != maxFrameKeysCount + 1){
        keys->l = 0;
        update_e_i_FK_lite(keys);
        return 0;}
    keys->n++;
    if (keys->n != maxApplicationSecretCount + 1){
        keys->m = 0;
        keys->l = 0;
        update_ATS(keys);
        update_e_i_FK_full(keys);
        return 0;}
    exit(1);
}


int decrypt_frame(Octet * frame, int len, session_keys *keys){
    ak_bckey_init_kuznechik_tables();
    // fprintf(stderr, "Decrypting frame\n");
    // for(int i=0; i<len; i++) fprintf(stderr, "%.2x", frame[i]);
    // fprintf(stderr, "\n");

    if (frame[0] != encryptedFrame) exit(1);
    unsigned short framelen = frame[1];
    framelen = (framelen << 8) | frame[2];
    // fprintf(stderr, "frame length is %d\n", framelen);
    if (framelen != len) exit(2);
    unsigned short num_n = frame[3];
    unsigned short num_m = frame[4];
    num_m = (num_m << 8) | frame[5];
    unsigned short num_l = frame[6];
    num_l = (num_l << 8) | frame[7];
    if (keys->l != num_l || keys->m != num_m || keys->n != num_n) exit(3);
    struct bckey Key_mac;
    struct bckey Key_cipher;
    unsigned char mac[16];
    ak_bckey_create_kuznechik(&Key_mac);
    ak_bckey_create_kuznechik(&Key_cipher);
    // fprintf(stderr, "mac on ifk:\n"); 
    // for(int i=0; i<32; i++) fprintf(stderr, "%.2x", keys->iFK[i]);
    // fprintf(stderr, "\n");
    Octet current_key[32];
    memcpy(current_key, keys->eFK, 32);
    ak_bckey_context_set_ptr(&Key_cipher, current_key, 32, ak_false);
    ak_bckey_context_xcrypt(&Key_cipher, &frame[8], &frame[8], framelen - 26, frame, 8);
    // fprintf(stderr, "Decrypted frame\n");
    // for(int i=0; i<len; i++) fprintf(stderr, "%.2x", frame[i]);
    // fprintf(stderr, "\n");
    memcpy(current_key, keys->iFK, 32);
    // fprintf(stderr, "mac key:\n");
    // for(int i=0; i<32; i++) fprintf(stderr, "%.2x", current_key[i]);
    // fprintf(stderr, "\n");
    ak_bckey_context_set_ptr(&Key_mac, current_key, 32, ak_false);
    ak_bckey_context_mac_gost3413(&Key_mac, frame, framelen - 18, mac);
    if(memcmp(&frame[framelen-16], mac, 16) != 0){
        fprintf(stderr, "wrong mac\n");
        exit(3);}
    // for(int i=0; i<len; i++) fprintf(stderr, "%.2x", frame[i]);
    // fprintf(stderr, "\n");
    unsigned short meslen = frame[9];
    meslen = (meslen << 8) | frame[10];
    return meslen;
    

}