#include <stdio.h> 
#include <stdlib.h>
#include <string.h>

#include "krypt_include/libakrypt.h"
#include "krypt_include/ak_random.h"
#include "krypt_include/ak_buffer.h"
#include "krypt_include/ak_curves.h"
#include "krypt_include/ak_parameters.h"
#include "krypt_include/ak_mac.h"
#include "krypt_include/ak_bckey.h"

#include "fiot_include/fiot_types.h"
#include "fiot_include/serialize_fiot.h"
#include "fiot_include/gench.h"

OctetString genClientHello(RandomOctetString k_client){
    ClientHelloMessage clientHello;

    clientHello.algorithm = hmac256ePSK;
    clientHello.idipsk.present = notPresent;
    clientHello.idepsk.present = isPresent;
    clientHello.idepsk.length = 8;
    clientHello.idepsk.id =  "Session0";

    struct random random;
    ak_random_create_lcg(&random);
    ak_buffer buf = ak_buffer_new_size(64);
    ak_buffer_set_random(buf, &random);
    ak_random_destroy(&random);
    memcpy(clientHello.random, buf->data, 32);
    memcpy(k_client, buf->data + 32, 32);
    ak_buffer_delete(buf);

    clientHello.point.id = rfc4357_gost3410_2001_paramsetA;

    struct wpoint elliptic_point;
    ak_wpoint_pow(&elliptic_point,
                  (ak_wpoint) &id_rfc4357_gost3410_2001_paramsetA.point,
                  (ak_uint64 *)k_client,
                  ak_mpzn256_size,
                  (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);

    ak_wpoint_reduce( &elliptic_point, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);
    clientHello.point.x = (OctetString) elliptic_point.x;
    clientHello.point.y = (OctetString) elliptic_point.y;
    clientHello.countOfExtensions = 0;
    OctetString serClientHello = malloc(1);
    serClientHelloMessage(&serClientHello, &clientHello);
    return serClientHello;
}

OctetString genHelloFrame(OctetString message){
    Frame helloFrame;

    helloFrame.tag = plainFrame;
    serLengthShortInt(helloFrame.length, 160);
    memset(helloFrame.number, 0x00, 5);
    helloFrame.type = clientHello;
    serLengthShortInt(helloFrame.meslen, 111);
    helloFrame.message = message;
    helloFrame.padding = "1234";
    helloFrame.icode.present = isPresent;
    helloFrame.icode.length = 32;
    helloFrame.icode.code = "DummyboxDummyboxDummyboxDummybox";
    OctetString serframe = malloc(1);
    serFrame(&serframe, &helloFrame);
    struct mac mctx;
    ak_mac_create_hmac_streebog256(&mctx);
    ak_mac_context_set_ptr(&mctx, "Session0CanBeTheOneToMakeAStable", 32);
    OctetString hmac = malloc(32);
    ak_mac_context_ptr( &mctx, serframe, 126, hmac);

    ak_mac_destroy( &mctx );
    memcpy(&serframe[128], hmac, 32);

    free(hmac);
    return serframe;
}

OctetString getClient_hello(RandomOctetString k_client){
    OctetString hello = genClientHello(k_client);
    OctetString serhello = genHelloFrame(hello);
    return serhello;
}


void check_server_hello(OctetString hello){
    struct mac mctx;
    ak_mac_create_hmac_streebog256( &mctx );
    ak_mac_context_set_ptr( &mctx, "Session0CanBeTheOneToMakeAStable", 32);
    OctetString hmac = malloc(32);
    ak_mac_context_ptr( &mctx, hello, 126, hmac);
    ak_mac_destroy( &mctx );
    int i = memcmp(&hello[128], hmac, 32);
    if(i != 0){
        printf("\nIncorrect mac\n");
        exit(2);
    }

    char z_coor[32] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct wpoint c_point;
    memcpy(&c_point.x, &hello[46], 32);
    memcpy(&c_point.y, &hello[78], 32);
    memcpy(&c_point.z, z_coor, 32);
    i = ak_wpoint_is_ok((ak_wpoint) &c_point, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);
    if(i != 1){
        printf("\nIncorrect curve point\n");
        exit(1);
    }
}

OctetString takeSHTS(OctetString R1, OctetString H1){
    OctetString bogR1 = malloc(64);
    OctetString bogH1 = malloc(64);
    struct hash hctx;
    ak_hash_create_streebog512(&hctx);
    ak_hash_context_ptr(&hctx, R1, 64, bogR1);
    ak_hash_context_ptr(&hctx, H1, 211, bogH1);
    ak_hash_destroy(&hctx);
    struct mac mctx;
    ak_mac_create_hmac_streebog512(&mctx);
    ak_mac_context_set_ptr( &mctx, bogR1, 64);
    OctetString SHTS = malloc(64);
    ak_mac_context_ptr( &mctx, bogH1, 64, SHTS);
    ak_mac_destroy(&mctx);
    free(bogR1);
    free(bogH1);
    return SHTS;

}


OctetString gen_SHTS(RandomOctetString k_client, OctetString server_hello, OctetString client_hello, OctetString R1){
    struct wpoint client_point;
    struct wpoint q_point;
    char z_coor[32] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(&client_point.x, &server_hello[46], 32);
    memcpy(&client_point.y, &server_hello[78], 32);
    memcpy(&client_point.z, z_coor, 32);
    ak_wpoint_pow(&q_point,
                  (ak_wpoint) &client_point,
                  (ak_uint64 *)k_client,
                  ak_mpzn256_size,
                  (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);

    ak_wpoint_reduce( &q_point, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);
    
    memcpy(R1, q_point.x, 32);
    memcpy(R1 + 32, "Session0CanBeTheOneToMakeAStable", 32);
    
    OctetString H1 = malloc(211);
    memcpy(H1, client_hello + 11, 111);
    memcpy(H1 + 111, server_hello+11, 100);
    OctetString SHTS = takeSHTS(R1, H1);
    return SHTS;
}


OctetString check_verify_frame(OctetString buf, OctetString eSHTK, OctetString iSHTK, OctetString c_hello, OctetString s_hello){
    ak_bckey_init_kuznechik_tables();
    struct bckey Key;
    unsigned char mac[16];
    ak_bckey_create_kuznechik(&Key);
    ak_bckey_context_set_ptr(&Key, eSHTK, 32, ak_false);
    ak_bckey_context_xcrypt(&Key, &buf[8], &buf[8], 34, buf, 8);
    ak_bckey_context_set_ptr(&Key, iSHTK, 32, ak_false);
    ak_bckey_context_mac_gost3413( &Key, buf, 42, mac );
    int i = memcmp(&buf[44], mac, 16);
    if(i != 0){
        printf("\nIncorrect mac\n");
        exit(2);
    }
    unsigned char code[16];
    memcpy(code, &buf[13], 16);
    
    OctetString H2 = malloc(211);
    memcpy(H2, c_hello + 11, 111);
    memcpy(H2 + 111, s_hello+11, 100);
    OctetString bogH2 = malloc(64);
    struct hash hctx;
    ak_hash_create_streebog512(&hctx);
    ak_hash_context_ptr(&hctx, H2, 211, bogH2);
    ak_hash_destroy(&hctx);
    i = memcmp(code, bogH2, 16);
    if(i != 0){
        printf("\nIncorrect mac.code\n");
        exit(2);
    }
    free(bogH2);
    return buf;
}

OctetString gen_CHTS(OctetString verifyframe, OctetString c_hello, OctetString s_hello, OctetString R1, OctetString H3){
    memcpy(H3, c_hello + 11, 111);
    memcpy(H3 + 111, s_hello+11, 100);
    memcpy(H3 + 211, verifyframe + 11, 19);
    OctetString CHTS = takeSHTS(R1, H3);
    return CHTS;
}
OctetString genVerifyFrame(OctetString verify, OctetString eSHTK, OctetString iSHTK){
    Frame verifyFrame;
    verifyFrame.tag = encryptedFrame;
    serLengthShortInt(verifyFrame.length, 60);
    memset(verifyFrame.number, 0x00, 5);
    serLengthShortInt(&verifyFrame.number[1], 1);
    verifyFrame.type = verifyMessage;
    serLengthShortInt(verifyFrame.meslen, 19);
    verifyFrame.padding = "335555555533";
    verifyFrame.message = verify;
    verifyFrame.icode.present = isPresent;
    verifyFrame.icode.length = 16;
    verifyFrame.icode.code = "0DefaultDefault0";
    OctetString serframe = malloc(1);
    serFrame(&serframe, &verifyFrame);
    ak_bckey_init_kuznechik_tables();
    struct bckey Key;
    ak_bckey_create_kuznechik(&Key);
    ak_bckey_context_set_ptr(&Key, iSHTK, 32, ak_false);
    ak_bckey_context_mac_gost3413( &Key, serframe, 42, &serframe[44] );
    ak_bckey_context_set_ptr(&Key, eSHTK, 32, ak_false);
    ak_bckey_context_xcrypt(&Key, &serframe[8], &serframe[8], 34, serframe, 8);
    return serframe;
}

OctetString genVerify(OctetString H4){
    OctetString bogH4 = malloc(64);
    struct hash hctx;
    ak_hash_create_streebog512(&hctx);
    ak_hash_context_ptr(&hctx, H4, 230, bogH4);
    ak_hash_destroy(&hctx);
    VerifyMessage verify;
    OctetString cutbogH4 = malloc(16);
    memcpy(cutbogH4, bogH4, 16);
    free(bogH4);
    verify.sign.present = notPresent;
    verify.mac.present = isPresent;
    verify.mac.length = 16;
    verify.mac.code = cutbogH4;
    OctetString serVerify = malloc(1);
    serVerifyMessage(&serVerify, &verify);
    return serVerify;
}

void make_session_keys(OctetString xQ, OctetString R2, OctetString H5, OctetString SATS, OctetString CATS, OctetString T){
    struct mac mctx;
    ak_mac_create_hmac_streebog512(&mctx);
    ak_mac_context_set_ptr( &mctx, xQ, 32);
    ak_mac_context_ptr( &mctx, R2, 40, T);

    OctetString A0 = malloc(64);
    struct hash hctx;
    ak_hash_create_streebog512(&hctx);
    ak_hash_context_ptr(&hctx, H5, 249, A0);
    ak_hash_destroy(&hctx);

    OctetString A1 = malloc(64);
    ak_mac_context_set_ptr( &mctx, T, 64);
    ak_mac_context_ptr( &mctx, A0, 64, A1);

    OctetString AxA0 = malloc(128);
    memcpy(AxA0, A1, 64);
    memcpy(AxA0 + 64, A0, 64);
    ak_mac_context_ptr( &mctx, AxA0, 64, CATS);
    OctetString A2 = malloc(64);
    ak_mac_context_ptr( &mctx, A1, 64, A2);
    memcpy(AxA0, A2, 64);
    ak_mac_context_ptr( &mctx, AxA0, 64, SATS);
    free(A0);
    free(A1);
    free(A2);
    free(AxA0);
    ak_mac_destroy(&mctx);  
}