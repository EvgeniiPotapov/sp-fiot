#include "krypt_include/ak_random.h"
#include "krypt_include/ak_buffer.h"
#include "krypt_include/ak_curves.h"
#include "krypt_include/ak_parameters.h"
#include "krypt_include/ak_mac.h"
#include "krypt_include/ak_bckey.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <unistd.h>
#include <sys/time.h> 

#include "fiot_include/fiot_types.h"
#include "fiot_include/serialize_fiot.h"


void check_chello(char * buf, int len){
    if(len != 160){
        printf("Incorrect hello len");
        exit(1);
    }
    printf("Hello len Ok\n");
    struct mac mctx;
    ak_mac_create_hmac_streebog256( &mctx );
    ak_mac_context_set_ptr( &mctx, "Session0CanBeTheOneToMakeAStable", 32);
    OctetString hmac = malloc(32);
    ak_mac_context_ptr( &mctx, buf, 126, hmac);
    ak_mac_destroy( &mctx );
    int i = memcmp(&buf[128], hmac, 32);
    if(i != 0){
        printf("\nIncorrect mac\n");
        exit(2);
    }
    printf("\nMac check: success\n");
    char z_coor[32] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct wpoint c_point;
    memcpy(&c_point.x, &buf[57], 32);
    memcpy(&c_point.y, &buf[89], 32);
    memcpy(&c_point.z, z_coor, 32);
    i = ak_wpoint_is_ok((ak_wpoint) &c_point, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);
    if(i != 1){
        printf("\nIncorrect curve point\n");
        exit(1);
    }
    printf("\nPoint check: success\n");
}


OctetString genServerHello(Octet * k_server){
    ServerHelloMessage serverhello;
    serverhello.algorithm = kuznechikCTRplusGOST3413;
    struct random random;
    ak_random_create_lcg(&random);
    ak_buffer buf = ak_buffer_new_size(64);
    ak_buffer_set_random(buf, &random);
    ak_random_destroy(&random);
    memcpy(serverhello.random, buf->data, 32);
    memcpy(k_server, buf->data + 32, 32);
    ak_buffer_delete(buf);
    serverhello.point.id = rfc4357_gost3410_2001_paramsetA;

    struct wpoint elliptic_point;
    ak_wpoint_pow(&elliptic_point,
                  (ak_wpoint) &id_rfc4357_gost3410_2001_paramsetA.point,
                  (ak_uint64 *)k_server,
                  ak_mpzn256_size,
                  (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);

    ak_wpoint_reduce( &elliptic_point, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);
    serverhello.point.x = (OctetString) elliptic_point.x;
    serverhello.point.y = (OctetString) elliptic_point.y;
    serverhello.countOfExtensions = 0;
    OctetString serhello = malloc(1);
    serServerHelloMessage(&serhello, &serverhello);
    return serhello;
}


OctetString genServerFrame(OctetString hello){
    Frame serverframe;
    serverframe.tag = plainFrame;
    serLengthShortInt(serverframe.length, 160);
    memset(serverframe.number, 0x00, 5);
    serverframe.type = serverHello;
    serLengthShortInt(serverframe.meslen, 100);
    serverframe.message = hello;
    serverframe.padding = "33PADDINGGOOD33";
    serverframe.icode.present = isPresent;
    serverframe.icode.length = 32;
    serverframe.icode.code = "DummyboxDummyboxDummyboxDummybox";
    OctetString serframe = malloc(1);
    serFrame(&serframe, &serverframe);
    struct mac mctx;
    ak_mac_create_hmac_streebog256( &mctx );
    ak_mac_context_set_ptr( &mctx, "Session0CanBeTheOneToMakeAStable", 32);
    OctetString hmac = malloc(32);
    ak_mac_context_ptr( &mctx, serframe, 126, hmac);
    ak_mac_destroy( &mctx );
    memcpy(serframe + 128, hmac, 32);
    free(hmac);
    return serframe;
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


OctetString genSHTS(RandomOctetString k_server, unsigned char * buf, OctetString hello, OctetString R1){
    struct wpoint client_point;
    struct wpoint q_point;
    unsigned char x_coor[32];
    char z_coor[32] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(&client_point.x, buf + 57, 32);

    printf("\n");
    memcpy(&client_point.y, buf + 89, 32);
    memcpy(&client_point.z, z_coor, 32);
    ak_wpoint_pow(&q_point,
                  (ak_wpoint) &client_point,
                  (ak_uint64 *)k_server,
                  ak_mpzn256_size,
                  (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);

    ak_wpoint_reduce( &q_point, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);
    memcpy(R1, q_point.x, 32);

    memcpy(R1 + 32, "Session0CanBeTheOneToMakeAStable", 32);
    OctetString H1 = malloc(211);
    memcpy(H1, buf + 11, 111);
    memcpy(H1 + 111, hello, 100);
    OctetString SHTS = takeSHTS(R1, H1);
    return SHTS;
}


OctetString genVerify(OctetString c_hello, OctetString s_hello){
    OctetString H2 = malloc(211);
    memcpy(H2, c_hello + 11, 111);
    memcpy(H2 + 111, s_hello, 100);
    OctetString bogH2 = malloc(64);
    struct hash hctx;
    ak_hash_create_streebog512(&hctx);
    ak_hash_context_ptr(&hctx, H2, 211, bogH2);
    ak_hash_destroy(&hctx);
    VerifyMessage verify;
    OctetString cutbogH2 = malloc(16);
    memcpy(cutbogH2, bogH2, 16);
    free(bogH2);
    free(H2);
    verify.sign.present = notPresent;
    verify.mac.present = isPresent;
    verify.mac.length = 16;
    verify.mac.code = cutbogH2;
    OctetString serVerify = malloc(1);
    serVerifyMessage(&serVerify, &verify);
    return serVerify;
}

OctetString genVerifyFrame(OctetString verify, unsigned char * eSHTK, unsigned char * iSHTK){
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

OctetString gen_CHTS(OctetString verifyframe, OctetString c_hello, OctetString s_hello, OctetString R1, OctetString H3){
    memcpy(H3, c_hello + 11, 111);
    memcpy(H3 + 111, s_hello+11, 100);
    memcpy(H3 + 211, verifyframe, 19);
    OctetString CHTS = takeSHTS(R1, H3);
    return CHTS;
}

OctetString check_verify_frame(OctetString buf, OctetString eSHTK, OctetString iSHTK, OctetString H4){
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
    printf("\nverify message Mac check: success\n");
    unsigned char code[16];
    memcpy(code, &buf[13], 16);
    OctetString bogH4 = malloc(64);
    struct hash hctx;
    ak_hash_create_streebog512(&hctx);
    ak_hash_context_ptr(&hctx, H4, 230, bogH4);
    ak_hash_destroy(&hctx);
    i = memcmp(code, bogH4, 16);
    if(i != 0){
        printf("\nIncorrect mac.code\n");
        exit(2);
    }
    printf("\nverify message mac.code check: success\n");
    free(bogH4);
    return buf;
}


void make_session_keys(OctetString xQ, OctetString R2, OctetString H5, OctetString SATS, OctetString CATS){
    OctetString T = malloc(64);
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
    free(T);
    free(A0);
    free(A1);
    free(A2);
    free(AxA0);
    ak_mac_destroy(&mctx);  
}

void make_vko(int sock){
    unsigned char buf[1024];
    int bufrv;
    bzero(buf, 1024);
    bufrv = recv(sock, buf, sizeof(buf), 0);
    check_chello(buf, bufrv);
    RandomOctetString k_server;
    OctetString hello = genServerHello(k_server);
    OctetString frame = genServerFrame(hello);
    send(sock, frame, 160, 0);
    printf("server hello sent\n");

    OctetString R1 = malloc(64);
    OctetString SHTS = genSHTS(k_server, buf, hello, R1);
    unsigned char eSHTK[32];
    unsigned char iSHTK[32];
    memcpy(eSHTK, SHTS,  32);
    memcpy( iSHTK, SHTS + 32, 32);

    OctetString verify = genVerify(buf, hello);
    OctetString verifyframe = genVerifyFrame(verify, eSHTK, iSHTK);
    printf("\nVerifyFrame:\n");
    for(int i=0;i<60;i++) printf("%.2X", verifyframe[i]);
    send(sock, verifyframe, 60, 0);
    printf("\nverify frame sent\n");

    OctetString H3 = malloc(230);
    OctetString CHTS = gen_CHTS(verify, buf, frame, R1, H3);
    OctetString eCHTK = malloc(32);
    OctetString iCHTK = malloc(32);
    memcpy(eCHTK, CHTS,  32);
    memcpy(iCHTK, CHTS + 32, 32);
    OctetString c_hello = malloc(160);
    memcpy(c_hello, buf, 160);
    bufrv = recv(sock, buf, sizeof(buf), 0);
    printf("verify message recovered, %d\n", bufrv);
    OctetString ver_message =  check_verify_frame(buf, eCHTK, iCHTK, H3);

    OctetString H5 = malloc(249);
    memcpy(H5, H3, 230);
    memcpy(H5 + 230, ver_message + 11, 19);
    OctetString xQ = malloc(32);
    memcpy(xQ, R1, 32);
    OctetString R2 = malloc(40);
    memcpy(R2, "serverIDSession0CanBeTheOneToMakeAStable", 40);
    OctetString SATS = malloc(64);
    OctetString CATS = malloc(64);
    make_session_keys(xQ, R2, H5, SATS, CATS);
    printf("\nSATS:\n");
    for(int i=0;i<64;i++) printf("%.2X", SATS[i]);
    printf("\n");
    printf("\nCATS:\n");
    for(int i=0;i<64;i++) printf("%.2X", CATS[i]);
    printf("\n");

}



void main(){
    int listener, i,buf_rv, sock;
    int enable = 1;
    struct sockaddr_in addr;
    char buf[1024];
    int bytes_read;
    fd_set readfds;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if(listener < 0)
    {
        printf("socket creation error");
        exit(1);
    }
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5000);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (setsockopt(listener, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0)
    printf("setsockopt(SO_REUSEPORT) failed");
    if(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        printf("bind error");
        exit(2);
    }
    
    listen(listener, 2);

    while(1)
    {
        sock = accept(listener, NULL, NULL);
        if(sock < 0)
        {
            printf("accept error");
            exit(3);
        }
        
        switch(fork())
        {
        case -1:
            printf("fork error");
            break;
            
        case 0:
            make_vko(sock);
            exit(0);
            close(listener);
            close(0);
            dup(sock);
            close(1);
            dup(sock);
            close(sock);
            execl("./sftp-server", "sftp-server");
            exit(0);
            
        default:
            close(sock);
        }
    }
    
}
