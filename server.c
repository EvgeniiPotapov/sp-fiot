#include "krypt_include/libakrypt.h"
#include "krypt_include/ak_random.h"
#include "krypt_include/ak_buffer.h"
#include "krypt_include/ak_curves.h"
#include "krypt_include/ak_parameters.h"
#include "krypt_include/ak_mac.h"
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
        perror("Incorrect hello len");
        exit(1);
    }
    printf("Hello len Ok\n");
    printf("ClientHello:\n");
    for(int i=0;i<160;i++) printf("%.2X", buf[i]);
    printf("\n");
    struct mac mctx;
    ak_mac_create_hmac_streebog256( &mctx );
    ak_mac_context_set_ptr( &mctx, "Session0CanBeTheOneToMakeAStable", 32);
    OctetString hmac = malloc(32);
    ak_mac_context_ptr( &mctx, buf, 126, hmac);
    ak_mac_destroy( &mctx );
    printf("Mac is:\n");
    for(int i=0;i<32;i++) printf("%.2X", hmac[i]);
    int i = memcmp(&buf[128], hmac, 32);
    if(i != 0){
        perror("\nIncorrect mac\n");
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
    printf("\ngen Ks:\n");
    for(int i=0;i<32;i++) printf("%.2X", k_server[i]);
    printf("\n");
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


OctetString genSHTS(RandomOctetString k_server, unsigned char buf, OctetString hello){
    struct wpoint client_point;
    struct wpoint q_point;
    char z_coor[32] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(&client_point.x, &buf + 58, 32);
    memcpy(&client_point.y, &buf + 90, 32);
    memcpy(&client_point.z, z_coor, 32);
    ak_wpoint_pow(&q_point,
                  (ak_wpoint) &client_point,
                  (ak_uint64 *)k_server,
                  ak_mpzn256_size,
                  (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);

    ak_wpoint_reduce( &q_point, (ak_wcurve) &id_rfc4357_gost3410_2001_paramsetA);
    OctetString R1 = malloc(64);
    memcpy(R1, q_point.x, 32);
    memcpy(R1 + 32, "Session0CanBeTheOneToMakeAStable", 32);
    OctetString H1 = malloc(211);
    memcpy(H1, buf, 111);
    memcpy(H1 + 111, hello, 100);
    OctetString SHTS = takeSHTS(R1, H1);
    return SHTS;
}


OctetString takeSHTS(OctetString R1, OctetString H1){
    
}


void make_vko(int sock){
    ak_libakrypt_create(NULL);
    unsigned char buf[1024];
    int bufrv;
    bzero(buf, 1024);
    bufrv = recv(sock, buf, sizeof(buf), 0);
    check_chello(buf, bufrv);
    RandomOctetString k_server;
    OctetString hello = genServerHello(k_server);
    OctetString frame = genServerFrame(hello);
    printf("\nServerHelloFrame:\n");
    for(int i=0;i<160;i++) printf("%.2X", frame[i]);
    printf("\n");
    OctetString SHTS = genSHTS(k_server, buf, hello);
    ak_libakrypt_destroy();
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
        perror("socket creation error");
        exit(1);
    }
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5000);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (setsockopt(listener, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0)
    perror("setsockopt(SO_REUSEPORT) failed");
    if(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind error");
        exit(2);
    }
    
    listen(listener, 2);

    while(1)
    {
        sock = accept(listener, NULL, NULL);
        if(sock < 0)
        {
            perror("accept error");
            exit(3);
        }
        
        switch(fork())
        {
        case -1:
            perror("fork error");
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
