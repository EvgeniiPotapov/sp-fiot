#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "fiot_include/fiot_types.h"
#include "fiot_include/gench.h"
#include "fiot_include/serialize_fiot.h"





void main(int argc, char *argv[]){
    unsigned char buf[1024];
    int buf_rv = 0;
    int i, sock;
    struct sockaddr_in addr;
    fd_set readfds;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    { 
        perror("socket creation error");
        exit(1);
    }
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5000);
    addr.sin_addr.s_addr = inet_addr(argv[1]);
   
    if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("socket connect error");
        exit(2);
    }
    printf("Connected\n");
    
    RandomOctetString k_client;
    OctetString hello = getClient_hello(k_client);
    send(sock, hello, 160, 0);
    printf("client hello sent\n");
    buf_rv = recv(sock, buf, sizeof(buf), 0);
    printf("server hello recovered, %d\n", buf_rv);
    check_server_hello(buf);
    OctetString R1 = malloc(64);
    OctetString SHTS = gen_SHTS(k_client, buf, hello, R1);
    OctetString eSHTK = malloc(32);
    OctetString iSHTK = malloc(32);
    memcpy(eSHTK, SHTS,  32);
    memcpy( iSHTK, SHTS + 32, 32);
    OctetString s_hello = malloc(160);
    memcpy(s_hello, buf,  160);
    buf_rv = recv(sock, buf, sizeof(buf), 0);
    printf("verify message recovered, %d\n", buf_rv);
    OctetString ver_message =  check_verify_frame(buf, eSHTK, iSHTK, hello, s_hello);
    OctetString H3 = malloc(230);
    OctetString CHTS = gen_CHTS(ver_message, hello, s_hello, R1, H3);
    OctetString eCHTK = malloc(32);
    OctetString iCHTK = malloc(32);
    memcpy(eCHTK, CHTS,  32);
    memcpy(iCHTK, CHTS + 32, 32);
    OctetString verify = genVerify(H3);
    OctetString verifyframe = genVerifyFrame(verify, eCHTK, iCHTK);
    send(sock, verifyframe, 60, 0);
    printf("\nverify frame sent\n");

    OctetString H5 = malloc(249);
    memcpy(H5, H3, 230);
    memcpy(H5 + 230, verify, 19);
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

    exit(0);



    while(1){
        FD_ZERO(&readfds);
        FD_SET(0, &readfds);
        FD_SET(sock, &readfds);
        select(sock+1, &readfds, NULL, NULL, NULL);
        
            if (FD_ISSET(0, &readfds)){
                buf_rv = read(0, buf, sizeof(buf));
                send(sock, buf, buf_rv, 0);
                memset(buf, 0, buf_rv);
            }
            if (FD_ISSET(sock, &readfds)){
                buf_rv = recv(sock, buf, sizeof(buf), 0);
                write(1, buf, buf_rv);
                memset(buf, 0, buf_rv);
            }
        
    }

}
