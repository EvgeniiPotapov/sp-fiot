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
    char buf[1024];
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
    printf("Hello compiled\n");
    for(i=0;i<160;i++) printf("%.2X", hello[i]);
    printf("\n");
    send(sock, hello, 160, 0);
    printf("client hello sent\n");
    buf_rv = recv(sock, buf, sizeof(buf), 0);
    printf("server hello recovered, %d\n", buf_rv);
    check_server_hello(buf);
    OctetString SHTS = gen_SHTS(k_client, buf, hello);
    unsigned char eSHTK[32];
    unsigned char iSHTK[32];
    memcpy(SHTS, eSHTK, 32);
    memcpy(SHTS + 32, iSHTK, 32);
    buf_rv = recv(sock, buf, sizeof(buf), 0);
    printf("verify message recovered, %d\n", buf_rv);

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
