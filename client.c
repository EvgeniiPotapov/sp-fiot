#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "krypt_include/ak_bckey.h"

#include "fiot_include/fiot_types.h"
#include "fiot_include/gench.h"
#include "fiot_include/serialize_fiot.h"
#include "fiot_include/tl_session.h"


void receive_all(int sock, Octet *buf, int len){
    int bytes_recieved = len;
    int buf_rv;
    while (bytes_recieved != FIOT_PACKET){
        buf_rv = read(sock, &buf[bytes_recieved], FIOT_PACKET - bytes_recieved);
        bytes_recieved = bytes_recieved + buf_rv;
    }
}


void main(int argc, char *argv[]){
    ak_bckey_init_kuznechik_tables();
    Octet buf[512];
    Octet buf_stdin[RAW_PACKET];
    Octet buf_sock[FIOT_PACKET];
    unsigned short buf_rv = 0;
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
    
    RandomOctetString k_client;
    OctetString hello = getClient_hello(k_client);
    send(sock, hello, 160, 0);
    buf_rv = recv(sock, buf, sizeof(buf), 0);
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

    OctetString H5 = malloc(249);
    memcpy(H5, H3, 230);
    memcpy(H5 + 230, verify, 19);
    OctetString xQ = malloc(32);
    memcpy(xQ, R1, 32);
    OctetString R2 = malloc(40);
    memcpy(R2, "serverIDSession0CanBeTheOneToMakeAStable", 40);
    OctetString SATS = malloc(64);
    OctetString CATS = malloc(64);
    OctetString T = malloc(64);
    make_session_keys(xQ, R2, H5, SATS, CATS, T);
    // for(int i=0;i<64;i++) printf("%.2X", SATS[i]);
    // printf("\n");
    // for(int i=0;i<64;i++) printf("%.2X", CATS[i]);
    // printf("\n");
    
    session_keys c_keys;
    session_keys s_keys;
    init_keys(&c_keys, CATS, T);
    init_keys(&s_keys, SATS, T);
    Frame app_data;
    app_data.tag = encryptedFrame;
    serLengthShortInt(app_data.length, FIOT_PACKET);
    app_data.type = applicationData;
    app_data.icode.present = isPresent;
    app_data.icode.length = 16;
    app_data.icode.code = "default0default1";
    fprintf(stderr, "Derive Ok\n");
    

    while(1){
        FD_ZERO(&readfds);
        FD_SET(0, &readfds);
        FD_SET(sock, &readfds);
        select(sock+1, &readfds, NULL, NULL, NULL);
        
            if (FD_ISSET(0, &readfds)){
                buf_rv = read(0, buf_stdin, RAW_PACKET);
                if (buf_rv > 0){
                // sleep(1);
                // fprintf(stderr, "message from client: %d\n", buf_rv);
                // for(int i=0; i<buf_rv; i++) fprintf(stderr, "%.2x", buf_stdin[i]);
                // fprintf(stderr, "\n");
                OctetString data_frame = gen_data_frame(buf_stdin, buf_rv, &c_keys, &app_data);
                // fprintf(stderr, "message from client\n");
                // for(int i=0; i<8; i++) fprintf(stderr, "%.2x", data_frame[i]);
                // fprintf(stderr, "\n");
                send(sock, data_frame, FIOT_PACKET, 0);
                // send(sock, buf_stdin, buf_rv, 0);
                // memset(buf, 0, buf_rv);
                update_keys(&c_keys);
                }
            }
            if (FD_ISSET(sock, &readfds)){
                buf_rv = recv(sock, buf_sock, FIOT_PACKET, 0);
                // fprintf(stderr, "message from socket: %d\n", buf_rv);
                if (buf_rv > 0){
                // sleep(1);
                if (buf_rv < FIOT_PACKET) receive_all(sock, buf_sock, buf_rv);
                int meslen = decrypt_frame(&buf_sock[0], FIOT_PACKET, &s_keys);
                // fprintf(stderr, "message from socket: %d\n", meslen);
                // fprintf(stderr, "mes: %d\n", meslen);
                // for(int i=0; i<buf_rv; i++) fprintf(stderr, "%.2x", buf_sock[i]);
                // fprintf(stderr, "\n");
                // for(int i=0; i<meslen; i++) fprintf(stderr, "%.2x", data[i]);
                // fprintf(stderr, "\n");
                write(1, &buf_sock[11], meslen);
                // fprintf(stderr, "message from socket\n");
                // for(int i=0; i<buf_rv; i++) fprintf(stderr, "%.2x", buf_sock[i]);
                // fprintf(stderr, "\n");
                // write(1, buf_sock, buf_rv);
                // memset(buf, 0, buf_rv);
                update_keys(&s_keys);
                }
                if (buf_rv == 0) exit(7);
            }
        
    }

}
