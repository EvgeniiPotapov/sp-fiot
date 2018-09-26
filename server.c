#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>

void check_chello(char * buf, int len){
    if(len != 160) printf("incorrect hello len\n");
    printf("len ok\n");
}


void make_vko(int sock){
    char buf[1024];
    int bufrv;
    bzero(buf, 1024);
    bufrv = recv(sock, buf, sizeof(buf), 0);
    check_chello(buf, bufrv);
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
