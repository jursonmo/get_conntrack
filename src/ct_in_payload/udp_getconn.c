#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "ct_info.h"

#define SERVER_PORT_NUM      50001
#define MAX_DATA_BUFSIZE     6000
#define ERROR                -1
#define OK                   0

unsigned char buf[MAX_DATA_BUFSIZE] = {0};

/* Function declaration  */
int main()
{
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
    int    sockAddrSize;
    int    accept_fd;
    int    sock_fd;
    fd_set fdset;
    int    bytes_received = 0;
    int    seq = 0;
    int    pkt_len = 0;
    printf("listen port:%d\n", SERVER_PORT_NUM);
    sockAddrSize = sizeof(struct sockaddr_in);

    bzero((char*) &serverAddr, sockAddrSize);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(SERVER_PORT_NUM);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == ERROR)
    {
        printf("Error: socket()!\n");
        return ERROR;
    }

    if (bind(sock_fd, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) == ERROR)
    {
        printf("Error: bind()!\n");
        close(sock_fd);
        return ERROR;
    }
    int first = 1;
    struct dnat_info di;
    char *p = buf;
    while (1)
    {
        if ((bytes_received = recvfrom(sock_fd, buf, MAX_DATA_BUFSIZE, 0, (struct sockaddr *) &clientAddr, &sockAddrSize)) > 0)
        {
	    if (first) {
		first = 0;
		if (bytes_received >= sizeof(di)){
			memcpy(&di, buf, sizeof(di));
			dump_dnat_info(&di);
			p = buf+sizeof(di);
		}
            }
            printf("Received %s \n", p);
        }
    }

    close(sock_fd);

    return OK;
}
