/* A UDP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h> 

#define PACKET_SIZE 512

int main(int argc, char **argv)
{
        int sockfd;
		uint16_t blocknum = 0;
        struct sockaddr_in server, client;
        char message[PACKET_SIZE];
		char buf[PACKET_SIZE];
		char* filename;
		int filedesc;
		struct packet {
			uint16_t opcode;
			uint16_t blocknum;
			char payload[PACKET_SIZE];
		};
		
		struct packet pack;
		
		if(argc < 2) {
			printf("You must supply a port number to run the server");
			exit(0);
		}

        /* Create and bind a UDP socket */
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        /* Network functions need arguments in network byte order instead of
           host byte order. The macros htonl, htons convert the values, */
        server.sin_addr.s_addr = htonl(INADDR_ANY);
        server.sin_port = htons(atoi(argv[1]));
        bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

        for (;;) {
                fd_set rfds;
                struct timeval tv;
                int retval;

                /* Check whether there is data on the socket fd. */
                FD_ZERO(&rfds);
                FD_SET(sockfd, &rfds);

                /* Wait for five seconds. */
                tv.tv_sec = 5;
                tv.tv_usec = 0;
                retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);

                if (retval == -1) {
                        perror("select()");
                } else if (retval > 0) {
                        /* Data is available, receive it. */
                        assert(FD_ISSET(sockfd, &rfds));
                        
                        /* Copy to len, since recvfrom may change it. */
                        socklen_t len = (socklen_t) sizeof(client);
                        /* Receive one byte less than declared,
                           because it will be zero-termianted
                           below. */
                        ssize_t n = recvfrom(sockfd, message,
                                             sizeof(message) - 1, 0,
                                             (struct sockaddr *) &client,
                                             &len);
						
						if(message[1] == 1) {
							char* path = "../data/";
							filename = &message[2];
							char* name_with_path;
							name_with_path = malloc(strlen(path) + 1 + strlen(filename)); 
							strcpy(name_with_path, path);
							strcat(name_with_path, filename);
							
							filedesc = open(name_with_path, O_RDONLY);
							if (filedesc < 0) {
								printf("Error: failed to open %s\n", filename);
							}
						}
						else if(message[1] == 4) {
							// do nothing
						}
						else {
							continue;
						}
						
						ssize_t packsize;
						if((packsize = read(filedesc, buf, PACKET_SIZE)) < 0) {
							printf("Error: failed to read %s\n", filename);
						}
						else {
							blocknum++;
							pack.opcode = htons(3);
							pack.blocknum = htons(blocknum);
							memcpy(pack.payload, buf, packsize);
							packsize += 4;
							
							sendto(sockfd, &pack, (size_t)packsize, 0,
								   (struct sockaddr *) &client,
								   (socklen_t) sizeof(client));
						}
                } else {
                        fprintf(stdout, "No message in five seconds.\n");
                        fflush(stdout);
                }
        }
}