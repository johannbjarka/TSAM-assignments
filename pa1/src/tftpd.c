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

#define PACKET_SIZE 512

int main(int argc, char **argv)
{
        int sockfd;
		FILE * filefd;
        struct sockaddr_in server, client;
        char message[512];

        /* Create and bind a UDP socket */
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        /* Network functions need arguments in network byte order instead of
           host byte order. The macros htonl, htons convert the values, */
        server.sin_addr.s_addr = htonl(INADDR_ANY);
        server.sin_port = htons(35651);
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

						char* path = "../data/";
						char* filename = &message[2];
						char* name_with_path;
						name_with_path = malloc(strlen(path) + 1 + strlen(filename)); 
						strcpy(name_with_path, path);
						strcat(name_with_path, filename);
						
						if((filefd = fopen(name_with_path, "r")) == NULL ) {
							fprintf(stderr, "Could not open destination file, using stdout.\n");
						}
						else {
							printf("Preparing to start reading file '%s'\n", filename );
							// þurfum að búa til buffer til að senda í stað message
							
							sendto(sockfd, message, (size_t) n, 0,
                               (struct sockaddr *) &client,
                               (socklen_t) sizeof(client));
						}
                        /* Send the message back. */
                        sendto(sockfd, message, (size_t) n, 0,
                               (struct sockaddr *) &client,
                               (socklen_t) sizeof(client));
                        /* Zero terminate the message, otherwise
                           printf may access memory outside of the
                           string. */
                        message[n] = '\0';
                        /* Print the message to stdout and flush. */
                        fprintf(stdout, "Received:\n%s\n", message);
                        fflush(stdout);
                } else {
                        fprintf(stdout, "No message in five seconds.\n");
                        fflush(stdout);
                }
        }
}
