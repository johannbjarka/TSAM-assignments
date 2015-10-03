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
#include <unistd.h>
#include <stdio.h>
#include <glib.h> 

GString* respondToGET();
GString* respondToColorQuery(gchar *color);
GString* respondToPOST();
GString* respondToHEAD();

int main(int argc, char **argv)
{
        int sockfd;
        struct sockaddr_in server, client;
        char message[512];

        /* Create and bind a TCP socket */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        /* Network functions need arguments in network byte order instead of
           host byte order. The macros htonl, htons convert the values, */
        server.sin_addr.s_addr = htonl(INADDR_ANY);
        server.sin_port = htons(35651);
        bind(sockfd, (struct sockaddr *) &server, (socklen_t) sizeof(server));

	/* Before we can accept messages, we have to listen to the port. We allow one
	 * 1 connection to queue for simplicity.
	 */
	listen(sockfd, 1);

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

                        /* For TCP connectios, we first have to accept. */
                        int connfd;
                        connfd = accept(sockfd, (struct sockaddr *) &client,
                                        &len);
                        
                        /* Receive one byte less than declared,
                           because it will be zero-termianted
                           below. */
                        ssize_t n = read(connfd, message, sizeof(message) - 1);
						
						fprintf(stdout, "Received:\n%s\n", message);
                        fflush(stdout);
						
						//TODO parse message
						
						GString *firstLine = g_string_new(strtok(message, "\n"));
						printf("%s\n", firstLine->str);
						
						GHashTable *dict = g_hash_table_new(g_str_hash, g_str_equal);
						
						GSList *list;
						char *pch = strtok(NULL, "\n");
						int j = 0;
						while(pch != NULL) {
							j++;
							printf("%d - %d\n", j, pch[1]);
							if(pch[0] == '\r') {
								break;
							}
							list = g_slist_append(list, pch);
							pch = strtok(NULL, "\n");
						}
						
						GString *payload = g_string_new(strtok(NULL, "\n"));
						//printf("THIS IS THE PAYLOAD %s\n", payload->str);
						
						while(list != NULL) {
							//printf("%s\n", list->data);
							//char *key = strtok(list->data, ": ");
							GString *key = g_string_new(strtok(list->data, ": "));
							//GString *key = g_string_new("Host");
							GString *value = g_string_new(strtok(NULL, "\n"));
							printf("%s - %s\n", key->str, value->str);
							g_hash_table_insert(dict, key->str, value->str);
							list = g_slist_next(list);
						}
						
						GHashTableIter iter;
						gpointer key, value;
						
						g_hash_table_iter_init(&iter, dict);
						int i = 0;
						while(g_hash_table_iter_next(&iter, &key, &value)) {
							i++;
							printf("%d\n", i);
							printf("key: %s\n", key);
							printf("%s\n", value);
						}
						
						if(g_hash_table_lookup(dict, "Host") != NULL) {
							printf("SWAG BITCHES RATATATA\n");
						}
						else {
							printf("sad face\n");
						}
						
						GString *request = g_string_new(strtok(firstLine->str, " /"));
						
						printf("%s\n", request->str);

						GString *query = g_string_new(strtok(NULL, " /?"));
						printf("%s\n", query->str);

						GString *reply;
						
						if(strcmp(query->str, "color") == 0) {
							GString *bg = g_string_new(strtok(NULL, "="));
							//GString *color = g_string_new(strtok(NULL, " "));
							gchar* color = strtok(NULL, " ");
							
							reply = respondToColorQuery(color);
						}
						
						else if(strcmp(request->str, "GET") == 0) {
							reply = respondToGET();
						}
						else if(strcmp(request->str, "POST") == 0) {
							reply = respondToPOST();
						}
						else if(strcmp(request->str, "HEAD") == 0) {
							printf("wut\n");
							reply = respondToHEAD();
						}

                        /* Send the message back. */
						//write(connfd, message, n);
                        write(connfd, reply->str, reply->len);

                        /* We should close the connection. */
                        shutdown(connfd, SHUT_RDWR);
                        close(connfd);

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

GString* respondToGET() {
	GString* html = g_string_new("whatever");
	return html;
}

GString* respondToColorQuery(gchar *color) {
	printf("%s\n", color);
	GString *html = g_string_new("<!DOCTYPE html>\n<html>\n<body style=\"background-color:");
	g_string_append(html, color);
	g_string_append(html, "\">\n</body>\n</html>\n");
	printf("%s\n", html->str);
	return html;
}

GString* respondToPOST() {
	GString* html = g_string_new("whatever");
	return html;
}

GString* respondToHEAD() {
	GString* header = g_string_new("HTTP/1.1 200 OK\nDate: ");
	char date[30];
	time_t now;
	time(&now);
	struct tm *tm;
	tm = localtime(&now);
	strftime(date, 30, "%a, %d %b %Y %H:%M:%S %Z", tm);
	date[30] = '\0';
	g_string_append(header, date);
	g_string_append(header, "\nServer: ReallyAwesomeServer 2.0\nContent-Type: text/html\n");
	return header;
}