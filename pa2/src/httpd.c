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
#include <stdlib.h> 

GString* respondToGET(gchar *host, GString* header);
GString* respondToColorQuery(gchar *color, GString* header);
GString* respondToPOST(gchar *host, gchar *payload, GString* header);
GString* buildHeader();
GString* respondToGetWithArgs(gchar *args, gchar *query, gchar *host, GString* header);
GString* buildHeaderWithCookie(gchar* color);
void logRequest(gchar *host, gchar *request, gchar *message, gchar *reply);

int main(int argc, char **argv)
{
        int sockfd;
        struct sockaddr_in server, client;
        char message[512];
		
		if(argc < 2) {
			printf("You must supply a port number to run the server");
			exit(0);
		}

        /* Create and bind a TCP socket */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        /* Network functions need arguments in network byte order instead of
           host byte order. The macros htonl, htons convert the values, */
        server.sin_addr.s_addr = htonl(INADDR_ANY);

        server.sin_port = htons(atoi(argv[1]));

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
						
						GString *messageCopy = g_string_new(message);
						fprintf(stdout, "Received:\n%s\n", message);
                        fflush(stdout);
						
						GString *firstLine = g_string_new(strtok(message, "\n"));
						
						printf("%s\n", firstLine->str);
						
						GHashTable *dict = g_hash_table_new(g_str_hash, g_str_equal);
						
						GSList *list;
						char *pch = strtok(NULL, "\n");
						while(pch != NULL) {
							if(pch[0] == '\r') {
								break;
							}
							list = g_slist_append(list, pch);
							pch = strtok(NULL, "\n");
						}
						
						GString *payload = g_string_new(strtok(NULL, "\0"));
						
						while(list != NULL) {
							GString *key = g_string_new(strtok(list->data, ": "));
							GString *value = g_string_new(strtok(NULL, "\n"));
							printf("%s - %s\n", key->str, value->str);
							g_hash_table_insert(dict, key->str, value->str);
							list = g_slist_next(list);
						}
											
						gchar *payloadLen = g_hash_table_lookup(dict, "Content-Length");
						if(payloadLen != NULL) {
							len = atoi(payloadLen);
							g_string_truncate(payload, len);
						}
						
						/*GHashTableIter iter;
						gpointer key, value;
						
						g_hash_table_iter_init(&iter, dict);
						int i = 0;
						while(g_hash_table_iter_next(&iter, &key, &value)) {
							i++;
							printf("%d\n", i);
							printf("key: %s\n", key);
							printf("%s\n", value);
						}*/
						
						GString *request = g_string_new(strtok(firstLine->str, " /"));
						
						printf("REQUEST: %s\n", request->str);

						GString *query = g_string_new(strtok(NULL, " /?"));
						printf("QUERY: %s\n", query->str);

						GString *reply;
						gchar *host = (gchar *)g_hash_table_lookup(dict, "Host");
						
						if(strcmp(query->str, "color") == 0) {
							GString *bg = g_string_new(strtok(NULL, "="));
							gchar* color = strtok(NULL, " ");
							if(color == NULL) {
								gchar *cookieColor;
								gchar *cookie = (gchar *)g_hash_table_lookup(dict, "Cookie");
								cookieColor = strtok(cookie,"=");
								cookieColor = strtok(NULL,"=");
								if(cookieColor != NULL){
									reply = buildHeader();
									reply = respondToColorQuery(cookieColor, reply);
								}
								else{
									//TODO call get...
								}
							}
							else {
								reply = buildHeaderWithCookie(color);
								reply = respondToColorQuery(color, reply);
							}
						}
						else if(strcmp(query->str, "HTTP") == 0) {
							if(strcmp(request->str, "GET") == 0) {
								reply = buildHeader();
								reply = respondToGET(host, reply);
							}
							else if(strcmp(request->str, "POST") == 0) {
								reply = buildHeader();
								reply = respondToPOST(host, payload->str, reply);
								g_string_free(payload, TRUE);
							}
							else if(strcmp(request->str, "HEAD") == 0) {
								reply = buildHeader();
							}
						}
						else {
							reply = buildHeader();
							GString *args = g_string_new(strtok(NULL, " "));
							printf("ARGS: %s\n", args->str);
							reply = respondToGetWithArgs(args->str, query->str, g_hash_table_lookup(dict, "Host"), reply);
						}

						/* Log the request and response*/
						logRequest(host, request->str, messageCopy->str, reply->str);
						
                        /* Send the message back. */
                        write(connfd, reply->str, reply->len);
						
						g_string_free(reply, TRUE);

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

GString* respondToGET(gchar *host, GString* header) {
	g_string_append(header, "\n<!DOCTYPE html>\n<html>\n<body>\n<p>\n http://localhost<br>\n");
	g_string_append(header, host);
	g_string_append(header, "\n</p>\n</body>\n</html>\n");
	return header;
}

GString* respondToColorQuery(gchar *color, GString* header) {
	g_string_append(header, "\n<!DOCTYPE html>\n<html>\n<body style=\"background-color:");
	g_string_append(header, color);
	g_string_append(header, "\">\n</body>\n</html>\n");
	return header;
}

GString* respondToPOST(gchar *host, gchar *payload, GString* header) {
	g_string_append(header, "\n<!DOCTYPE html>\n<html>\n<body>\n<p>\n http://localhost<br>\n");
	g_string_append(header, host);
	g_string_append(header, "\n</p>\n<p>\n");
	g_string_append(header, payload);
	g_string_append(header, "\n</p>\n</body>\n</html>\n");
	return header;
}

GString* buildHeader() {
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

GString* buildHeaderWithCookie(gchar* color) {
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
	g_string_append(header, "Set-Cookie: Color=");
	g_string_append(header, color);
	g_string_append(header, "\n");
	return header;
}

GString* respondToGetWithArgs(gchar *args, gchar *query, gchar *host, GString* header) {
	g_string_append(header, "\n<!DOCTYPE html>\n<html>\n<body>\n<p>\nhttp://localhost/");
	g_string_append(header, args);
	g_string_append(header, "<br>\n Host:");
	g_string_append(header, host);
	g_string_append(header, "\n");
	
	gchar *token = strtok(args, "?");
	token = strtok(token, "&");
	while(token != NULL) {
		g_string_append(header, " ");
		g_string_append(header, token);
		g_string_append(header, "<br>\n");
		token = strtok(NULL, "&");
	}
	g_string_append(header, "</p>");
	g_string_append(header, "\n</body>\n</html>\n");
	
	return header;
}

void logRequest(gchar *host, gchar *request, gchar *message, gchar *reply) {
	GString *temp = g_string_new(strtok(message, " "));
	GString *url = g_string_new("http://localhost"); 
	g_string_append(url, strtok(NULL, " "));
	gchar date[26];
	time_t now;
	time(&now);
	struct tm *tm;
	tm = localtime(&now);
	strftime(date, 26, "%FT%H:%M:%S %z", tm);
	date[26] = '\0';
	FILE * logFile;
	/* g_string_append kept overwriting the beginning of the
	 * string for some reason so we were forced to write into
	 * the log file in small chunks.
	 */
	logFile = fopen ("httpd.log","a+");
	if (logFile!=NULL)
	{
		fputs (date, logFile);
	}
	GString* logEntry1 = g_string_new(" :");
	g_string_append(logEntry1, host);
	if (logFile!=NULL)
	{
		fputs (logEntry1->str, logFile);
	}
	GString* logEntry2 = g_string_new(" ");
	g_string_append(logEntry2, request);
	if (logFile!=NULL)
	{
		fputs (logEntry2->str, logFile);
	}
	GString* logEntry3 = g_string_new(" ");
	g_string_append(logEntry3, url->str);
	if (logFile!=NULL)
	{
		fputs (logEntry3->str, logFile);
	}
	GString* logEntry4 = g_string_new(" : ");
	g_string_append(logEntry4, reply);
	if (logFile!=NULL)
	{
		fputs (logEntry4->str, logFile);
		fclose (logFile);
	}
}