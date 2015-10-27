/* 
 * A simple HTTP server that conforms to the HTTP/1.1 protocol. 
 * It accepts GET, POST and HEAD requests.
 * It supports persistent and parallel connections. 
 */

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h> 
#include <stdlib.h>

GString* respondToGET(gchar *host, GString* header, GHashTable* headers);
GString* respondToColorQuery(gchar *color, GString* header);
GString* respondToPOST(gchar *host, gchar *payload, GString* header);
GString* buildHeader();
GString* respondToGetWithArgs(gchar *args, gchar *query, gchar *host, GString* header, GHashTable* headers);
GString* buildHeaderWithCookie(gchar* color);
gchar* writeHeaders(GHashTable* headers);
void logRequest(gchar *host, gchar *request, gchar *message, gchar *reply);

const int MAX_CONN = 10;

int main(int argc, char **argv) {
	int sockfd;
	int fdmax, listener, newfd, nbytes;
	fd_set master, read_fds;
	struct sockaddr_in serveraddr, clientaddr;
	char message[512];
	
	int yes = 1;
	int addrlen;
	int i, j;
	
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	
	if(argc < 2) {
		printf("You must supply a port number to run the server");
		exit(0);
	}
	
	/* Create and bind a TCP socket */
	if((listener = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		exit(1);
	}
	
	/* "Address already in use" error message */
	if(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		perror("Server-setsockopt()");
		exit(1);
	}
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = INADDR_ANY;
	serveraddr.sin_port = htons(atoi(argv[1]));
	
	memset(&(serveraddr.sin_zero), '\0', 8);
	 
	if(bind(listener, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) == -1) {
		perror("Server-bind()");
		exit(1);
	}
	
	if(listen(listener, MAX_CONN) == -1) {
		 perror("Server-listen()");
		 exit(1);
	}
	/* Create dictionary to keep of track of the time passed for each connection */
	GHashTable *connections = g_hash_table_new(g_str_hash, g_str_equal);	
	
	FD_SET(listener, &master);
	fdmax = listener;

	for (;;) {
		read_fds = master;
		struct timeval tv;
		
		/* Set tv to 1 second to check rapidly for client time outs */
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		
		int retval = select(fdmax+1, &read_fds, NULL, NULL, &tv);
		
		if( retval == -1) {
			perror("select()");
			exit(1);
		} else if(retval > 0) {
			for(i = 0; i <= fdmax; i++) {
				if(FD_ISSET(i, &read_fds)) {
					/* A file descriptor is active */
					if(i == listener) {
						/* Handle new connections */
						addrlen = sizeof(clientaddr);
						if((newfd = accept(listener, (struct sockaddr *)&clientaddr, &addrlen)) == -1) {
							perror("Server-accept()");
						}
						else {
							FD_SET(newfd, &master); /* Add to master set */
							if(newfd > fdmax) { /* Keep track of the maximum */
								fdmax = newfd;
							}
						}
					}
					else {						
						/* Handle data from a client */
						if((nbytes = recv(i, message, sizeof(message), 0)) <= 0) {
							/* Got error or connection closed by client */
							if(nbytes == 0) {
								/* Connection closed by client */
								fdmax -= 1;
								shutdown(i, SHUT_RDWR);
								close(i);
								FD_CLR(i, &master);
								gchar *key1 = g_strdup_printf("%i", i);
								g_hash_table_remove(connections, key1);
							}
							else {
								perror("recv()");
								fdmax -= 1;
								shutdown(i, SHUT_RDWR);
								close(i);
								FD_CLR(i, &master);
								gchar *key1 = g_strdup_printf("%i", i);
								g_hash_table_remove(connections, key1);
							}
						}
						else {
							GString *messageCopy = g_string_new(message);
							if(FD_ISSET(i, &master)) {
								if(i != listener) {
									time_t now;
									now = time(NULL);
									gchar *theKey = g_strdup_printf("%i", i);
									g_hash_table_replace(connections, theKey, (gpointer)now);
										
									GString *firstLine = g_string_new(strtok(message, "\n"));									
									GHashTable *dict = g_hash_table_new(g_str_hash, g_str_equal);
									
									/* Make a list with all the lines we received */
									GSList *list = NULL;
									char *pch = strtok(NULL, "\n");
									while(pch != NULL) {
										if(pch[0] == '\r') {
											break;
										}
										list = g_slist_append(list, pch);
										pch = strtok(NULL, "\n");
									}
									
									GString *payload = g_string_new(strtok(NULL, "\0"));
									
									/* Make a dictionary containing all the headers we received */
									while(list != NULL) {
										GString *key = g_string_new(strtok(list->data, ": "));
										GString *value = g_string_new(strtok(NULL, "\n"));
										g_hash_table_insert(dict, key->str, value->str);
										list = g_slist_next(list);
									}
									gchar *payloadLen = g_hash_table_lookup(dict, "Content-Length");
									if(payloadLen != NULL) {
										size_t len = atoi(payloadLen);
										g_string_truncate(payload, len);
									}
				
									GString *request = g_string_new(strtok(firstLine->str, " /"));
									GString *query = g_string_new(strtok(NULL, " /?"));
									GString *reply;
									/*Build a string with the client's IP and port*/
									GString *host = g_string_new(inet_ntoa(clientaddr.sin_addr));
									g_string_append(host, ":");
									gchar *port = g_strdup_printf("%i", ntohs(clientaddr.sin_port));
									g_string_append(host, port);
									
									if(strcmp(query->str, "color") == 0) {
										GString *bg = g_string_new(strtok(NULL, "="));
										gchar* color = strtok(NULL, " ");
										if(color == NULL) {
											gchar *cookieColor;
											gchar *cookie = (gchar *)g_hash_table_lookup(dict, "Cookie");
											cookieColor = strtok(cookie,"=");
											cookieColor = strtok(NULL,"=");
											/* If a cookie header was received we use the color for the background*/
											if(cookieColor != NULL) {
												reply = buildHeader();
												reply = respondToColorQuery(cookieColor, reply);
											}
											/* No cookie is found so we return a normal GET */
											else {
												reply = buildHeader();
												reply = respondToGET(host->str, reply, dict);
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
											reply = respondToGET(host->str, reply, dict);
										}
										else if(strcmp(request->str, "POST") == 0) {
											reply = buildHeader();
											reply = respondToPOST(host->str, payload->str, reply);
											g_string_free(payload, TRUE);
										}
										else if(strcmp(request->str, "HEAD") == 0) {
											reply = buildHeader();
											reply = respondToGET(host->str, reply, dict);
										}
										else {
											perror("This server only accepts GET, POST and HEAD requests");
										}										
									}
									else {
										reply = buildHeader();
										GString *args = g_string_new(strtok(NULL, " "));
										reply = respondToGetWithArgs(args->str, query->str, host->str, reply, dict);
									}
									
									/* Log the request and response*/
									logRequest(host->str, request->str, messageCopy->str, reply->str);
									
									/* Send the message back. */
									write(i, reply->str, reply->len);
									
									g_string_free(reply, TRUE);
									
									gchar *conn = (gchar *)g_hash_table_lookup(dict, "Connection");
									if(g_strcmp0(conn, "close\r") == 0) {
										/* Closes the connection */
										fdmax -= 1;
										shutdown(i, SHUT_RDWR);
										close(i);
										FD_CLR(i, &master);
										gchar *key1 = g_strdup_printf("%i", i);
										g_hash_table_remove(connections, key1);
									}
								} else {
									/* Do nothing */
								}
							}
						}
					}
				}
				else {
					time_t now;
					now = time(NULL);
					gchar *theKey = g_strdup_printf("%i", i);
					gpointer ptr = g_hash_table_lookup(connections, theKey);
					if(ptr != NULL) {
						long tmr = (long)ptr;
						/* If 30 seconds have gone by without activity we close the connection */
						if(difftime(now, tmr) >= 30.0) {
							/* Closes the connection */
							fdmax -= 1;
							shutdown(i, SHUT_RDWR);
							close(i);
							FD_CLR(i, &master);
							g_hash_table_remove(connections, theKey);
						}
					}
				}
			}
		} else {
			GHashTableIter iter;
			gpointer key, value;
			g_hash_table_iter_init(&iter, connections);
			
			gboolean timeout = FALSE;
			gpointer closeKey;
			time_t now;
			now = time(NULL);
			while(g_hash_table_iter_next(&iter, &key, &value)) {
				long tmr = (long)value;
				/* If 30 seconds have gone by without activity we close the connection */
				if(difftime(now, tmr) >= 30.0) {
					/* Closes the connection */
					int closeFd = atoi(key);					
					fdmax -= 1;
					shutdown(closeFd, SHUT_RDWR);
					close(closeFd);
					FD_CLR(closeFd, &master);
					timeout = TRUE;
					closeKey = key;
				}
			}
			if(timeout) {
				g_hash_table_remove(connections, closeKey);
			}
		}
	}
}

GString* respondToGET(gchar *host, GString* header, GHashTable* headers) {
	GString *reply = g_string_new("\n<!DOCTYPE html>\n<html>\n<body>\n<p>\n http://localhost<br>\n");
	g_string_append(reply, host);
	g_string_append(reply, "\n</p>\n<p>\n");
	g_string_append(reply, writeHeaders(headers));
	g_string_append(reply, "\n</p>\n</body>\n</html>\n");
	g_string_append(header, "Content-Length: ");
	gchar *len = g_strdup_printf("%i", (reply->len - 1));
	g_string_append(header, len);
	g_string_append(header, "\n");
	g_string_append(header, reply->str);
	return header;
}

GString* respondToColorQuery(gchar *color, GString* header) {
	GString *reply = g_string_new("\n<!DOCTYPE html>\n<html>\n<body style=\"background-color:");
	g_string_append(reply, color);
	g_string_append(reply, "\">\n</body>\n</html>\n");
	g_string_append(header, "Content-Length: ");
	gchar *len = g_strdup_printf("%i", (reply->len - 1));
	g_string_append(header, len);
	g_string_append(header, "\n");
	g_string_append(header, reply->str);
	return header;
}

GString* respondToPOST(gchar *host, gchar *payload, GString* header) {
	GString *reply = g_string_new("\n<!DOCTYPE html>\n<html>\n<body>\n<p>\n http://localhost<br>\n");
	g_string_append(reply, host);
	g_string_append(reply, "<br>\n</p>\n<p>\n");
	g_string_append(reply, payload);
	g_string_append(reply, "\n</p>\n</body>\n</html>\n");
	g_string_append(header, "Content-Length: ");
	gchar *len = g_strdup_printf("%i", (reply->len - 1));
	g_string_append(header, len);
	g_string_append(header, "\n");
	g_string_append(header, reply->str);
	return header;
}

GString* buildHeader() {
	GString* header = g_string_new("HTTP/1.1 200 OK\nDate: ");
	
	gchar date[30];
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
	
	gchar date[30];
	time_t now;
	time(&now);
	struct tm *tm;
	tm = localtime(&now);
	strftime(date, 30, "%a, %d %b %Y %H:%M:%S %Z", tm);
	date[30] = '\0';
	
	/* Make the cookie expire 10 minutes from when it is set */
	if(tm->tm_min < 50) {
		tm->tm_min += 10;
	} else {
		tm->tm_hour += 1;
		tm->tm_min -= 50;
	}
		
	gchar expirationDate[30];
	strftime(expirationDate, 30, "%a, %d %b %Y %H:%M:%S %Z", tm);
	expirationDate[30] = '\0';
	
	g_string_append(header, date);
	g_string_append(header, "\nServer: ReallyAwesomeServer 2.0\nContent-Type: text/html\n");
	g_string_append(header, "Set-Cookie: Color=");
	g_string_append(header, color);
	g_string_append(header, "; expires=");
	g_string_append(header, expirationDate);
	g_string_append(header, "\n");
	return header;
}

GString* respondToGetWithArgs(gchar *args, gchar *query, gchar *host, GString* header, GHashTable* headers) {
	GString *reply = g_string_new("\n<!DOCTYPE html>\n<html>\n<body>\n<p>\nhttp://localhost/");
	g_string_append(reply, args);
	g_string_append(reply, "<br>\n");
	g_string_append(reply, host);
	g_string_append(reply, "<br>\n");
	g_string_append(reply, "\n</p>\n<p>\n");
	g_string_append(reply, writeHeaders(headers));
	
	gchar *token = strtok(args, "?");
	token = strtok(token, "&");
	while(token != NULL) {
		g_string_append(reply, " ");
		g_string_append(reply, token);
		g_string_append(reply, "<br>\n");
		token = strtok(NULL, "&");
	}
	g_string_append(reply, "</p>");
	g_string_append(reply, "\n</body>\n</html>\n");
	g_string_append(header, "Content-Length: ");
	gchar *len = g_strdup_printf("%i", (reply->len - 1));
	g_string_append(header, len);
	g_string_append(header, "\n");
	g_string_append(header, reply->str);
	return header;
}

gchar* writeHeaders(GHashTable* headers) {
	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, headers);
	GString * hdrs = g_string_new("");
	while(g_hash_table_iter_next(&iter, &key, &value)) {
		g_string_append(hdrs, key);
		g_string_append(hdrs, ":");
		g_string_append(hdrs, value);
		g_string_append(hdrs, "<br>");
	}
	return hdrs->str;
}

void logRequest(gchar *host, gchar *request, gchar *message, gchar *reply) {
	/* Get the requested URL*/
	GString *temp = g_string_new(strtok(message, " "));
	GString *url = g_string_new("http://localhost"); 
	g_string_append(url, strtok(NULL, " "));
	
	/* Get the current date in ISO 8601 format*/
	gchar date[26];
	time_t now;
	time(&now);
	struct tm *tm;
	tm = localtime(&now);
	strftime(date, 26, "%FT%H:%M:%S %z", tm);
	date[26] = '\0';
	
	GString* logEntry = g_string_new(date); 
	g_string_append(logEntry, " : ");
	g_string_append(logEntry, host);
	g_string_append(logEntry, " ");
	g_string_append(logEntry, request);
	g_string_append(logEntry, " ");
	g_string_append(logEntry, url->str);
	g_string_append(logEntry, " : ");
	g_string_append(logEntry, reply);
	
	/* Write into the log file */
	FILE * logFile;
	logFile = fopen ("httpd.log","a+");
	if (logFile!=NULL) {
		fputs (logEntry->str, logFile);
		fclose (logFile);
	}
}