/* 
 *
 */

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <glib.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

#define RETURN_NULL(x) if ((x)==NULL) exit(1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }

const int MAX_CONN = 10;
static SSL *client_ssl;

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
	const struct sockaddr_in *_addr1 = addr1;
	const struct sockaddr_in *_addr2 = addr2;

	/* If either of the pointers is NULL or the addresses
	   belong to different families, we abort. */
	g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
		(_addr1->sin_family != _addr2->sin_family));

	if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
		return -1;
	} else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
		return 1;
	} else if (_addr1->sin_port < _addr2->sin_port) {
		return -1;
	} else if (_addr1->sin_port > _addr2->sin_port) {
		return 1;
	}
	return 0;
}



int main(int argc, char **argv)
{
	int fdmax, listener, newfd, nbytes, err;
	fd_set master, read_fds;
	struct sockaddr_in serveraddr, clientaddr;
	char message[512];
	
	int yes = 1;
	int i;

	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	
	if(argc < 2) {
		printf("You must supply a port number to run the server");
		exit(0);
	}
	
	/* Initialize OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_server_method());
	
	if(!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
	
	int result = SSL_CTX_use_certificate_file(ssl_ctx, "certd.pem", SSL_FILETYPE_PEM);
	printf("certificate result %d\n", result);

	SSL_CTX_use_PrivateKey_file(ssl_ctx,"keyd.pem", SSL_FILETYPE_PEM);

	result = printf("private key result %d\n", result);

	/* Check if the server certificate and private-key matches */
    if(!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr,"Private key does not match the certificate public key\n");
        exit(1);
    }
	
	/* Load the RSA CA certificate into the SSL_CTX structure */
	if(!SSL_CTX_load_verify_locations(ssl_ctx, "certd.pem", NULL)) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Set to require peer (client) certificate verification */
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

	/* Set the verification depth to 1 */
	SSL_CTX_set_verify_depth(ssl_ctx, 1);
	
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
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
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
						printf("Connection received \n");
						/* Handle new connections */
						socklen_t addrlen = (socklen_t) sizeof(clientaddr);
						if((newfd = accept(listener, (struct sockaddr *)&clientaddr, &addrlen)) == -1) {
							perror("Server-accept()");
						}
						else {
							FD_SET(newfd, &master); /* Add to master set */
							if(newfd > fdmax) { /* Keep track of the maximum */
								fdmax = newfd;
							}
							/* TCP connection is ready. */
							/* A SSL structure is created */
							client_ssl = SSL_new(ssl_ctx);

							RETURN_NULL(client_ssl);
							
							/* Assign the socket into the SSL structure (SSL and socket without BIO) */
							SSL_set_fd(client_ssl, newfd);

							/* Perform SSL Handshake on the SSL server */
							err = SSL_accept(client_ssl);

							RETURN_SSL(err);
						}
					}
					else {						
						/* Receive data from the SSL client */
						err = SSL_read(client_ssl, message, sizeof(message) - 1);
						RETURN_SSL(err);
						message[err] = '\0';
						printf ("Received %d chars:'%s'\n", err, message);
						
						/* Send data to the SSL client */
						err = SSL_write(client_ssl, "This message is from the SSL server", 
										strlen("This message is from the SSL server"));
						RETURN_SSL(err);
						
						/*if((nbytes = recv(i, message, sizeof(message), 0)) <= 0) {
							// Got error or connection closed by client
							if(nbytes < 0) {
								perror("recv()");
							}							
							fdmax -= 1;
							shutdown(i, SHUT_RDWR);
							close(i);
							FD_CLR(i, &master);
							gchar *key1 = g_strdup_printf("%i", i);
							g_hash_table_remove(connections, key1);
						}
						else {
							GString *messageCopy = g_string_new(message);
							printf("%s\n", message);
							if(FD_ISSET(i, &master)) {
								if(i != listener) {
									time_t now;
									now = time(NULL);
									gchar *theKey = g_strdup_printf("%i", i);
									g_hash_table_replace(connections, theKey, (gpointer)now);
										
									
									// TODO parse input, write appropriate functions for the input possibilities
									
									// Send the message back.
									write(i, message, (size_t) nbytes);
									
									
								} else {
									// Do nothing 
								}
							}
						}*/
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
							/* Shut down this side (server) of the connection. */
							err = SSL_shutdown(client_ssl);
							RETURN_SSL(err);
							/* Terminate communication on a socket */
							err = close(i);
							RETURN_ERR(err, "close");
							/* Free the SSL structure */
							SSL_free(client_ssl);
							
							fdmax -= 1;
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
					/* Shut down this side (server) of the connection. */
					err = SSL_shutdown(client_ssl);
					RETURN_SSL(err);
					/* Terminate communication on a socket */
					err = close(closeFd);
					RETURN_ERR(err, "close");
					/* Free the SSL structure */
					SSL_free(client_ssl);
					
					fdmax -= 1;
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
