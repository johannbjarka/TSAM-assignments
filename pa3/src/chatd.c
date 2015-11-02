
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

enum ops { WHO, SAY, USER, LIST, JOIN, GAME, ROLL };

struct user {
	unsigned long addr;
	unsigned short port;
	char name[40];
	char room[40];
	time_t time;
};

static int fdmax;

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2) {
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

void closeCon(int fd, fd_set* master) {
	printf("disconnected\n");
	fdmax--;
	FD_CLR(fd, master);
}

int main(int argc, char **argv) {
	int i, listener, newfd, nbytes, err, yes = 1;
	fd_set master, read_fds;
	struct sockaddr_in serveraddr, clientaddr;
	char message[512];
	time_t now;
	char timeF[sizeof "2011-10-08T07:07:09Z"];
	
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

	/* Check if the server certificate and private-key matches */
    if(!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr,"Private key does not match the certificate public key\n");
        exit(1);
    }
	
	/* Load the RSA CA certificate into the SSL_CTX structure */
	if(!SSL_CTX_load_verify_locations(ssl_ctx, "cert.pem", NULL)) {
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
	GHashTable *authTable = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(authTable, "siggi", "asdf1");
	g_hash_table_insert(authTable, "derp", "asdf2");
	g_hash_table_insert(authTable, "joi", "asdf3");
	
	GHashTable *connections = g_hash_table_new(g_direct_hash, g_direct_equal);
	//GTree *nonUsers = g_tree_new(sockaddr_in_cmp);
	//GTree *authUsers = g_tree_new(sockaddr_in_cmp);

	FD_SET(listener, &master);
	fdmax = listener;
	for (;;) {
		read_fds = master;
		struct timeval tv;
		
		time(&now);
		strftime(timeF, sizeof timeF, "%FT%TZ", gmtime(&now));
		
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		int retval = select(fdmax+1, &read_fds, NULL, NULL, &tv);
		
		if(retval == -1) {
			perror("select()");
			exit(1);
		} else if(retval > 0) {
			for(i = 0; i <= fdmax; i++) {
				if(FD_ISSET(i, &read_fds)) {
					/* A file descriptor is active */
					if(i == listener) {
						/* Handle new connections */
						socklen_t addrlen = (socklen_t) sizeof(clientaddr);
						if((newfd = accept(listener, (struct sockaddr *)&clientaddr, &addrlen)) == -1) {
							perror("Server-accept()");
						}
						else {
							printf("%s : %s:%d connected\n", timeF, inet_ntoa(clientaddr.sin_addr), clientaddr.sin_port);

							FD_SET(newfd, &master); /* Add to master set */
							if(newfd > fdmax) { /* Keep track of the maximum */
								fdmax = newfd;
							}
							/* TCP connection is ready. */
							/* An SSL structure is created */
							client_ssl = SSL_new(ssl_ctx);

							RETURN_NULL(client_ssl);
							
							/* Assign the socket into the SSL structure (SSL and socket without BIO) */
							SSL_set_fd(client_ssl, newfd);

							/* Perform SSL Handshake on the SSL server */
							err = SSL_accept(client_ssl);
							RETURN_SSL(err);
							printf("asdf\n");
						}
					}
					else {						
						/* Receive data from the SSL client */
						err = SSL_read(client_ssl, message, sizeof(message) - 1);
						RETURN_SSL(err);
						
						if(err == 0) {
							continue;
						}
						
						message[err] = '\0';
						printf("Received %d chars:'%s'\n", err, message);
						
						switch(message[0]) {
						case WHO:
							printf("who!\n");
							break;
						case SAY:
							printf("say!\n");
							break;
						case USER:
							printf("user!\n");
							break;
						case LIST:
							printf("list!\n");
							//g_hash_table_iter_init;
							break;
						case JOIN:
							printf("join!\n");
							break;
						case GAME:
							printf("game!\n");
							break;
						case ROLL:
							printf("roll!\n");
							break;
						}
						
						/* Send data to the SSL client */
						err = SSL_write(client_ssl, "This message is from the SSL server", strlen("This message is from the SSL server"));
						RETURN_SSL(err);
						
						/*
						closeCon(i, &master);
						g_hash_table_remove(connections, GINT_TO_POINTER(i));
						}
						else {
							//GString *messageCopy = g_string_new(message);
							if(FD_ISSET(i, &master)) {
								if(i != listener) {
									struct user *newuser = g_new0(struct user, 1);
									newuser->time = time(NULL);
									newuser->addr = clientaddr.sin_addr.s_addr;
									newuser->port = clientaddr.sin_port;
									g_hash_table_replace(connections, GINT_TO_POINTER(i), newuser);

									// TODO parse input, write appropriate functions for the input possibilities

									// Send the message back. 

				//---------
						err = SSL_write(client_ssl, "This message is from the SSL server", 
										strlen("This message is from the SSL server"));
						RETURN_SSL(err);
						
						if((nbytes = recv(i, message, sizeof(message), 0)) <= 0) {
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
				//430b77850a4c5ef1fd14c506e372d8574f02b88e
							if(FD_ISSET(i, &master)) {
								if(i != listener) {
									time_t now;
									now = time(NULL);
									gchar *theKey = g_strdup_printf("%i", i);
									g_hash_table_replace(connections, theKey, (gpointer)now);
										
									
									// TODO parse input, write appropriate functions for the input possibilities
									
									// Send the message back.
									write(i, message, (size_t) nbytes);

							}
						}*/
					}
				}
				else {
					gpointer ptr = g_hash_table_lookup(connections, GINT_TO_POINTER(i));
					if(ptr != NULL) {
						struct user *userdata = (struct user*) ptr;
						if(difftime(time(NULL), userdata->time) >= 5.0) {
							/* Shut down this side (server) of the connection. */
							err = SSL_shutdown(client_ssl);
							RETURN_SSL(err);
							/* Terminate communication on a socket */
							err = close(i);
							RETURN_ERR(err, "close");
							/* Free the SSL structure */
							SSL_free(client_ssl);
							printf("%s : %s:%d disconnected\n", timeF, inet_ntoa(clientaddr.sin_addr), clientaddr.sin_port);
							closeCon(i, &master);
							g_hash_table_remove(connections, GINT_TO_POINTER(i));
						}
					}
				}
			}
		} else {
			GHashTableIter iter;
			gpointer key, value;
			g_hash_table_iter_init(&iter, connections);
			while(g_hash_table_iter_next(&iter, &key, &value)) {
				struct user *userdata = (struct user*) value;
				if(difftime(time(NULL), userdata->time) >= 5.0) {
					/* Shut down this side (server) of the connection. */
					err = SSL_shutdown(client_ssl);
					RETURN_SSL(err);
					/* Terminate communication on a socket */

					err = close(GPOINTER_TO_INT(key));
					RETURN_ERR(err, "close");
					/* Free the SSL structure */
					SSL_free(client_ssl);
					printf("%s : %d:%d disconnected\n", timeF, userdata->addr, userdata->port);
					
					closeCon(GPOINTER_TO_INT(key), &master);
					g_hash_table_iter_remove(&iter);
				}
			}
		}
	}
}
