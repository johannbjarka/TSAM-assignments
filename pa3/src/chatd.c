
#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <glib.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define RETURN_NULL(x) if ((x)==NULL) exit(1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }

const int MAX_CONN = 10;
const double LOGIN_DELAY = 2.0;
const double TIMEOUT = 300.0;
FILE *logFile;
SSL_CTX *ssl_ctx;
typedef void handler_t(int);
handler_t *Signal(int signum, handler_t *handler);
void unix_error(char *msg);

enum ops { SPEAK = 1, WHO, SAY, USER, LIST, JOIN, GAME, ROLL, NICK, BYE, CLOSE };

typedef struct client_user {
	SSL *ssl;
	unsigned long addr;
	unsigned short port;
	char addr_str[16];
	char name[40];
	char nick[40];
	char room[40];
	time_t time;
	int login_tries;
} user;

typedef struct challenger_user {
	SSL *ssl;
	char name[40];
} challenger;

static int fdmax;
static char timeF[sizeof "2011-10-08T07:07:09Z"];

/* This variable is 1 while the server is active and becomes 0 after
   a quit command to terminate the server and to clean up the 
   connection. */
static int active = 1;

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

/* Shut down this side (server) of the connection. Terminate 
 * communication on a socket and free the SSL structure.
 */
void closeCon(user *usr, fd_set *master) {
	int fd = SSL_get_fd(usr->ssl);
	RETURN_SSL(SSL_shutdown(usr->ssl));
	SSL_free(usr->ssl);
	RETURN_ERR(close(fd), "close");
	FD_CLR(fd, master);
}

void logAction(char *str) {
	/* Write into the log file */
	printf("%s", str);
	if(logFile != NULL) {
		fputs(str, logFile);
		fflush(logFile); 
	}
}

/*
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler) {
    struct sigaction action, old_action;

    action.sa_handler = handler;  
    sigemptyset(&action.sa_mask); /* block sigs of type being handled */
    action.sa_flags = SA_RESTART; /* restart syscalls if possible */

    if (sigaction(signum, &action, &old_action) < 0) {
	unix_error("Signal error");
    }
    return (old_action.sa_handler);
}

/*
 * unix_error - unix-style error routine
 */
void unix_error(char *msg)
{
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

void sigint_handler(int signum) {
	char str[80];
	sprintf(str, "%s : Server closed\n", timeF);
	logAction(str);
	fclose(logFile);
	
	/* Free the SSL_CTX structure */
    SSL_CTX_free(ssl_ctx);
	exit(0);
}

int main(int argc, char **argv) {
	int i, listener, yes = 1;
	fd_set master, read_fds;
	struct sockaddr_in serveraddr;
	char message[512];
	char str[80];
	time_t now;
	
	FD_ZERO(&read_fds);
	
	if(argc < 2) {
		printf("You must supply a port number to run the server");
		exit(0);
	}
	
	/* Open file stream for log file */
	logFile = fopen("chatd.log","a+");
	
	Signal(SIGINT, sigint_handler); /* ctrl-c */
	
	/* Initialize OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new(TLSv1_server_method());
	
	if(!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
	
	/* Load the server certificate into the SSL_CTX structure */
	if (SSL_CTX_use_certificate_file(ssl_ctx, "certd.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	/* Load the private-key corresponding to the server certificate */
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "keyd.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

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

	/* Create dictionary to keep track of active usernames */
	GHashTable *usernames = g_hash_table_new(g_str_hash, g_str_equal);
	/* Create dictionary to keep of track of connected users */
	GHashTable *connections = g_hash_table_new(g_direct_hash, g_direct_equal);
	GHashTable *gameChallengers = g_hash_table_new(g_str_hash, g_str_equal);

	FD_SET(listener, &master);
	fdmax = listener;
	while(active) {
		read_fds = master;
		struct timeval tv;
		
		time(&now);
		strftime(timeF, sizeof(timeF), "%FT%TZ", gmtime(&now));
		
		tv.tv_sec = 3;
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
						int newfd;
						struct sockaddr_in clientaddr;
						/* Handle new connections */
						socklen_t addrlen = (socklen_t) sizeof(clientaddr);
						if((newfd = accept(listener, (struct sockaddr *)&clientaddr, &addrlen)) == -1) {
							perror("Server-accept()");
							continue;
						}
						/* TCP connection is ready. */
						sprintf(str, "%s : %s:%d connected\n", timeF, inet_ntoa(clientaddr.sin_addr), clientaddr.sin_port);
						logAction(str);

						FD_SET(newfd, &master); /* Add to master set */
						if(newfd > fdmax) { /* Keep track of the maximum */
							fdmax = newfd;
						}
						/* An SSL structure is created */
						SSL *client_ssl = SSL_new(ssl_ctx);
						RETURN_NULL(client_ssl);
						
						SSL_set_fd(client_ssl, newfd);
						/* Perform SSL Handshake on the SSL server */
						RETURN_SSL(SSL_accept(client_ssl));
						
						user *newuser = g_new0(user, 1);
						newuser->ssl = client_ssl;
						newuser->time = now;
						newuser->addr = clientaddr.sin_addr.s_addr;
						newuser->port = clientaddr.sin_port;
						strcpy(newuser->addr_str, inet_ntoa(clientaddr.sin_addr));
						g_hash_table_replace(connections, GINT_TO_POINTER(newfd), newuser);
						
						RETURN_SSL(SSL_write(newuser->ssl, "Welcome", 7));
					}
					else {
						/* Receive data from the SSL client */
						gpointer ptr = g_hash_table_lookup(connections, GINT_TO_POINTER(i));
						if(ptr == NULL) continue;
						user *caller = (user*) ptr;
						
						int len = SSL_read(caller->ssl, message, sizeof(message) - 1);
						RETURN_SSL(len);
						if(len == 0) continue;
						message[len] = '\0';
						unsigned n;
						char buff[2048];
						memset(buff, 0, sizeof(buff));
						
						int roll, hasLeft = 0;
						SSL *ussl;
						GHashTable *rooms;
						GHashTableIter iter;
						gpointer key, value;
						
						
						if(strcmp(caller->name, "") == 0 && message[0] != USER) {
							RETURN_SSL(SSL_write(caller->ssl, "Please authorize yourself!(/user name)", 38));
						}
						else if(SPEAK == message[0]) {
							if(strcmp(caller->room, "") == 0) {
								RETURN_SSL(SSL_write(caller->ssl, "Please join a room!", 19));
							} else {
								strcat(buff, caller->nick);
								strcat(buff, ": ");
								strncat(buff, &message[1], sizeof(buff) - 45);
								g_hash_table_iter_init(&iter, connections);
								while(g_hash_table_iter_next(&iter, &key, &value)) {
									user *aUser = (user*) value;
									if(strcmp(caller->room, aUser->room) == 0) {
										RETURN_SSL(SSL_write(aUser->ssl, buff, strlen(buff)));
									}
								}
							}
						}
						else if(WHO == message[0]) {
							g_hash_table_iter_init(&iter, connections);
							while(g_hash_table_iter_next(&iter, &key, &value)) {
								user *aUser = (user*) value;
								sprintf(&buff[strlen(buff)], "%s:%d ", aUser->addr_str, aUser->port);
								strcat(buff, (strlen(aUser->nick) > 0 ? aUser->nick : "N/A"));
								strcat(buff, " | ");
								strcat(buff, (strlen(aUser->room) > 0 ? aUser->room : "N/A"));
								strcat(buff, "\n");
							}
							buff[strlen(buff)-1] = '\0'; // Removing last newline
							//possible overflow, not handled.
							RETURN_SSL(SSL_write(caller->ssl, buff, strlen(buff)));
						} 
						else if(SAY == message[0]) {
							char username[40];
							char usermsg[1024];
							for(n = 0; !isspace(message[n+1]) && n < sizeof(caller->nick); n++);
							strncpy(username, &message[1], n);
							username[sizeof(username)-1] = '\0';
							strncpy(usermsg, &message[n+1], sizeof(usermsg));
							usermsg[sizeof(usermsg)-1] = '\0';
							ussl = NULL;
							
							g_hash_table_iter_init(&iter, connections);
							while(g_hash_table_iter_next(&iter, &key, &value)) {
								user *aUser = (user*) value;
								if(strcmp(aUser->nick, username) == 0) {
									ussl = aUser->ssl;
									break;
								}
							}
							if(ussl == NULL) {
								RETURN_SSL(SSL_write(caller->ssl, "No known user with that name", 28));
							}
							else if(ussl == caller->ssl) {
								RETURN_SSL(SSL_write(caller->ssl, "Can't send private message to self", 34));
							}
							else {
								strcat(buff, "PM from ");
								strcat(buff, caller->nick);
								strcat(buff, ": ");
								strcat(buff, usermsg);
								RETURN_SSL(SSL_write(ussl, buff, strlen(buff)));
							}
						}
						else if(USER == message[0]) {
							for(n = 1; !isspace(message[n]) && n < sizeof(caller->name); n++);
							gchar *username = strndup(&message[1], n-1);
							gchar *password = strndup(&message[n+1], 32);
							gchar *password64 = g_base64_encode((guchar*)password, strlen(password));
							g_free(password);
							if(g_hash_table_contains(usernames, username)) {
								strcat(buff, "User: ");
								strcat(buff, username);
								strcat(buff, " is already logged in!");
								RETURN_SSL(SSL_write(caller->ssl, buff, strlen(buff)));
								g_free(username);
							}
							else {
								/* Initialize hash structures */
								EVP_MD_CTX *mdctx;
								const EVP_MD *md;
								unsigned char md_value[EVP_MAX_MD_SIZE];
								unsigned int md_len;
								md = EVP_sha256();
								mdctx = EVP_MD_CTX_create();
								GKeyFile *keyfile = g_key_file_new();
								
								if(g_key_file_load_from_file(keyfile, "passwords.ini", G_KEY_FILE_NONE, NULL)) {
									gchar *salt = g_key_file_get_string(keyfile, "salts", username, NULL);
									if(salt != NULL) {
										/* Prepend salt to the password and hash it */								
										EVP_DigestInit_ex(mdctx, md, NULL);
										EVP_DigestUpdate(mdctx, salt, strlen(salt));
										EVP_DigestUpdate(mdctx, password64, strlen(password64));
										g_free(salt);
										g_free(password64);
										EVP_DigestFinal_ex(mdctx, md_value, &md_len);
										EVP_MD_CTX_destroy(mdctx);
										EVP_cleanup();

										/* Compare the result to the stored password */
										gchar *passwd64 = g_base64_encode(md_value, md_len);
										gchar *stored_passwd = g_key_file_get_string(keyfile, "passwords", username, NULL);
										g_key_file_free(keyfile);
										if(strcmp(stored_passwd, passwd64) != 0) {
											if(difftime(now, caller->time) < LOGIN_DELAY) {
												RETURN_SSL(SSL_write(caller->ssl, "DELAYED!", 8));
												g_free(passwd64);
												g_free(stored_passwd);
											}
											else {
												caller->login_tries++;
												if(caller->login_tries == 3) {
													RETURN_SSL(SSL_write(caller->ssl, "KICKED!", 7));
													closeCon(caller, &master);
													g_hash_table_remove(connections, GINT_TO_POINTER(i));
													sprintf(str, "%s : %s:%d kicked, failed to authenticate\n", timeF, caller->addr_str, caller->port);
													logAction(str);
													g_free(passwd64);
													g_free(stored_passwd);
												}
												sprintf(str, "%s : %s:%d %s authentication error\n", timeF, caller->addr_str, caller->port, username);
												logAction(str);
												RETURN_SSL(SSL_write(caller->ssl, "Wrong password!", 15));
												g_free(passwd64);
												g_free(stored_passwd);
											}
										} 
										else {
											/* Password matches */
											strncpy(caller->name, username, sizeof(caller->name));
											strncpy(caller->nick, username, sizeof(caller->nick));
											sprintf(str, "%s : %s:%d %s authenticated\n", timeF, caller->addr_str, caller->port, caller->name);
											logAction(str);
											caller->login_tries = 0;
											
											g_hash_table_add(usernames, caller->name);
											strcat(buff, "Logged in as: ");
											strcat(buff, caller->name);
											RETURN_SSL(SSL_write(caller->ssl, buff, strlen(buff)));
											g_free(passwd64);
											g_free(stored_passwd);
											g_free(username);
										}
									}
									else {
										/* If no file or salt exists, then we have a new user. We create a new random salt and store it */
										char salt[33];
										size_t j, len = 32;
										srand(time(NULL));
										for(j = 0; j < len; j++) {
											salt[j] = '0' + rand() % 72;
										}
										salt[len] = '\0';							
										g_key_file_set_string(keyfile, "salts", username, salt);
										
										/* Prepend salt to the password and hash it */								
										EVP_DigestInit_ex(mdctx, md, NULL);
										EVP_DigestUpdate(mdctx, salt, strlen(salt));
										EVP_DigestUpdate(mdctx, password64, strlen(password64));
										g_free(password64);
										EVP_DigestFinal_ex(mdctx, md_value, &md_len);
										EVP_MD_CTX_destroy(mdctx);
										EVP_cleanup();
										
										/* Store the resulting string and save changes to file */
										gchar *passwd64 = g_base64_encode(md_value, md_len);
										g_key_file_set_string(keyfile, "passwords", username, passwd64);
										g_key_file_save_to_file(keyfile, "passwords.ini", NULL);
										g_key_file_free(keyfile);
										g_free(passwd64);
										
										strncpy(caller->name, username, sizeof(caller->name));
										strncpy(caller->nick, username, sizeof(caller->nick));
										g_hash_table_replace(usernames, username, NULL);
										
										sprintf(str, "%s : %s:%d %s authenticated\n", timeF, caller->addr_str, caller->port, caller->name);
										logAction(str);
										caller->login_tries = 0;
										
										strcpy(buff, "Logged in as: ");
										strcat(buff, caller->name);
										RETURN_SSL(SSL_write(caller->ssl, buff, strlen(buff)));
										g_free(username);
									}
								}
								else {
									/* If no file or salt exists, then we have a new user. We create a new random salt and store it */
									char salt[33];
									size_t j, len = 32;
									srand(time(NULL));
									for(j = 0; j < len; j++) {
										salt[j] = '0' + rand() % 72;
									}
									salt[len] = '\0';							
									g_key_file_set_string(keyfile, "salts", username, salt);
									
									/* Prepend salt to the password and hash it */								
									EVP_DigestInit_ex(mdctx, md, NULL);
									EVP_DigestUpdate(mdctx, salt, strlen(salt));
									EVP_DigestUpdate(mdctx, password64, strlen(password64));
									g_free(password64);
									EVP_DigestFinal_ex(mdctx, md_value, &md_len);
									EVP_MD_CTX_destroy(mdctx);
									EVP_cleanup();
									
									/* Store the resulting string and save changes to file */
									gchar *passwd64 = g_base64_encode(md_value, md_len);
									g_key_file_set_string(keyfile, "passwords", username, passwd64);
									g_key_file_save_to_file(keyfile, "passwords.ini", NULL);
									g_key_file_free(keyfile);
									g_free(passwd64);
									
									strncpy(caller->name, username, sizeof(caller->name));
									strncpy(caller->nick, username, sizeof(caller->nick));
									g_hash_table_replace(usernames, username, NULL);
									
									sprintf(str, "%s : %s:%d %s authenticated\n", timeF, caller->addr_str, caller->port, caller->name);
									logAction(str);
									caller->login_tries = 0;
									
									strcpy(buff, "Logged in as: ");
									strcat(buff, caller->name);
									RETURN_SSL(SSL_write(caller->ssl, buff, strlen(buff)));
									g_free(username);
								}
							}
						} 
						else if(LIST == message[0]) {
							rooms = g_hash_table_new(g_str_hash, g_str_equal);
							g_hash_table_iter_init(&iter, connections);
							while(g_hash_table_iter_next(&iter, &key, &value)) {
								user *aUser = (user*) value;
								if(strlen(aUser->room) == 0) continue;
								if(!g_hash_table_contains(rooms, aUser->room)) {
									g_hash_table_add(rooms, aUser->room);
								}				
							}
							g_hash_table_iter_init(&iter, rooms);
							while(g_hash_table_iter_next(&iter, &key, &value)) {
								strcat(buff, (char *)key);
								strcat(buff, "\n");
							}
							buff[strlen(buff)-1] = '\0'; // Removing last newline
							//possible overflow, not handled.
							RETURN_SSL(SSL_write(caller->ssl, buff, strlen(buff)));
							g_hash_table_destroy(rooms);
						} 
						else if(JOIN == message[0]) {
							strncpy(caller->room, &message[1], sizeof(caller->room));
							caller->room[sizeof(caller->room)-1] = '\0';
							
							strcat(buff, "Joined room: ");
							strcat(buff, caller->room);
							RETURN_SSL(SSL_write(caller->ssl, buff, strlen(buff)));
						} 
						else if(GAME == message[0]) {
							char username[40];
							char usernick[40];
							for(n = 0; !isspace(message[n+1]) && n < sizeof(caller->nick); n++);
							strncpy(usernick, &message[1], n);
							usernick[sizeof(usernick)-1] = '\0';
							ussl = NULL;
							
							g_hash_table_iter_init(&iter, connections);
							while(g_hash_table_iter_next(&iter, &key, &value)) {
								user *aUser = (user*) value;
								if(strcmp(aUser->nick, usernick) == 0) {
									ussl = aUser->ssl;
									strcpy(username, aUser->name);
									break;
								}
							}
							if(ussl == NULL) {
								RETURN_SSL(SSL_write(caller->ssl, "No known user with that name", 28));
							} else if(ussl == caller->ssl) {
								RETURN_SSL(SSL_write(caller->ssl, "Can't challenge yourself", 34));
							} else {
								challenger *chall = g_new(challenger, 1);
								chall->ssl = ussl;
								strcpy(chall->name, username);
								g_hash_table_replace(gameChallengers, caller->name, chall);
								
								strcpy(buff, caller->nick);
								strcat(buff, " has challenged you too a game of dice!(/roll ");
								strcat(buff, caller->nick);
								strcat(buff, ") to challenge him!");
								RETURN_SSL(SSL_write(ussl, buff, strlen(buff)));
							}
						} 
						else if(ROLL == message[0]) {
							char username[40];		
							char usernick[40];
							for(n = 0; !isspace(message[n+1]) && n < sizeof(caller->nick); n++);
							strncpy(usernick, &message[1], n);
							usernick[sizeof(usernick)-1] = '\0';
							roll = (int)(floor(drand48() * 6.0) + 1);
							sprintf(buff, "%s rolled %d", caller->nick, roll);
							if(strlen(usernick) > 0) {
								ussl = NULL;
								g_hash_table_iter_init(&iter, connections);
								while(g_hash_table_iter_next(&iter, &key, &value)) {
									user *aUser = (user*) value;
									if(strcmp(aUser->nick, usernick) == 0) {
										ussl = aUser->ssl;
										strcpy(username, aUser->name);
										break;
									}
								}
							
								gpointer ptr = g_hash_table_lookup(gameChallengers, username);
								if(ptr == 0) {
									RETURN_SSL(SSL_write(caller->ssl, "No user by that name has challenged you", 39));
								}
								else {
									challenger *userdata = (challenger*) ptr;
									if(userdata->ssl == ussl) {
										int s_roll = (int)(floor(drand48() * 6.0) + 1);
										sprintf(buff, "\n%s rolled %d", usernick, s_roll);
										if(roll == s_roll) {
											strcat(buff, "It's a tie.");
										} else {
											strcat(buff, (roll > s_roll ? caller->nick : usernick));
											strcat(buff, " wins!");
										}
										RETURN_SSL(SSL_write(caller->ssl, buff, strlen(buff)));
										RETURN_SSL(SSL_write(ussl, buff, strlen(buff)));
										g_free(ptr);
										g_hash_table_remove(gameChallengers, username);
									}
									else {
										RETURN_SSL(SSL_write(caller->ssl, "No user by that name has challenged you", 39));
									}
								}
							}
							else if(strcmp(caller->room, "") == 0) {
								RETURN_SSL(SSL_write(caller->ssl, buff, strlen(buff)));
							}
							else {
								g_hash_table_iter_init(&iter, connections);
								while(g_hash_table_iter_next(&iter, &key, &value)) {
									user *aUser = (user*) value;
									if(strcmp(caller->room, aUser->room) == 0) {
										RETURN_SSL(SSL_write(aUser->ssl, buff, strlen(buff)));
									}
								}
							}
						} 
						else if(NICK == message[0]) {
							char usernick[40];
							for(n = 0; !isspace(message[n+1]) && n < sizeof(caller->nick); n++);
							strncpy(usernick, &message[1], n);
							usernick[sizeof(usernick)-1] = '\0';
							
							int nickExists = 0;
							g_hash_table_iter_init(&iter, connections);
							while(g_hash_table_iter_next(&iter, &key, &value)) {
								user *aUser = (user*) value;
								if(strcmp(aUser->nick, usernick) == 0) {
									nickExists = 1;
									break;
								}
							}
							if(!nickExists) {
								strcpy(caller->nick, usernick);
								strcat(buff, "Nickname changed to: ");
								strcat(buff, caller->nick);
								RETURN_SSL(SSL_write(caller->ssl, buff, strlen(buff)));
							}
							else {
								RETURN_SSL(SSL_write(caller->ssl, "Someone is already using that nick!", 35));
							}
							
						} 
						else if(BYE == message[0]) {
							closeCon(caller, &master);
							sprintf(str, "%s : %s:%d disconnected\n", timeF, caller->addr_str, caller->port);
							logAction(str);
							g_hash_table_remove(usernames, caller->name);	
							g_free(g_hash_table_lookup(connections, GINT_TO_POINTER(i)));
							g_hash_table_remove(connections, GINT_TO_POINTER(i));
							hasLeft = 1;
						}
						if(!hasLeft) {
							caller->time = now;
						}
					}
				}
				else {
					gpointer ptr = g_hash_table_lookup(connections, GINT_TO_POINTER(i));
					if(ptr == NULL) continue;
					user *userdata = (user*) ptr;
					
					if(difftime(now, userdata->time) >= TIMEOUT) {
						sprintf(str, "%s : %s:%d time out\n", timeF, userdata->addr_str, userdata->port);
						logAction(str);
						char buff[30];
						buff[0] = CLOSE;
						strcat(&buff[1], "Kicked due to timing out!");
						RETURN_SSL(SSL_write(userdata->ssl, buff, strlen(buff)));
						closeCon(userdata, &master);
						g_hash_table_remove(usernames, userdata->name);
						g_free(g_hash_table_lookup(connections, GINT_TO_POINTER(i)));
						g_hash_table_remove(connections, GINT_TO_POINTER(i));
					}
				}
			}
		} else {
			GHashTableIter iter;
			gpointer key, value;
			g_hash_table_iter_init(&iter, connections);
			while(g_hash_table_iter_next(&iter, &key, &value)) {
				user *userdata = (user*) value;
				if(difftime(now, userdata->time) >= TIMEOUT) {
					sprintf(str, "%s : %s:%d time out\n", timeF, userdata->addr_str, userdata->port);
					logAction(str);
					char buff[30];
					buff[0] = CLOSE;
					strcat(&buff[1], "Kicked due to timing out!");
					RETURN_SSL(SSL_write(userdata->ssl, buff, strlen(buff)));
					closeCon(userdata, &master);
					g_hash_table_remove(usernames, userdata->name);
					g_free(g_hash_table_lookup(connections, &iter));
					g_hash_table_iter_remove(&iter);
				}
			}
		}
	}
}