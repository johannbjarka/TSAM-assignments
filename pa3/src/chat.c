/* 
 * server pass phrase: golf
 * client pass phrase: arse
 */

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <arpa/inet.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>

#define RETURN_NULL(x) if ((x)==NULL) exit (1)
#define RETURN_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define RETURN_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(1); }

/* This variable is 1 while the client is active and becomes 0 after
   a quit command to terminate the client and to clean up the 
   connection. */
static int active = 1;

enum ops { WHO, SAY, USER, LIST, JOIN, GAME, ROLL };

/* To read a password without echoing it to the console.
 *
 * We assume that stdin is not redirected to a pipe and we won't
 * access tty directly. It does not make much sense for this program
 * to redirect input and output.
 *
 * This function is not safe to termination. If the program
 * crashes during getpasswd or gets terminated, then echoing
 * may remain disabled for the shell (that depends on shell,
 * operating system and C library). To restore echoing,
 * type 'reset' into the sell and press enter. */
void getpasswd(const char *prompt, char *passwd, size_t size) {
	struct termios old_flags, new_flags;

	/* Clear out the buffer content. */
	memset(passwd, 0, size);
	
	/* Disable echo. */
	tcgetattr(fileno(stdin), &old_flags);
	memcpy(&new_flags, &old_flags, sizeof(old_flags));
	new_flags.c_lflag &= ~ECHO;
	new_flags.c_lflag |= ECHONL;

	if (tcsetattr(fileno(stdin), TCSANOW, &new_flags) != 0) {
		perror("tcsetattr");
		exit(EXIT_FAILURE);
	}

	printf("%s", prompt);
	fgets(passwd, size, stdin);

	/* The result in passwd is '\0' terminated and may contain a final
	 * '\n'. If it exists, we remove it.*/
	if(passwd[strlen(passwd) - 1] == '\n') {
		passwd[strlen(passwd) - 1] = '\0';
	}

	/* Restore the terminal */
	if (tcsetattr(fileno(stdin), TCSANOW, &old_flags) != 0) {
		perror("tcsetattr");
		exit(EXIT_FAILURE);
	}
}

/* If someone kills the client, it should still clean up the readline
   library, otherwise the terminal is in a inconsistent state. We set
   active to 0 to get out of the loop below. Also note that the select
   call below may return with -1 and errno set to EINTR. Do not exit
   select with this error. */
void sigint_handler(int signum) {
	active = 0;
	write(STDOUT_FILENO, "Terminated.\n", 12);
	fsync(STDOUT_FILENO);
}

/* The next two variables are used to access the encrypted stream to
 * the server. The socket file descriptor server_fd is provided for
 * select (if needed), while the encrypted communication should use
 * server_ssl and the SSL API of OpenSSL.
 */
static int server_fd;
static SSL *server_ssl;

/* This variable shall point to the name of the user. The initial value
   is NULL. Set this variable to the username once the user managed to be
   authenticated. */
static char *user;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
static char *chatroom;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static char *prompt;
  
int skipSpaces(char *line, int i) {
	for (; line[i] != '\0' && isspace(line[i]); i++);
	return (line[i] != '\0') ? i : -1;
}

void writeOut(char *line) {
	write(STDOUT_FILENO, line, strlen(line));
	fsync(STDOUT_FILENO);
	rl_redisplay();
}

/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */
void readline_callback(char *line) {
	if(line == NULL) {
		rl_callback_handler_remove();
		active = 0;
		return;
	}
	if(strlen(line) > 0) {
		add_history(line);
	}
	if(strncmp("/bye", line, 4) == 0 || strncmp("/quit", line, 5) == 0) {
		rl_callback_handler_remove();
		active = 0;
		return;
	}
	if(strncmp("/game", line, 5) == 0) {
		int i = skipSpaces(line, 5);
		if(i == -1) {
			writeOut("Usage: /game username\n");
			return;
		}
		/* TODO: Start game */
		return;
	}
	if(strncmp("/roll", line, 5) == 0) {
		/* TODO: roll dice and declare winner. */
		return;
	}
	if(strncmp("/join", line, 5) == 0) {
		int i = skipSpaces(line, 5);
		if(i == -1) {
			writeOut("Usage: /join chatroom\n");
			return;
		}
		char* chatroom = strdup(&(line[i]));
		/* TODO: Process and send this information to the server. */

		/* Maybe update the prompt. */
		free(prompt);
		prompt = NULL; /* What should the new prompt look like? */
		rl_set_prompt(prompt);
		return;
	}
	if(strncmp("/list", line, 5) == 0) {
		/* TODO: Query all available chat rooms */
		return;
	}
	if(strncmp("/say", line, 4) == 0) {
		int i = skipSpaces(line, 4);
		if(i == -1) {
			writeOut("Usage: /say username message\n");
			return;
		}
		/* get username */
		int j = i+1;
		while (line[j] != '\0' && isgraph(line[j])) { j++; }
		if (line[j] == '\0') {
			writeOut("Usage: /say username message\n");
			return;
		}
		char *receiver = strndup(&(line[i]), j - i - 1);
		char *message = strdup(&(line[j]));
		
		/* TODO: Send private message to receiver. */

		return;
	}
	if(strncmp("/user", line, 5) == 0) {
		int i = skipSpaces(line, 5);
		if(i == -1) {
			writeOut("Usage: /user username\n");
			return;
		}
		char *new_user = strdup(&(line[i]));
		char passwd[48];
		getpasswd("Password: ", passwd, 48);

		/* TODO: Process and send this information to the server. */
		//writeOut(passwd);
		/* Maybe update the prompt. */
		free(prompt);
		prompt = strdup(":: "); /* What should the new prompt look like? */
		rl_set_prompt(prompt);
		return;
	}
	if(strncmp("/who", line, 4) == 0) {
		/* TODO: Query all available users */
		return;
	}
	if(strncmp("/", line, 1) == 0) {
		writeOut("Invalid command\n");
		return;
	}
	/* Sent the buffer to the server. */
	char buffer[256];
	snprintf(buffer, 255, "Message: %s\n", line);
	write(STDOUT_FILENO, buffer, strlen(buffer));
	fsync(STDOUT_FILENO);
}

int main(int argc, char **argv) {
	int err;
	char buf[4096];
	char *str;
	struct sockaddr_in server_addr;
	
	if(argc < 3) {
		printf("You must supply an address and port number to run the client");
		exit(0);
	}
	
	/* Initialize OpenSSL */
	SSL_library_init();
	SSL_load_error_strings();
	SSL_CTX *ssl_ctx = SSL_CTX_new(TLSv1_client_method());
        
	/* TODO:
	 * We may want to use a certificate file if we self sign the
	 * certificates using SSL_use_certificate_file(). If available,
	 * a private key can be loaded using
	 * SSL_CTX_use_PrivateKey_file(). The use of private keys with
	 * a server side key data base can be used to authenticate the
	 * client.
	 */
	
	int result = SSL_CTX_use_certificate_file(ssl_ctx, "cert.pem", SSL_FILETYPE_PEM);

	SSL_CTX_use_PrivateKey_file(ssl_ctx, "key.pem", SSL_FILETYPE_PEM);

	printf("certificate result %d\n", result);

	/* Check if the client certificate and private-key matches */
	if (!SSL_CTX_check_private_key(ssl_ctx)) {
		fprintf(stderr,"Private key does not match the certificate public key\n");
		exit(1);
	}
	
	/* Load the RSA CA certificate into the SSL_CTX structure
     * This will allow this client to verify the server's     
     * certificate.                                           
	 */
    /*if (!SSL_CTX_load_verify_locations(ssl_ctx, "cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }*/
	
	/* Set flag in context to require peer (server) certificate verification */
    //SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    //SSL_CTX_set_verify_depth(ssl_ctx, 1);
	
    /* Set up a TCP socket */	
	server_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP); /* Check if correct file descriptor*/
    RETURN_ERR(server_fd, "socket");
	
	memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(argv[1]);   /* Server IP */
	server_addr.sin_port        = htons(atoi(argv[2]));       /* Server Port number */
	
    /* Establish a TCP/IP connection to the SSL client */

	err = connect(server_fd, (struct sockaddr*) &server_addr, sizeof(server_addr));
	RETURN_ERR(err, "connect");
	
    /* An SSL structure is created */
	server_ssl = SSL_new(ssl_ctx);
	RETURN_NULL(server_ssl);
	
	/* Use the socket for the SSL connection. */
	SSL_set_fd(server_ssl, server_fd);
	
	/* Perform SSL Handshake on the SSL client */
    err = SSL_connect(server_ssl);
	RETURN_SSL(err);
	
	/* Now we can create SSL and use them instead of the socket.
	 * The SSL is responsible for maintaining the state of the
	 * encrypted connection and the actual encryption. Reads and
	 * writes to sock_fd will insert unencrypted data into the
	 * stream, which even may crash the server. */

	/* Set up secure connection to the chatd server. */

	/* Read characters from the keyboard while waiting for input. */
	prompt = strdup("> ");
	rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
	while(active) {
		fd_set rfds;
		struct timeval timeout;

		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
	
		int r = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &timeout);
		if(r < 0) {
			if (errno == EINTR) {
				/* This should either retry the call or
				   exit the loop, depending on whether we
				   received a SIGTERM. */
				continue;
			}
			/* Not interrupted, maybe nothing we can do? */
			perror("select()");
			break;
		}
		if(r == 0) {
			//write(STDOUT_FILENO, "No message?\n", 12);
			//fsync(STDOUT_FILENO);
			/* Whenever you print out a message, call this
			   to reprint the current input line. */
			rl_redisplay();
			continue;
		}
		if(FD_ISSET(STDIN_FILENO, &rfds)) {
			rl_callback_read_char();
		}

		/* Handle messages from the server here! */
		err = SSL_read(server_ssl, buf, sizeof(buf)-1);

		RETURN_SSL(err);
		buf[err] = '\0';

		printf ("Received %d chars:'%s'\n", err, buf);
	}
    /* Shut down the client side of the SSL connection */

    err = SSL_shutdown(server_ssl);
    RETURN_SSL(err);

    /* Terminate communication on a socket */
    err = close(server_fd);

    RETURN_ERR(err, "close");

    /* Free the SSL structure */
    SSL_free(server_ssl);

    /* Free the SSL_CTX structure */
    SSL_CTX_free(ssl_ctx);
}
