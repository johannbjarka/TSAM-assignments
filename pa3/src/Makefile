CC = gcc
CFLAGS = -std=gnu11 -O2 -g -Wall -Wextra -Wformat=2 $(shell pkg-config glib-2.0 openssl --cflags)

all: chatd chat

chat: chat.o
	$(CC) $(CFLAGS) -o $@ $^ -lreadline $(shell pkg-config glib-2.0 openssl --libs)

chatd: chatd.o
	$(CC) $(CFLAGS) -lm -o $@ $^ $(shell pkg-config glib-2.0 openssl --libs)

clean:
	rm -f *.o *~

distclean: clean
	rm -f chatd chat
