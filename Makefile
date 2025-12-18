CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -D_GNU_SOURCE $(shell pkg-config --cflags libgcrypt gpg-error)
LDFLAGS = $(shell pkg-config --libs libgcrypt gpg-error)

TARGET = passmgr
SRCS = main.c crypto.c manager.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
