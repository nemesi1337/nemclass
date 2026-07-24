# Build the nemclass_mod userspace test tools (no kernel headers needed beyond
# the shared UAPI header, which is includable from userspace).
CFLAGS ?= -O2 -Wall -Wextra
CFLAGS += -I../include/uapi

all: fixture nemclient

fixture: fixture.c
	$(CC) $(CFLAGS) -o $@ $<

nemclient: nemclient.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f fixture nemclient

.PHONY: all clean
