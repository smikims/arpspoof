SRC=arp.c
OUT=arp
CFLAGS=-Wall -Wextra -Wpedantic -std=gnu99

all:
	$(CC) $(CFLAGS) -o $(OUT) $(SRC)
clean:
	$(RM) $(OUT)
