SRC=arpspoof.c
OUT=arpspoof
CFLAGS=-Wall -Wextra -Wpedantic -std=gnu99 `libnet-config --defines`

all:	$(OUT)

$(OUT):	$(SRC)
	$(CC) $(CFLAGS) -o $@ $?

clean:
	$(RM) $(OUT)
