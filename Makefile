SRC=arpspoof.c
OUT=arpspoof
CFLAGS=-Wall -Wextra -Wpedantic -std=gnu99

all:	$(OUT)

$(OUT):	$(SRC)
	$(CC) $(CFLAGS) -o $@ $?

clean:
	$(RM) $(OUT)
