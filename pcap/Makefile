CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lpcap

TARGET  = pcap-test
SRC     = pcap-test.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
