CC      = g++        # gcc → g++ (C++ 파일이므로)
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lpcap

TARGET  = pcaptest
SRC     = pcap.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean