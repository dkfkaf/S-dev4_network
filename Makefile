CXX      = g++
CXXFLAGS = -Wall -Wextra -O2 -std=c++11
TARGET   = deauth-attack
SRC      = main.cpp frame.cpp

.PHONY: all clean debug

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) -lpcap

# 디버그 빌드 (gdb 용 심볼 + 최적화 끔)
debug: CXXFLAGS = -Wall -Wextra -O0 -g -std=c++11
debug: clean all

clean:
	rm -f $(TARGET) *.o
