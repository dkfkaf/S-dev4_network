CXX      = g++
CXXFLAGS = -std=c++11 -Wall -O2
LDFLAGS  = -lpcap -lpthread
TARGET   = airodump
OBJS     = main.o parser.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean