CXX      = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
TARGET   = radiohdr_test

all: $(TARGET)

$(TARGET):
	$(CXX) $(CXXFLAGS) -o $(TARGET) main.cpp radiohdr.cpp

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all test clean
