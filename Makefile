CXX = g++
CXXFLAGS = -Wall -std=c++17

TARGET = sum-nbo
SRC = sum-nbo.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)