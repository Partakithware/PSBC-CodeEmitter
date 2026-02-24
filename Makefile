CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
TARGET = emitter
SOURCES = main.cpp emitter.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

test: $(TARGET)
	@echo "Running test examples..."
	./$(TARGET) examples/hello.emit hello.bin
	@echo ""
	./$(TARGET) examples/elf64_hello.emit hello_world

.PHONY: all clean test
