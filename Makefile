CC = gcc
CFLAGS = -Wall -fPIC
LDFLAGS = -shared -lpcap

SRC_DIR = src/c_core
BUILD_DIR = build
TARGET = libsniffer.so

all: $(TARGET)

$(TARGET): $(SRC_DIR)/sniffer.c $(SRC_DIR)/modbus.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SRC_DIR)/sniffer.c -o $(BUILD_DIR)/$(TARGET) $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
