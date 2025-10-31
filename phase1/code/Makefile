CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
LDFLAGS := 

SRC_DIR := .
BIN_DIR := bin

SERVER_SRC := $(SRC_DIR)/server.cpp
CLIENT_SRC := $(SRC_DIR)/client.cpp

SERVER_BIN := $(BIN_DIR)/server
CLIENT_BIN := $(BIN_DIR)/client

INCLUDES := -I.

all: dirs $(SERVER_BIN) $(CLIENT_BIN)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

dirs: $(BIN_DIR)

$(SERVER_BIN): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean dirs
