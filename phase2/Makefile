CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -Wpedantic -O2
LDFLAGS := -pthread

SRC_DIR := .
BUILD_DIR := build
BIN_DIR := bin

SERVER_SRCS := \
	server/main.cpp \
	server/server_app.cpp \
	server/server_state.cpp \
	server/command_handler.cpp \
	server/thread_pool.cpp \
	common/command.cpp \
	common/line_buffer.cpp

SERVER_OBJ := $(addprefix $(BUILD_DIR)/,$(SERVER_SRCS:.cpp=.o))

CLIENT_SRCS := \
	client/main.cpp \
	client/p2p_listener.cpp \
	client/p2p_sender.cpp \
	common/command.cpp \
	common/line_buffer.cpp

CLIENT_OBJ := $(addprefix $(BUILD_DIR)/,$(CLIENT_SRCS:.cpp=.o))

INCLUDES := -I. -I./server -I./common -I./utils

$(BIN_DIR)/server: $(SERVER_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(SERVER_OBJ) -o $@ $(LDFLAGS)

$(BIN_DIR)/client: $(CLIENT_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) $(CLIENT_OBJ) -o $@ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.cpp | prepare
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

prepare:
	@mkdir -p $(BUILD_DIR)

.PHONY: all clean

all: $(BIN_DIR)/server $(BIN_DIR)/client
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
