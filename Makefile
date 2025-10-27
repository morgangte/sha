SRC_DIR=src
INC_DIR=include

CC=gcc
CPPFLAGS=-I./$(INC_DIR)
CFLAGS=-Wall -Wextra

EXEC=test

.PHONY: all clean distclean

all: $(EXEC)

$(EXEC): $(SRC_DIR)/test.o $(SRC_DIR)/sha256.o
	$(CC) $^ -o $@

$(SRC_DIR)/sha256.o: $(SRC_DIR)/sha256.c $(INC_DIR)/sha256.h
$(SRC_DIR)/test.o: $(SRC_DIR)/test.c $(INC_DIR)/sha256.h

$(SRC_DIR)/%.o: 
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(SRC_DIR)/*.o

distclean: clean
	rm -rf $(EXEC)
