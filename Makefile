SRC_DIR=src
INC_DIR=include
DOC_DIR=docs

CC=gcc
CPPFLAGS=-I./$(INC_DIR)
CFLAGS=-Wall -Wextra

EXEC=test

.PHONY: all docs clean distclean

all: $(EXEC)

# ************************ Executable ************************

$(EXEC): $(SRC_DIR)/test.o $(SRC_DIR)/sha256.o
	$(CC) $^ -o $@

# *********************** Object files ***********************

$(SRC_DIR)/sha256.o: $(SRC_DIR)/sha256.c $(INC_DIR)/sha256.h
$(SRC_DIR)/test.o: $(SRC_DIR)/test.c $(INC_DIR)/sha256.h

$(SRC_DIR)/%.o: 
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# *************************** Docs ***************************

docs:
	doxygen Doxyfile

# ************************* Cleaning *************************

clean:
	rm -rf $(SRC_DIR)/*.o

distclean: clean
	rm -rf $(EXEC)
	rm -rf $(HEADER_ONLY_DIR)
	rm -rf $(DOC_DIR)/html
