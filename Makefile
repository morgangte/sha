SRC_DIR=src
INC_DIR=include
OUT_DIR=out
OBJ_DIR=object
DOC_DIR=docs

CC=gcc
CPPFLAGS=-I./$(INC_DIR)
CFLAGS=-Wall -Wextra

EXEC=test

.PHONY: all run docs clean distclean

all: $(OUT_DIR)/$(EXEC)

run: $(OUT_DIR)/$(EXEC)
	./$(OUT_DIR)/$(EXEC)

# ************************ Executable ************************

$(OUT_DIR)/$(EXEC): $(OUT_DIR)/$(OBJ_DIR)/test.o $(OUT_DIR)/$(OBJ_DIR)/sha256.o
	$(CC) $^ -o $@

# *********************** Object files ***********************

$(OUT_DIR)/$(OBJ_DIR)/sha256.o: $(SRC_DIR)/sha256.c $(INC_DIR)/sha256.h
$(OUT_DIR)/$(OBJ_DIR)/test.o: $(SRC_DIR)/test.c $(INC_DIR)/sha256.h

$(OUT_DIR)/%.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# *************************** Docs ***************************

docs:
	doxygen Doxyfile

# ************************* Cleaning *************************

clean:
	rm -rf $(OUT_DIR)/$(OBJ_DIR)/*.o

distclean: clean
	rm -rf $(OUT_DIR)/$(EXEC)
	rm -rf $(DOC_DIR)/html
