SRC_DIR=src
INC_DIR=include
OUT_DIR=out
OBJ_DIR=object
TST_DIR=tests
DOC_DIR=docs

CC=gcc
CPPFLAGS=-I./$(INC_DIR)
CFLAGS=-Wall -Wextra

# *************************** Files **************************

FILES=sha256

SOURCE_OBJECTS=$(patsubst %, $(OUT_DIR)/$(OBJ_DIR)/%.o, $(FILES))
TEST_HEADERS=$(patsubst %, $(TST_DIR)/test_%.h, $(FILES))

EXEC=run_tests

# ************************************************************

.PHONY: all run docs clean distclean

all: $(OUT_DIR)/$(EXEC)

run: $(OUT_DIR)/$(EXEC)
	./$(OUT_DIR)/$(EXEC)

# ************************ Executable ************************

$(OUT_DIR)/$(EXEC): $(OUT_DIR)/$(OBJ_DIR)/main.o $(SOURCE_OBJECTS)
	$(CC) $^ -o $@

# *********************** Object files ***********************

$(OUT_DIR)/$(OBJ_DIR)/main.o: $(TST_DIR)/main.c $(TST_DIR)/minunit.h $(TEST_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OUT_DIR)/$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INC_DIR)/%.h
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
