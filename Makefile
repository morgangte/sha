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

FILES=sha1 sha256

SOURCE_OBJECTS=$(patsubst %, $(OUT_DIR)/$(OBJ_DIR)/%.o, $(FILES))
TEST_HEADERS=$(patsubst %, $(TST_DIR)/test_%.h, $(FILES))

EXEC=run_tests

# ************************************************************

.PHONY: all run docs clean distclean

all: $(OUT_DIR)/$(EXEC)

run: $(OUT_DIR)/$(EXEC)
	./$(OUT_DIR)/$(EXEC)

# ************************ Executable ************************

$(OUT_DIR)/$(EXEC): $(OUT_DIR)/$(OBJ_DIR)/main.o $(OUT_DIR)/$(OBJ_DIR)/sha.o $(SOURCE_OBJECTS)
	$(CC) $^ -o $@

# *********************** Object files ***********************

$(OUT_DIR)/$(OBJ_DIR)/main.o: $(TST_DIR)/main.c $(TST_DIR)/minunit.h $(TEST_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OUT_DIR)/$(OBJ_DIR)/sha.o: $(SRC_DIR)/sha.c $(INC_DIR)/sha.h 
$(OUT_DIR)/$(OBJ_DIR)/sha1.o: $(SRC_DIR)/sha1.c $(INC_DIR)/sha1.h $(INC_DIR)/sha.h 
$(OUT_DIR)/$(OBJ_DIR)/sha256.o: $(SRC_DIR)/sha256.c $(INC_DIR)/sha256.h $(INC_DIR)/sha.h 

$(OUT_DIR)/$(OBJ_DIR)/%.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# *************************** Docs ***************************

docs:
	doxygen Doxyfile

# ************************* Cleaning *************************

clean:
	rm -rf $(OUT_DIR)/$(OBJ_DIR)/*.o

distclean: clean
	rm -rf $(OUT_DIR)/$(EXEC)
	rm -rf $(DOC_DIR)
