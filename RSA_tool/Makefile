# Makefile for rsa_tool

# Compiler and flags
CC = gcc
CFLAGS = -I/opt/homebrew/include -L/opt/homebrew/lib -lgmp
TARGET = rsa_assign_1
SRC = rsa.c


# Build target
all: $(TARGET) plaintext.txt

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(DEPFLAGS) -o $@ $<

plaintext.txt:
	@echo "Hello Mister Ioannidis this is a test on the rsa code we wrote!" > plaintext.txt

# Clean target to remove compiled files
clean:
	rm -f $(TARGET)
	rm -rf Keys/*
	find . -type f -name "*.txt" ! -name "plaintext.txt" -exec rm -f {} +

# Run the tool with arguments
run: $(TARGET)
	@echo "Usage: ./rsa_assign_1 [options]"
	@echo "Options:"
	@echo "  -i <inputFile>        Specify input file"
	@echo "  -o <outputFile>       Specify output file"
	@echo "  -k <keyFile>          Specify key file"
	@echo "  -g <keyLength>        Generate keys of specified length"
	@echo "  -d                    Decrypt"
	@echo "  -e                    Encrypt"
	@echo "  -a <performanceFile>  Analyze performance"
	@echo "  -h                    Display this help message"

# Post-run target to execute and clean up
post-run: run
	./$(TARGET) [options] # Replace [options] with actual options
	make clean


.PHONY: all clean run post-run debug install uninstall test
