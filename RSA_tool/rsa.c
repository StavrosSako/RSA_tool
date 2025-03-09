#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>

// Function prototypes
void rsaKeyGeneration(mpz_t n, mpz_t e, mpz_t d, int keyLength);
void generateKeyFiles(const mpz_t n, const mpz_t e, const mpz_t d, int keySize);
void generatePrime(mpz_t prime, int bits);
void readKeyFile(const char *keyFile, mpz_t n, mpz_t keyNumber, const char *dir);
void printMenu(const char *program);
void encryptFile(const char *inputFile, const char *outputFile, const char *keyFile);
void decryptFile(const char *inputFile, const char *outputFile, const char *keyFile);
void performanceTesting(const char *performanceFile, const char *plaintextFile); 
long getPeakMemoryUsage(); 

int main(int argc, char const *argv[]) {
    const char *inputFile = NULL, *outputFile = NULL, *keyFile = NULL, *performanceFile = NULL;
    int keyLength = 0; // can take values from 1024, 2048, 4096, etc.
    int generateKeys = 0, decrypt = 0, encrypt = 0, performance = 0;

    if (argc < 2) {
        printMenu(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            inputFile = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            keyFile = argv[++i];
        } else if (strcmp(argv[i], "-g") == 0 && i + 1 < argc) {
            keyLength = atoi(argv[++i]);
            generateKeys = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            decrypt = 1;
        } else if (strcmp(argv[i], "-e") == 0) {
            encrypt = 1;
        }else if(strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            performance = 1;
            performanceFile = argv[++i];
        } 
        else if (strcmp(argv[i], "-h") == 0) {
            printMenu(argv[0]);
            return 0;
        }
    }

    // Ensuring all the arguments are provided for encryption or decryption of the file.
    if ((encrypt || decrypt) && (!inputFile || !outputFile || !keyFile)) {
        printf("Error: Options -i, -o, and -k are required for encrypting or decrypting.\n");
        return 1;
    }

    if (generateKeys) {
        mpz_t n, e, d; // creating constants with the names of the keys
        mpz_inits(n, e, d, NULL); // keys == NULL
        rsaKeyGeneration(n, e, d, keyLength);
        generateKeyFiles(n, e, d, keyLength);
        mpz_clears(n, e, d, NULL);
        return 0;
    }

    if (encrypt) {
        encryptFile(inputFile, outputFile, keyFile);
    }
    if(decrypt) {
        decryptFile(inputFile, outputFile, keyFile);
    }

    if(performance) { 
        const char *inputFile = "plaintext.txt";
        performanceTesting(performanceFile, inputFile);
    }


    return 0;
}

void rsaKeyGeneration(mpz_t n, mpz_t e, mpz_t d, int keyLength) {
    mpz_t p, q, lambda_n, gcd_result;
    mpz_inits(p, q, lambda_n, gcd_result, NULL);
    int halfBits = keyLength / 2;

    generatePrime(p, halfBits);
    generatePrime(q, halfBits);

    mpz_mul(n, p, q); // n = p * q

    mpz_t p_minus_1, q_minus_1;
    mpz_inits(p_minus_1, q_minus_1, NULL);
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(lambda_n, p_minus_1, q_minus_1); // λ(n) = (p-1)(q-1)

    mpz_set_ui(e, 65537); // Common choice for e

    // Ensure gcd(e, λ(n)) = 1
    while (mpz_gcd(gcd_result, e, lambda_n), mpz_cmp_ui(gcd_result, 1) != 0) {
        mpz_add_ui(e, e, 2);
    }

    if (mpz_invert(d, e, lambda_n) == 0) {
        printf("Modular inverse doesn't exist\n");
    }

    mpz_clears(p, q, lambda_n, p_minus_1, q_minus_1, NULL);
}

void generatePrime(mpz_t prime, int bits) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL) + rand());

    do {
        mpz_urandomb(prime, state, bits);
        mpz_nextprime(prime, prime);
    } while (mpz_probab_prime_p(prime, 25) == 0);

    gmp_randclear(state);
}

void generateKeyFiles(const mpz_t n, const mpz_t e, const mpz_t d, int keySize) {
    char publicKeyFile[256], privateKeyFile[256];

    const char *keyDir = "Keys"; 
    if(mkdir(keyDir, 0777) && errno != EEXIST) { 
        perror("Error creating keys Directory!");
        exit(1); 
    }
    
    // Construct paths for public and private keys
    snprintf(publicKeyFile, sizeof(publicKeyFile), "%s/public_%d.key", keyDir, keySize);
    snprintf(privateKeyFile, sizeof(privateKeyFile), "%s/private_%d.key", keyDir, keySize);

    FILE *pubFile = fopen(publicKeyFile, "w");
    if (!pubFile) {
        perror("Error opening public key file");
        exit(1);
    }
    gmp_fprintf(pubFile, "%Zd\n%Zd\n", n, e);
    fclose(pubFile);

    FILE *privFile = fopen(privateKeyFile, "w");
    if (!privFile) {
        perror("Error opening private key file");
        exit(1);
    }
    gmp_fprintf(privFile, "%Zd\n%Zd\n", n, d);
    fclose(privFile);

    printf("Keys generated and saved to %s and %s\n", publicKeyFile, privateKeyFile);
}

void encryptFile(const char *inputFile, const char *outputFile, const char *keyFile) {
    mpz_t n, d, plaintext, ciphertext;
    mpz_inits(n, d, plaintext, ciphertext, NULL);

    const char *keyDir = "Keys"; 
    // Read the public key (n, d) from the key file
    readKeyFile(keyFile, n, d, keyDir); // Ensure this function reads the key correctly

    // Open the input file to read the plaintext
    FILE *input = fopen(inputFile, "r");
    if (!input) {
        perror("Error opening input file");
        exit(1);
    }

    // Read input file in smaller chunks
    char buffer[245];  // For a 1024-bit key, the plaintext size should be <= 245 bytes
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), input)) > 0) {
        // Null-terminate the buffer and remove the newline (if necessary)
        buffer[bytesRead] = '\0';

        // Convert buffer to a number (plaintext)
        mpz_set_ui(plaintext, 0);
        for (size_t i = 0; i < bytesRead; i++) {
            mpz_mul_ui(plaintext, plaintext, 256);  // Multiply by 256 (byte size)
            mpz_add_ui(plaintext, plaintext, (unsigned char)buffer[i]);
        }

        // Encrypt the plaintext: ciphertext = plaintext^d mod n
        mpz_powm(ciphertext, plaintext, d, n);

        // Open output file for appending the ciphertext
        FILE *output = fopen(outputFile, "a");
        if (!output) {
            perror("Error opening output file");
            fclose(input);
            exit(1);
        }

        // Write the ciphertext as a number in the output file
        mpz_out_str(output, 10, ciphertext);  // Write ciphertext as a decimal number
        fputc('\n', output);  // Add a newline for separation between chunks
        fclose(output);
    }

    fclose(input);

    // Clear variables
    mpz_clears(n, d, plaintext, ciphertext, NULL);
}


void decryptFile(const char *inputFile, const char *outputFile, const char *keyFile) {
    mpz_t n, e, ciphertext, plaintext;
    mpz_inits(n, e, ciphertext, plaintext, NULL);

    const char *keyDir = "Keys"; 
    // Read the private key (n, d) from the key file
    readKeyFile(keyFile, n, e, keyDir);  // Make sure this reads n and e (private exponent)

    // Open the input file to read the ciphertext
    FILE *input = fopen(inputFile, "r");
    if (!input) {
        perror("Error opening input file");
        exit(1);
    }

    // Open the output file to write the decrypted plaintext
    FILE *output = fopen(outputFile, "w");
    if (!output) {
        perror("Error opening output file");
        fclose(input);
        exit(1);
    }

    // Read ciphertext in chunks (assuming they were saved in chunks)
    char buffer[4096];  // Buffer for reading ciphertext
    while (fgets(buffer, sizeof(buffer), input)) {
        // Remove the newline character (if any)
        buffer[strcspn(buffer, "\n")] = '\0';

        // Convert the buffer (which is a string) into a number
        mpz_set_str(ciphertext, buffer, 10);  // Assuming ciphertext is stored in base 10

        // Decrypt: plaintext = ciphertext^e mod n
        mpz_powm(plaintext, ciphertext, e, n);

        // Convert the plaintext number back to ASCII characters
        char outputBuffer[256];  // Adjust size based on expected plaintext length
        size_t outIndex = 0;
        while (mpz_cmp_ui(plaintext, 0) > 0) {
            unsigned long byte = mpz_fdiv_q_ui(plaintext, plaintext, 256);  // Get the least significant byte
            outputBuffer[outIndex++] = (char)byte;
        }

        // Reverse the buffer to get the correct order and write to the file
        for (int i = outIndex - 1; i >= 0; i--) {
            fputc(outputBuffer[i], output);
        }
    }

    fclose(input);
    fclose(output);

    // Clear variables
    mpz_clears(n, e, ciphertext, plaintext, NULL);
}


void readKeyFile(const char *keyFile, mpz_t n, mpz_t keyNumber, const char *dir) {
    char fullPath[256];
    snprintf(fullPath, sizeof(fullPath), "%s/%s", dir, keyFile);
    FILE *file = fopen(fullPath, "r");
    if (!file) {
        perror("Error opening key file");
        exit(1);
    }
    gmp_fscanf(file, "%Zd\n%Zd\n", n, keyNumber);
    fclose(file);
}
long getPeakMemoryUsage() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    // Return the peak resident set size in kilobytes (on Linux/MacOS)
    return usage.ru_maxrss;
}

void performanceTesting(const char *performanceFile, const char *plaintextFile) {
    FILE *performaceF = fopen(performanceFile, "w"); 
    if (!performaceF) { 
        perror("Error opening performance file"); 
        return;
    }

    int keyLengths[] = {1024, 2048, 4096}; 

    for (int i = 0; i < 3; i++) {
        long baseMemory = getPeakMemoryUsage();
        int keyLen = keyLengths[i]; 
        printf("Generating keys of size %d.\n", keyLen);

        char encryptOutput[256]; 
        char decryptOutput[256]; 
        snprintf(encryptOutput, sizeof(encryptOutput), "encrypted_%d.txt", keyLen); 
        snprintf(decryptOutput, sizeof(decryptOutput), "decrypted_%d.txt", keyLen);

        // Generate keys once
        mpz_t n, e, d;
        mpz_inits(n, e, d, NULL); 
        rsaKeyGeneration(n, e, d, keyLen);
        generateKeyFiles(n, e, d, keyLen);

        // Prepare the public and private key file names
        char publicKeyFile[256], privateKeyFile[256];
        snprintf(publicKeyFile, sizeof(publicKeyFile), "public_%d.key", keyLen);
        snprintf(privateKeyFile, sizeof(privateKeyFile), "private_%d.key", keyLen);

        // Encryption performance test
        struct timeval start, end; 
        gettimeofday(&start, NULL);  // Start time
        long initialMemEncrypt = getPeakMemoryUsage(); // Memory before encryption

        printf("Encrypting with key size %d.\n", keyLen); // Debug statement
        encryptFile(plaintextFile, encryptOutput, publicKeyFile);
        
        gettimeofday(&end, NULL);  // End time
        long finalMemEncrypt = getPeakMemoryUsage() - baseMemory; // Memory after encryption

        double encryption_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
        long peakMemoryEncrypt = finalMemEncrypt - initialMemEncrypt; // Peak memory usage for encryption

        // Decryption performance test
        gettimeofday(&start, NULL);  // Start time
        long initialMemDecrypt = getPeakMemoryUsage() ; // Memory before decryption

        printf("Decrypting with key size %d.\n", keyLen); // Debug statement
        decryptFile(encryptOutput, decryptOutput, privateKeyFile);
        
        gettimeofday(&end, NULL);  // End time
        long finalMemDecrypt = getPeakMemoryUsage() - baseMemory; // Memory after decryption

        double decryption_time = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
        long peakMemoryDecrypt = finalMemDecrypt - initialMemDecrypt; // Peak memory usage for decryption

        // Write performance data
        fprintf(performaceF, "Key Length: %d bits\n", keyLen);
        fprintf(performaceF, "Encryption Time: %fs\n", encryption_time);
        fprintf(performaceF, "Peak Memory Usage (Encryption): %ld KB\n", finalMemEncrypt);
        fprintf(performaceF, "Decryption Time: %fs\n", decryption_time);
        fprintf(performaceF, "Peak Memory Usage (Decryption): %ld KB\n", finalMemDecrypt);
        fprintf(performaceF, "\n");

        // Clear GMP variables
        mpz_clears(n, e, d, NULL);
    }

    fclose(performaceF);
}





void printMenu(const char *program) {
    printf("Usage: %s [-g keySize | -e | -d] [-i inputFile] [-o outputFile] [-k keyFile]\n", program);
    printf("Options:\n");
    printf("  -g keySize    Generate RSA keys of specified size (e.g., 1024, 2048)\n");
    printf("  -e            Encrypt a file\n");
    printf("  -d            Decrypt a file\n");
    printf("  -i inputFile  Input file for encryption/decryption\n");
    printf("  -o outputFile Output file for encryption/decryption result\n");
    printf("  -k keyFile    Key file for encryption/decryption\n");
    printf("  -h            Show this help message\n");
}