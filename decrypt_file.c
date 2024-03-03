#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"

#define BLOCK_SIZE 16
#define AES_KEY_LENGTH 32
#define PASS_LENGTH 4 

uint8_t key[] = { 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x6B, 0x65, 0x79, 0x61, 0x65, 0x73, 0x63, 0x79, 0x70,
                  0x68, 0x65, 0x72, 0x6B, 0x75, 0x74, 0x78, 0x61, 0x62, 0x61, 0x6E, 0x6B, 0x00, 0x00, 0x00, 0x00 };

uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };


int main(int argc, char *argv[])
{
	struct AES_ctx ctx;
	uint8_t enc_text[BLOCK_SIZE];
    	uint8_t passwd[PASS_LENGTH + 1];
	FILE *fd_in, *fd_out;
 	uint32_t total_bytes = 0;
    	uint64_t size;
	uint8_t padding;
    	uint32_t read_bytes;
	
	if(argc != 3)
	{
		fprintf(stderr, "Usage: %s source_file dest_file\n", argv[0]);
		return(0);
	}

	printf("Insert decryption password: ");
	if( fgets (passwd, PASS_LENGTH + 1, stdin) == NULL ) 
	{
		fprintf(stderr, "Error reading the decryption password.\n", argv[0]);
                return(0);      
   	}

    	memcpy(&key[AES_KEY_LENGTH - PASS_LENGTH], passwd, PASS_LENGTH);
	AES_init_ctx_iv(&ctx, key, iv);
	
	if((fd_in = fopen(argv[1],"r")) == 0)
	{
		fprintf(stderr, "Error opening input file %s\n", argv[1]);
		return(0);
	}

	if((fd_out = fopen(argv[2],"w+")) == 0)
	{
		fprintf(stderr, "Error opening output file %s\n", argv[2]);
		return(0);
	}

    	fseek(fd_in, 0, SEEK_END);
   	size = ftell(fd_in);
    	fseek(fd_in, 0, SEEK_SET);

	while((read_bytes = fread(enc_text, 1, BLOCK_SIZE, fd_in)) > 0)
	{
 		//memset(enc_text, 0, BLOCK_SIZE);
        	total_bytes += read_bytes;
		AES_CBC_decrypt_buffer(&ctx, enc_text, BLOCK_SIZE);
		
		if(total_bytes == size)
		    fwrite(enc_text, 1, BLOCK_SIZE - enc_text[BLOCK_SIZE - 1], fd_out);
		else if (total_bytes > BLOCK_SIZE)
		    fwrite(enc_text, 1, BLOCK_SIZE, fd_out);
	}

	fclose(fd_in);
	fclose(fd_out);
}
