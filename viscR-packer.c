#define _GNU_SOURCE
#include <zstd.h>
#include <unistd.h>
#include <elf.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include "aes.h"
#include <stdbool.h>
#include <sys/random.h>
#define KEYSIZE 32
#define IVSIZE  16

#if defined(__LP64__)
# define ElfW(type) Elf64_ ## type
#else
# define ElfW(type) Elf32_ ## type
#endif

void print_hex(unsigned char *Data, size_t size) {
    printf("unsigned char data[] = {");
    for (int i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n\t");
        if (i < size - 1)
            printf("0x%0.2X ", Data[i]);
        else
            printf("0x%0.2X ", Data[i]);
    }
    printf("};\n");
}

int split(char *str, char **str_arr) {
    int i = 1;
    str_arr[i] = strtok(str, " ");
    while (str_arr[i] != NULL)
        str_arr[++i] = strtok(NULL, " ");
    return i;
}

unsigned char *buff_padding(unsigned char *input, size_t input_size, size_t *output_size) {
    size_t padding_size = 16 - (input_size % 16);
    unsigned char *padded_buff = malloc(input_size + padding_size);
    if (!padded_buff) {
        return NULL;
    }
    
    memcpy(padded_buff, input, input_size);
    memset(padded_buff + input_size, padding_size, padding_size);
    *output_size = input_size + padding_size;
    
    return padded_buff;
}

unsigned char *compress_blob(unsigned char *file, ssize_t size, ssize_t *compressed_size) {
    ssize_t max_size = ZSTD_compressBound(size);
    unsigned char *compressed = malloc(max_size);
    if (!compressed) return NULL;

    *compressed_size = ZSTD_compress(compressed, max_size, file, size, 20);
    return compressed;
}

char *open_file(char *av, ssize_t *size) {
    struct stat fdata;
    int fd;
    char *file;

    if ((fd = open(av, O_RDONLY)) == -1) {
        perror("open: ");
        return NULL;
    }
    if (fstat(fd, &fdata) == -1) {
        close(fd);
        perror("fstat: ");
        return NULL;
    }

    *size = fdata.st_size;
    
    file = mmap(0, (size_t)*size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED) {
        close(fd);
        perror("mmap: ");
        return NULL;
    }
    close(fd);
    return file;
}

int add_section(char *filename, unsigned char *data, size_t data_size, unsigned char *key, unsigned char *iv) {
    int fd;
    char *mem;
    struct stat st;
    char new_filename[256];
    char *section_name = ".note.gnu.metadata";
    ssize_t full_size = data_size + KEYSIZE + IVSIZE;
    
    if ((fd = open("./stub", O_RDONLY)) < 0) {
        perror("stub open");
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    
    mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED) {
        close(fd);
        return -1;
    }
    
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)mem;
    ElfW(Shdr) *shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];
    ElfW(Shdr) *shstrtab = &shdr[ehdr->e_shstrndx];
    char *shstrtab_data = &mem[shstrtab->sh_offset];
    
    size_t new_section_offset = st.st_size;
    size_t new_shstrtab_size = shstrtab->sh_size + strlen(section_name) + 1;
    size_t new_section_name_offset = shstrtab->sh_size;
    
    snprintf(new_filename, sizeof(new_filename), "./%s_protected", filename);
    int out_fd = open(new_filename, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (out_fd < 0) {
        munmap(mem, st.st_size);
        close(fd);
        return -1;
    }
    
    write(out_fd, mem, st.st_size);

    ElfW(Shdr) new_section = {
        .sh_name = new_section_name_offset,
        .sh_type = SHT_PROGBITS,
        .sh_flags = SHF_ALLOC,
        .sh_addr = 0,
        .sh_offset = new_section_offset,
        .sh_size = full_size,
        .sh_link = 0,
        .sh_info = 1337,
        .sh_addralign = 16,
        .sh_entsize = 0
    };
    
    char *new_shstrtab = calloc(new_shstrtab_size, 1);
    if (!new_shstrtab) {
        munmap(mem, st.st_size);
        close(fd);
        close(out_fd);
        return -1;
    }
    
    memcpy(new_shstrtab, shstrtab_data, shstrtab->sh_size);
    memcpy(new_shstrtab + new_section_name_offset, section_name, strlen(section_name) + 1);
    shstrtab->sh_size = new_shstrtab_size;
    
    unsigned char *full_data = malloc(full_size);
    if (!full_data) {
        free(new_shstrtab);
        munmap(mem, st.st_size);
        close(fd);
        close(out_fd);
        return -1;
    }
    
    memcpy(full_data, key, KEYSIZE);
    memcpy(full_data + KEYSIZE, iv, IVSIZE);
    memcpy(full_data + KEYSIZE + IVSIZE, data, data_size);
    
    lseek(out_fd, new_section_offset, SEEK_SET);
    write(out_fd, full_data, full_size);
    
    lseek(out_fd, shstrtab->sh_offset, SEEK_SET);
    write(out_fd, new_shstrtab, new_shstrtab_size);
    
    ehdr->e_shnum++;
    ehdr->e_shoff = new_section_offset + full_size;
    
    lseek(out_fd, ehdr->e_shoff, SEEK_SET);
    write(out_fd, shdr, (ehdr->e_shnum - 1) * sizeof(ElfW(Shdr)));
    write(out_fd, &new_section, sizeof(ElfW(Shdr)));
    
    lseek(out_fd, 0, SEEK_SET);
    write(out_fd, ehdr, sizeof(ElfW(Ehdr)));
    
    free(full_data);
    free(new_shstrtab);
    munmap(mem, st.st_size);
    close(fd);
    close(out_fd);
    
    return 0;
}

bool is_elf(const char *file) {
    unsigned char magic[4];
    int fd = open(file, O_RDONLY);
    if (fd == -1) {
        return false;
    }
    
    if (read(fd, magic, 4) != 4) {
        close(fd);
        return false;
    }
    
    close(fd);
    return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F';
}

int main(int ac, char **av, char **env) {
    struct AES_ctx ctx;
    ssize_t size;
    char *file;
    int memfd;
    unsigned char key[KEYSIZE];
    unsigned char iv[IVSIZE];
    unsigned char iv_copy[IVSIZE];
    ssize_t compressed_size;
    unsigned char *compressed;
    char *args[32] = {NULL,};

    if (ac == 1) {
        printf("%s <binary to pack>\n", av[0]);
        return 1;
    }

    if (!is_elf(av[1])) {
        printf("Error: %s is not an ELF file\n", av[1]);
        return 1;
    }
    
    getrandom(key, KEYSIZE, 0);
    getrandom(iv, IVSIZE, 0);

    print_hex(key, KEYSIZE);
    print_hex(iv, IVSIZE);

    AES_init_ctx_iv(&ctx, key, iv);
    
    file = open_file(av[1], &size);
    if (!file) return 1;

    compressed = compress_blob(file, size, &compressed_size);
    if (!compressed) {
        munmap(file, size);
        return 1;
    }

    memcpy(iv_copy, ctx.Iv, 16);

    size_t padded_size;
    unsigned char *padded_buff = buff_padding(compressed, compressed_size, &padded_size);
    if (!padded_buff) {
        free(compressed);
        munmap(file, size);
        return 1;
    }

    AES_CBC_encrypt_buffer(&ctx, padded_buff, padded_size);


    printf("compressed at 20 level; size: %d\n", compressed_size);    


    add_section(av[1], padded_buff, padded_size, key, iv);

    AES_ctx_set_iv(&ctx, iv_copy);
    
    free(compressed);
    free(padded_buff);
    munmap(file, size);
    
    return 0;
}
