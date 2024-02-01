#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#define JMP_BACK 9

//TODO ERROR CHECKS

#if defined(__LP64__)
# define ElfW(type) Elf64_ ## type
#else
# define ElfW(type) Elf32_ ## type
#endif

int is_sect_exec(char *file, ssize_t fsize, ssize_t entry, int len)
{
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	size_t phdr_num;
	ssize_t index;

	ehdr = (void *)file;
	phdr_num = ehdr->e_phnum;
	if ((ssize_t)(phdr_num * sizeof(ElfW(Phdr)) + ehdr->e_phoff) > fsize)
	{
		dprintf(2, "ERROR: Corrupted binary\n");
		return 0;
	}
	phdr = (void *)(file + ehdr->e_phoff);
	index = 0;
	if (!phdr_num)
	{
		dprintf(2, "ERROR: There is no program header\n");
		return (0);
	}
	while ((size_t)index < phdr_num)
	{
		if (!(phdr[index].p_flags & 1) || !(phdr[index].p_flags & 4))	 // PF_Read & PF_Xecute
		{
			index++;
			continue ;
		}
		if (phdr[index].p_offset < (size_t)entry &&
			phdr[index].p_offset + phdr[index].p_filesz + phdr[index].p_align >
			(size_t)entry + len)
			return 1;
		index += 1;
	}
	return 0;
}

ssize_t get_cave_size(char *file, ssize_t off, ssize_t fsize) {

	ssize_t i;

	i = 0;
	while (i + off < fsize && !file[off + i])
		i++;
	return i;
}

ssize_t find_cave(char *file, ssize_t fsize, ssize_t payload_len, ssize_t *cave_size) {

	ssize_t i;
	ssize_t tmp_size;

	tmp_size = 0;
	i = 0;
	while (i < fsize)
	{
		if (!file[i] && i % 4 == 0)
		{
			tmp_size = get_cave_size(file, i, fsize);
	
			if ((tmp_size > payload_len && i != 0) && (is_sect_exec(file, fsize, i , payload_len)))
			{
				*cave_size = tmp_size;
				return (i);
			}
			i += tmp_size;
		}
		else
			i += 1;
	}
	return 0;
}

ssize_t rewrite_entry(char *av, ssize_t cave, ElfW(Ehdr) *ehdr) {


	int fd = open(av, O_RDWR);
	read(fd, &ehdr, sizeof(ehdr));
        ElfW(Addr) og_entry = ehdr->e_entry;
	ehdr->e_entry = cave;
        lseek(fd, 0, SEEK_SET);
        write(fd, &ehdr, sizeof(ehdr));
	close(fd);
	return 0; 
}

char *open_file(char *av, ssize_t *size) {
	//easier to manipulate file
		
	struct stat fdata;
	int fd;
	char *file;

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
	close(fd);
	return (file);
}

long	get_vaddr(FILE *fd) {

	ElfW(Ehdr) ehdr;
	ElfW(Phdr) phdr;

	fseek(fd, 0, SEEK_SET);
	
	fread(&ehdr, 1, sizeof(ehdr), fd);
	int num_heads = ehdr.e_phnum;

	fseek(fd, ehdr.e_phoff, SEEK_SET); //first programm header
	
	for (int i = 0; i < num_heads; i++)
	{
		fread(&phdr, 1, sizeof(phdr), fd);
		if (phdr.p_type == PT_LOAD)
		{
			printf("Base Address: %lx\n", phdr.p_vaddr);
			break;
		}
	}
	fseek(fd, 0, SEEK_SET); 
	return phdr.p_vaddr;
}
/*
char pre payload [ ] = {
'\x50', '\x53', '\x51', '\x52', '\x56', '\x57', // push eax , ebx , ecx , edx , e s i , edi
'\xE8', '.', '.' , '.', '.', // call ‘t h e v i r u s‘ function
'\x5F' , '\x5E'	, ’ \x5A ’ , ’ \x59 ’ , ’ \x5B ’ , ’ \x58 ’ , // pop edi , e s i , edx , ecx , ebx , eax
’ \xE9 ’ , ’ . ’ , ’ . ’ , ’ . ’ , ’ . ’ // jump to the old ent ry point
};
*/

/*
unsigned char payload[] = "\xeb\x14\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x5e\xba\x0e"
"\x00\x00\x00\x0f\x05\xeb\x13\xe8\xe7\xff\xff\xff\x2e\x2e\x2e"
"\x2e\x57\x4f\x4f\x44\x59\x2e\x2e\x2e\x2e\x0a\x48\x31\xc0\x48"
"\x31\xff\x48\x31\xd2\x48\x31\xf6";
*/

char payload[] = "\xe9\xde\xad\xbe\xef";

//"\x50\x51\x52\x53\x48\xc7\xc0\x30\x31\x00\x00\x5b\x5a\x59\xff\xe0"; //push regs; jmp; pop regs

int main(int ac, char **av) {


	ElfW(Ehdr)	ehdr;
	ssize_t		cave; 
	ssize_t		fsize;
	ssize_t		csize;
	int		jmp_addr;
	char *file = open_file(av[1], &fsize);
	FILE *fd = fopen(av[1], "r+b");
	size_t payload_size = sizeof(payload);

        fread(&ehdr, 1, sizeof(ehdr), fd);
	long base = get_vaddr(fd);

	if ((cave = find_cave(file, fsize, payload_size + JMP_BACK, &csize)) == 0) {
		dprintf(2, "Cave is too small to handle payload\n");
		fclose(fd);
		exit(1);
	}

	printf("Found cave at: 0x%lx; With the size of: %d ; Payload size: %d\n", cave + base, csize, payload_size);
        fseek(fd, cave, SEEK_SET);
        //fwrite(payload, sizeof(char *), strlen(payload), fd);
	//rewrite_entry(av[1],cave,&ehdr);

//	fclose(fd);

	int f = open(av[1], O_RDWR);
	read(f, &ehdr, sizeof(ehdr));
        ElfW(Addr) og_entry = ehdr.e_entry;
	ehdr.e_entry = cave + base;
        lseek(f, 0, SEEK_SET);
        write(f, &ehdr, sizeof(ehdr));
	jmp_addr = (og_entry - (cave + 5)); // - instruction size AND payload size
	memcpy(payload + 1, &jmp_addr, sizeof(jmp_addr));
        
	fwrite(payload, sizeof(char *), strlen(payload), fd);
	fclose(fd);
	close(f);
}	
