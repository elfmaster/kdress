/*
 * Kernel dress v1.0
 * kunpress.c - vmlinuz decompression
 * mk_vmlinux.c - vmlinux symtab reconstruction
 * vmlinuz to vmlinux translation with symbol table reconstruction.
 * This software is part of the kernelVoodoo project by elfmaster
 * Ryan O'Neill <elfmaster@zoho.com> 2014
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <errno.h>

#define MAX_KSYMS 100000
#define MAX_SHDRS 64

typedef enum {
	TEXT = 0,
	DATA1 = 1,
	DATA2 = 3,
	DATA3 = 4
} segtype_t;

typedef enum {
	FUNC = 0,
	OBJECT = 1,
} symtype_t;
	
struct {
	char name[256];
	unsigned long addr;
      	char c;
} sysmap_entry;

typedef struct elftype_private // not the same as in elfhelper.h
{
	const char *path;
        uint8_t *mem;     /* raw memory */
        char *StringTable;
        /* Elf headers */
        ElfW(Shdr) *shdr;
        ElfW(Phdr) *phdr;
        ElfW(Ehdr) *ehdr;
        
        uint8_t **section; /* sections   */
        uint32_t size;     /* file size  */
        int mode;          /* file mode  */
        char *name;        /* file name  */
        ElfW(Addr) seg_vaddr[4];
	ElfW(Off) seg_offset[4];
        ElfW(Word) seg_filesz[4];
        ElfW(Word) seg_memsz[4];

	ElfW(Off) shdr_offset;
	ElfW(Off) shstrtab_offset;
	ElfW(Off) shstrtab_size;
	int shdr_count;
	struct {
		ElfW(Addr) min, max;
		char *name;
		int index;
	} section_ranges[MAX_SHDRS];
	struct {
		char *strtab;
		ElfW(Sym) *symtab;
	} new;
	
} elftype_t;

typedef struct {
        char *symstr;
	size_t size;
        ElfW(Addr) vaddr;
} symdata_t;

	
struct metadata {
	char *symfile;
	char *infile; // in vmlinux
	char *outfile; //out vmlinux
	size_t symtab_size;
	uint32_t ksymcount;
};

struct kallsyms
{
	char name[256];
   	char c;
   	unsigned long addr; 
   	unsigned long size;
   	symtype_t symtype;
}  kallsyms_entry[MAX_KSYMS];

unsigned long low_limit;
unsigned long high_limit;

static inline char * get_line_by_offset(const char *file, loff_t offset) __attribute__((always_inline));
static int validate_va_range(ElfW(Addr) addr)
{
        return (addr >= low_limit && addr < high_limit) ? 1 : 0;
}

static inline char * get_line_by_offset(const char *file, loff_t offset) 
{
	FILE *fd;
	char *str; 

	if ((str = malloc(256)) == NULL) {
		perror("malloc");
		exit(-1);
	}

	if ((fd = fopen(file, "r")) == NULL) {
		perror("fopen");
		exit(-1);
	}
	
	if (fseek(fd, offset, SEEK_SET) < 0) {
		perror("fseek");
		exit(-1);
	}

	if (fgets(str, 256, fd) == NULL) {
		perror("fgets");
		exit(-1);
	}
	
	fclose(fd);

	return str;
}


static size_t strtab_size = 0; // how big does the .strtab need to be for symbols?

static size_t calculate_symtab_size(struct metadata *meta)
{
	FILE *fd;
	size_t c;
	char line[256], *s;
	loff_t foff;
	unsigned long vaddr;
	char ch;
	char name[128];

	if ((fd = fopen(meta->symfile, "r")) == NULL) {
		perror("fopen");
		exit(-1);
	}
	for (c = 0; fgets(line, sizeof(line), fd) != NULL; c++) {
                sscanf(line, "%lx %c %s", &sysmap_entry.addr, &sysmap_entry.c, sysmap_entry.name);
		if (!validate_va_range(sysmap_entry.addr)) {
                        c--;
                        continue;
                }
                sscanf (line, "%lx %c %s", &kallsyms_entry[c].addr, &kallsyms_entry[c].c,
                        kallsyms_entry[c].name);
		switch(toupper(kallsyms_entry[c].c)) {
			case 'T': // text segment
				kallsyms_entry[c].symtype = FUNC; //.text function
				break;
			case 'R':
				kallsyms_entry[c].symtype = OBJECT; //.rodata object
				break;
			case 'D':
				kallsyms_entry[c].symtype = OBJECT; //.data object
				break;
		}
		strtab_size += strlen(kallsyms_entry[c].name) + 1;
		foff = ftell(fd);
		s = get_line_by_offset(meta->symfile, foff);
		sscanf(s, "%lx %c %s", &vaddr, &ch, name);
		kallsyms_entry[c].size = vaddr - sysmap_entry.addr;
	}
	
	meta->ksymcount = c;
        return c * sizeof(ElfW(Sym));

}

static inline int get_section_index_by_address(elftype_t *elf, ElfW(Addr) addr)
{
	int i;
	
	for (i = 0; i < elf->shdr_count; i++)
		if (addr >= elf->section_ranges[i].min && addr < elf->section_ranges[i].max) 
			return elf->section_ranges[i].index;
	
	return SHN_UNDEF;
}

				
/*
 * In this function we parse the program headers
 * of vmlinux. This gets kind of strange because there
 * are 4 loadable segments, 1 text, 2 data's, and 1 misc/data
 */
int parse_vmlinux(elftype_t *elf)
{
	int fd, i, hit_data = 0, misc_seg = 0;
	uint8_t *mem;
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	ElfW(Shdr) *shdr;
	struct stat st;
	char *StringTable;

	if ((fd = open(elf->path, O_RDWR)) < 0) {
		perror("open");
		return -1;
	}
	
	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return -1;
	}

	elf->mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (elf->mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	mem = elf->mem;
	
	if (memcmp(mem, "\x7f\x45\x4c\x46", 4) != 0) {
		fprintf(stderr, "%s is not an ELF file, it should be.\n", elf->path); 
		exit(-1);
	}

	ehdr = elf->ehdr = (ElfW(Ehdr) *)mem;
	phdr = elf->phdr = (ElfW(Phdr) *)(mem + ehdr->e_phoff);
	shdr = elf->shdr = (ElfW(Shdr) *)(mem + ehdr->e_shoff);

#ifdef __x86_64__
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			switch(phdr[i].p_flags) {
				case (PF_R|PF_X): /* text segment */
#if DEBUG
					printf("[DEBUG] Found text segment\n");
#endif
					elf->seg_vaddr[TEXT] = phdr[i].p_vaddr;
					elf->seg_offset[TEXT] = phdr[i].p_offset;
					elf->seg_filesz[TEXT] = phdr[i].p_filesz;
					elf->seg_memsz[TEXT] = phdr[i].p_memsz;
					break;	
				case (PF_R|PF_W): /* data segment */
#if DEBUG
					printf("[DEBUG] Found data segment\n");
#endif
					if (hit_data++ == 0) {
						elf->seg_vaddr[DATA1] = phdr[i].p_vaddr;
						elf->seg_offset[DATA1] = phdr[i].p_offset;
						elf->seg_filesz[DATA1] = phdr[i].p_filesz;
						elf->seg_memsz[DATA1] = phdr[i].p_memsz;
					} else {
			                        elf->seg_vaddr[DATA2] = phdr[i].p_vaddr;
                                                elf->seg_offset[DATA2] = phdr[i].p_offset;
                                                elf->seg_filesz[DATA2] = phdr[i].p_filesz;
                                                elf->seg_memsz[DATA2] = phdr[i].p_memsz;
					}
					break;
				case (PF_R|PF_W|PF_X): 
#if DEBUG
					printf("[DEBUG] Found RWE segment\n");
#endif
					hit_data++;
					misc_seg++;
					elf->seg_vaddr[DATA3] = phdr[i].p_vaddr;
					elf->seg_offset[DATA3] = phdr[i].p_offset;
					elf->seg_filesz[DATA3] = phdr[i].p_filesz;
					elf->seg_memsz[DATA3] = phdr[i].p_memsz;
					break;
			}
		}
	}
#else
	/*
	 * The phdr's are laid out a bit differently on 32bit linux
	 */
#if DEBUG
	printf("[DEBUG] 32bit vmlinux parsing code\n");
#endif 
        for (i = 0; i < ehdr->e_phnum; i++) {
                if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R|PF_X)) {
			elf->seg_vaddr[TEXT] = phdr[i].p_vaddr;
			elf->seg_offset[TEXT] = phdr[i].p_offset;
			elf->seg_filesz[TEXT] = phdr[i].p_filesz;
			elf->seg_memsz[TEXT] = phdr[i].p_memsz;
			
			elf->seg_vaddr[DATA1] = phdr[i + 1].p_vaddr;
                        elf->seg_offset[DATA1] = phdr[i + 1].p_offset;
                        elf->seg_filesz[DATA1] = phdr[i + 1].p_filesz;
                        elf->seg_memsz[DATA1] = phdr[i + 1].p_memsz;
			break;
		}
	}
#endif

	
	/*
	 * Extract other info we need 
	 */
		
	elf->shdr_count = ehdr->e_shnum;
	elf->shdr_offset = ehdr->e_shoff;
	StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset];
	for (i = 0; i < ehdr->e_shnum; i++) {
		if (!strcmp(&StringTable[shdr[i].sh_name], ".shstrtab")) {
			elf->shstrtab_offset = shdr[i].sh_offset;
			elf->shstrtab_size = shdr[i].sh_size;
			break;
		}
	}
	
	/*
	 * get address ranges of individual sections
	 */
	for (i = 0; i < ehdr->e_shnum; i++) {
		elf->section_ranges[i].index = i;
		elf->section_ranges[i].name = strdup(&StringTable[shdr[i].sh_name]);	 
		elf->section_ranges[i].min = shdr[i].sh_addr;
		elf->section_ranges[i].max = shdr[i].sh_addr + shdr[i].sh_size;
		
	}

	return 0;
}

int create_new_binary(elftype_t *elf, struct metadata *meta)
{
	int fd;
	size_t b;
	ElfW(Shdr) shdr[2];

	if ((fd = open(meta->outfile, O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
		perror("open");
		return -1;
	}

	/*
	 * Write out first part of vmlinux (all of it actually, up until where shdrs start)
	 */
#if DEBUG
	printf("[DEBUG] writing first %u bytes of original vmlinux into new\n", elf->shdr_offset);
#endif
	int i;
	
	/*
	 * Adjust new ELF file header, namely the e_shoff
	 */
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)elf->mem;
	ehdr->e_shoff += meta->symtab_size;
	ehdr->e_shoff += strtab_size;
	ehdr->e_shnum += 2;

	/*
	 * Write out vmlinux up until where the shdr's originally started
	 */
	if ((b = write(fd, elf->mem, elf->shdr_offset)) < 0) {
		perror("write");
		return -1;
	}
	
	/*
	 * write symtab  
	 */
	ElfW(Off) new_e_shoff;
	
	if ((b = write(fd, elf->new.symtab, meta->symtab_size)) < 0) {
		perror("write");
		return -1;
	}
	
	/* write out strtab here
 	 */
	loff_t soff = elf->shdr_offset + meta->symtab_size;

	if ((b = write(fd, elf->new.strtab, strtab_size)) < 0) {
		perror("write");
		return -1;
	}	

	
	
	/*
	 * write section headers
	 */
	if ((b = write(fd, &elf->mem[elf->shdr_offset], elf->shdr_count * sizeof(ElfW(Shdr)))) < 0) {
		perror("write");
		return -1;
	}
	
	
	/*
	 * Add 2 new section headers '.symtab' and '.strtab'
	 */
	shdr[0].sh_name = 0;
	shdr[0].sh_type = SHT_SYMTAB;
	shdr[0].sh_link = elf->shdr_count + 1;
	shdr[0].sh_addr = 0;
	shdr[0].sh_offset = elf->shdr_offset; 
	shdr[0].sh_size = meta->symtab_size;
	shdr[0].sh_entsize = sizeof(ElfW(Sym));
	shdr[0].sh_flags = 0;
	shdr[1].sh_name = 0;
	shdr[1].sh_type = SHT_STRTAB;
	shdr[1].sh_link = 0;
	shdr[1].sh_addr = 0;
	shdr[1].sh_offset = soff; //shdr_offset +  + sizeof(ElfW(Sym));
	shdr[1].sh_size = strtab_size;
	shdr[1].sh_entsize = 0;
	shdr[1].sh_flags = 0;

	loff_t offset = elf->shdr_offset + (elf->shdr_count * sizeof(ElfW(Shdr)));
	if ((b = write(fd, shdr, sizeof(ElfW(Shdr)) * 2)) < 0) {
		perror("write");
		return -1;
	}
	
	
	/* 
	 * Write out shdrs
	 */
	close(fd);
}

int main(int argc, char **argv)
{
	struct metadata meta;
	elftype_t elf;
	int i;
	char *strtab;
	size_t offset;
	int symtype;
	uint32_t st_offset;
	ElfW(Sym) *symtab;
	char c;

	if (argc < 4) {
		printf("%s <vmlinux_input> <vmlinux_output> <system.map>\n", argv[0]);
		exit(0);
	}
	
	meta.infile = strdup(argv[1]); // vmlinux
	meta.outfile = strdup(argv[2]);
	meta.symfile = strdup(argv[3]);	
	
	elf.path = strdup(meta.infile);

	if (access(meta.symfile, R_OK) < 0) {
                fprintf(stderr, "[!] Unable to read file %s: %s\n", meta.symfile, strerror(errno));
                exit(-1);
	}
	
	parse_vmlinux(&elf);
	low_limit = elf.seg_vaddr[TEXT];
#ifdef __x86_64__
	high_limit = elf.seg_vaddr[DATA3];
#else
	high_limit = elf.seg_vaddr[DATA1];
#endif
	
#if DEBUG
	printf("high_limit: %lx low_limit: %lx\n", high_limit, low_limit);
#endif
	meta.symtab_size = calculate_symtab_size(&meta);

#if DEBUG
	printf("Symbol table size: %lx bytes\n", meta.symtab_size);
#endif

	/*
	 * Allocate room for string table
	 */
	if ((strtab = (char *)malloc(strtab_size)) == NULL) {
		perror("malloc");
		exit(-1);
	}

	/*
	 * Create string table '.strtab' for symtab.
 	 */
	for (offset = 0, i = 0; i < meta.ksymcount; i++) {
		strcpy(&strtab[offset], kallsyms_entry[i].name);
		offset += strlen(kallsyms_entry[i].name) + 1;
	}

	/*
	 * Add the .symtab section
	 */
	if ((symtab = (ElfW(Sym) *)malloc(sizeof(ElfW(Sym)) * meta.ksymcount)) == NULL) {
		perror("malloc");
		exit(-1);
	}
	 
	for (st_offset = 0, i = 0; i < meta.ksymcount; i++) {
		symtype = kallsyms_entry[i].symtype == FUNC ? STT_FUNC : STT_OBJECT;
		symtab[i].st_info = (((STB_GLOBAL) << 4) + ((symtype) & 0x0f));
		symtab[i].st_value = kallsyms_entry[i].addr;
		symtab[i].st_other = 0;
		symtab[i].st_shndx = get_section_index_by_address(&elf, symtab[i].st_value);
		symtab[i].st_name = st_offset;
		symtab[i].st_size = kallsyms_entry[i].size;
		strcpy(&strtab[st_offset], kallsyms_entry[i].name);
		st_offset += strlen(kallsyms_entry[i].name) + 1;
	}
	
	elf.new.symtab = symtab;
	elf.new.strtab = strtab;
	
	create_new_binary(&elf, &meta);
	
	printf("[+] vmlinux has been successfully instrumented with a complete ELF symbol table.\n");
	
	exit(0);	
		
}


