/* kunpress (C) innosecc.com 2009
 * This tool decompresses bzImage (or vmlinuz) just like the boot loader does
 * and creates an output file similar to vmlinux, except that it has no ELF headers
 * <ryan@innosecc.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <stdint.h>

#define TMP "/tmp/.vmlinux_xyz"

void exec_string(char *str, ...)
{
        char string[255];
        va_list va;

        va_start (va, str);
        vsnprintf (string, 255, str, va);
        va_end (va);


        system(string);
}


int main(int argc, char **argv)
{

	uint8_t *p, *mem;
	int fd, out;
	struct stat st;
	int i;
        int offset = -1;

	if (argc < 3)
	{
		printf("Usage: %s <bzimage> <outfile>\n", argv[0]);
		exit(-1);
	}

	if ((fd = open(argv[1], O_RDONLY)) < 0)
	{
		printf("Could not open %s \n", argv[1]);
		perror("open");
		exit(-1);
	}

	if (fstat(fd, &st) < 0)
	{
		perror("fstat");
		exit(-1);
	}
	
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED)
	{
		perror("mmap");
		exit(-1);
	}

	for (p = mem, i = 0; i < st.st_size; i++)
	{
		if (p[i] == 0x1f && p[i + 1] == 0x8b && p[i + 2] == 0x08)
		{
			printf("Offset %d\n", i);
			offset = i;
			break;
		}
	}
	if (offset == -1)
	{
		printf("Could not find gzip magic within target kernel image: %s\n", argv[1]);
		exit(0);
	}
	

        if ((out = open(TMP, O_CREAT | O_TRUNC | O_WRONLY, st.st_mode)) == -1)
	{
		perror("open outfile");
		exit(-1);
	}

	write(out, &p[offset], st.st_size - offset);
	close(out);

	exec_string("zcat -q %s > %s", TMP, argv[2]);
	chmod(argv[2], 0777);
	exec_string("rm -f %s", TMP);
	
	printf("\n[+] vmlinux has been successfully extracted\n");  
	
 	close(fd);
	
	if ((fd = open(argv[2], O_RDONLY)) < 0)
        {
                printf("Could not open %s \n", argv[1]);
                perror("open");
                exit(-1);
        }
	
	
	exit(0);
}
