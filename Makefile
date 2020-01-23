all:
	gcc -O2 build_ksyms.c -o build_ksyms
	gcc -O2 kunpress.c -o kunpress
