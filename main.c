#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "dex.h"
#include "utils.h"
#include "infor.h"

int main(int argc, char **argv) {
	//check the presence of the input file
	if(argc < 2) {
		printf("Usage: %s <dex_file>\n", argv[0]);
		return -1;
	}
	//open the DEX file
	dex_file_t dexFile;
	load_DEX(argv[1], &dexFile);
	//check for header corruption
	if(!dex_header_integrity(&dexFile)) {
		printf("[!] The DEX file is corrupted\n");
		return -1;
	}
	//read strings
	string_data_item_t *strings;
	read_strings((dex_header_t *)dexFile.dex, &strings);
	//unload the DEX file
	unload_DEX(NULL, &dexFile);
	return 0;
}