/*
	@param header - a pointer to the header structure
	@return - true if the integrity is kept, false
	otherwise
	@description - checks if dex string/new line/null byte
	are present in the header
*/
bool dex_header_integrity(dex_file_t *dex_file) {
	dex_header_t *header = (dex_header_t *)dex_file->dex;
	if(memcmp(header->magic.dex, "dex", 3) != 0 || header->magic.nl != '\n' || header->magic.nb != '\0') {
		//check the magic field
		printf("[-] The DEX signature is corrupted\n");
		return false;
	} else if(memcmp(header->magic.version, DEX_VERSION_API_13, 3) != 0 && memcmp(header->magic.version, DEX_VERSION_CURRENT, 3) != 0) {
		//check the DEX version
		printf("[-] The DEX version is invalid, currently valid versions are: 035 & 0x36\n");
		return false;
	} else if(dex_file->sz != header->file_size) {
		//check file size
		printf("[-] The real and memorized file size are different\n");
		return false;
	} else if(dex_file->sz < sizeof(dex_header_t)) {
		//check file size, it must be (for sure) greater than the header
		printf("[-] The file size smaller than the DEX header size\n");
		return false;
	} else if(header->header_size != sizeof(dex_header_t)) {
		//check if the header size is equal to header->header_size
		printf("[-] The header size is invalid\n");
		return false;
	} else if(header->endian_tag != REVERSE_ENDIAN_CONSTANT && header->endian_tag != ENDIAN_CONSTANT) {
		//check the endian tag
		printf("[-] The endian tag is invalid\n");
		return false;
	} else if(header->string_ids_off >= dex_file->sz) {
		//check if string_ids_off is out of range
		printf("[-] string_ids_off is out of range\n");
		return false;
	} else if(header->type_ids_off >= dex_file->sz) {
		//check if type_ids_off is out of range
		printf("[-] type_ids_off is out of range\n");
		return false;
	} else if(header->proto_ids_off >= dex_file->sz) {
		//check if proto_ids_off is out of range
		printf("[-] proto_ids_off is out of range\n");
		return false;
	} else if(header->field_ids_off >= dex_file->sz) {
		//check if field_ids_off is out of range
		printf("[-] field_ids_off is out of range\n");
		return false;
	} else if(header->method_ids_off >= dex_file->sz) {
		//check if method_ids_off is out of range
		printf("[-] method_ids_off is out of range\n");
		return false;
	} else if(header->class_defs_off >= dex_file->sz) {
		//check if class_defs_off is out of range
		printf("[-] class_defs_off is out of range\n");
		return false;
	} else if(header->data_off >= dex_file->sz) {
		//check if data_off is out of range
		printf("[-] data_off is out of range\n");
		return false;
	} else if(calc_adler32((uint8_t *)(dex_file->dex + 12), dex_file->sz - 12) != header->checksum) {
		//check the adler32 checksum
		printf("[-] checksum field invalid, file is tampered\n");
		return false;
	} else if(header->link_size != 0 && header->link_off >= dex_file->sz) {
		//check link_off
		printf("[-] link_off is out of range\n");
		return false;
	} else if(header->map_off == 0) {
		//check map_off
		printf("[-] map_off could not be zero\n");
		return false;
	} else if(header->map_off >= dex_file->sz || header->map_off < header->data_off) {
		//check bound of map_off
		printf("[-] map_off is out of range\n");
		return false;
	} else if(header->data_size % sizeof(uint32_t) != 0) {
		//check if data_size is an even multiple of sizeof(uint32_t)
		printf("[-] data_size is not an even multiple of sizeof(uint)\n");
		return false;
	}
	return true;
}

/*
	@param file_name - the name of the DEX file to map in memory
	@param dexF - a structure used to save the pointer to the mapped file
	and its size
*/
void load_DEX(char *file_name, dex_file_t *dexF) {
	FILE *dex_file = fopen(file_name, "rb");
	if(!dex_file) {
		printf("[-] Impossible to open %s\n", file_name);
		exit(-1);
	}
	fseek(dex_file, 0, SEEK_END);
	dexF->sz = ftell(dex_file);
	fseek(dex_file, 0, SEEK_SET);
	printf("[+] Loading DEX file: %s (%d bytes)\n", file_name, dexF->sz);
	dexF->name = (char *)malloc(strlen(file_name) + 1);
	sprintf(dexF->name, "%s", file_name);
	dexF->dex = malloc(dexF->sz);
	fread(dexF->dex, 1, dexF->sz, dex_file);
	fclose(dex_file);
}

/*
	@param file_name - the name of the DEX file used to save the
	mapped memory representation; if NULL the file is not saved
	to disk
	@param dexF - a structure used to read the pointer to the mapped file,
	its name and its size
*/
void unload_DEX(char *file_name, dex_file_t *dexF) {
	if(file_name) {
		printf("[+] Saving modified file as %s\n", file_name);
		FILE *dex_file = fopen(file_name, "wb");
		fwrite(dexF->dex, 1, dexF->sz, dex_file);
		fclose(dex_file);
	}
	printf("[+] Unloading DEX file: %s (%d bytes)\n", dexF->name, dexF->sz);
	free(dexF->dex);
	free(dexF->name);
	dexF->name = NULL;
	dexF->dex = NULL;
	dexF->sz = 0;
}

/*
	@param dex_header - a pointer to the DEX header
	@param strings - an array of string_data_item_t values
*/

typedef struct string_data_item {
	uint32_t utf16_size;	//in the DEX specification it is an uleb128
	uint8_t *data;			//in the DEX specification it is an ubyte[]
} string_data_item_t;

void read_strings(dex_header_t *header, string_data_item_t **strings) {
	uint64_t base = (uint64_t)header;
	uint32_t sz = header->string_ids_size;
	uint64_t off = header->string_ids_off;
	uint32_t *string_id_items = (uint32_t *)(base + off);
	uint64_t string_data_off;
	uint8_t *curr;
	//allocate space for the string_data_item_t array
	*strings = (string_data_item_t *)calloc(sz + 1, sizeof(string_data_item_t));
	for(size_t i = 0; i < sz; i++) {
		string_data_off = string_id_items[i];
		curr = (uint8_t *)(base + string_data_off);
		(*strings)[i].utf16_size = decode_uleb128((uint8_t *)curr);
		(*strings)[i].data = decode_mutf8((uint8_t *)curr, (*strings)[i].utf16_size);
		printf("string%d: %s\n", i, (*strings)[i].data);
	}
}