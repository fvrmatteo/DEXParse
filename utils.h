/*
	Utility functions:
	- uleb128/uleb128/sleb128 encode & decode functions;
	- adler32 calculator;
	- MUTF-8 strings encode & decode functions;
*/

/*
	@param uleb128 - a pointer to an array of byte
	representing the number
	@return - an uint32_t representation of the
	decoded number
*/
uint32_t decode_uleb128(uint8_t *uleb128) {
	uint32_t num = 0, shift = 0;
	do {
		num |= ((*uleb128 & 0x7f) << shift);
		shift += 7;
	} while(*uleb128++ & 0x80);
	return num;
}

/*
	@param uleb128p1 - a pointer to an array of byte
	representing the number
	@return - an uint32_t representation of the
	decoded number
*/
uint32_t decode_uleb128p1(uint8_t *uleb128p1) {
	return decode_uleb128(uleb128p1) - 1;
}

/*
	@param sleb128 - a pointer to an array of byte
	representing the number
	@return - an int32_t representation of the
	decoded number
*/
int32_t decode_sleb128(uint8_t *sleb128) {
	int32_t num = 0, shift = 0, size = 0;
	do {
		num |= ((*sleb128 & 0x7f) << shift);
		shift += 7;
		size += 8;
	} while(*sleb128++ & 0x80);
	if((shift < size) && (*(--sleb128) & 0x40)) {
		num |= - (1 << shift);
	}
	return num;
}

/*
	@param stream - a pointer to an array of bytes representing
	the data stream of which we need to calculate Adler32
	@param len - the length of the data stream in bytes
*/
const int MOD_ADLER = 65521;
uint32_t calc_adler32(uint8_t *stream, uint32_t len) {
	uint32_t a = 1, b = 0, i;
	for(i = 0; i < len; i++) {
		a = (a + stream[i]) % MOD_ADLER;
		b = (b + a) % MOD_ADLER;
	}
	return (b << 16) | a;
}

/*
	@param stream - a pointer to an array of bytes representing
	the encoded MUTF-8 string
	@param mutf8_sz - the size of the mutf8 encoded string
	@return - a pointer to the decoded string

	@information - http://grepcode.com/file/repository.grepcode.com/java/ext/com.google.android/android/4.3_r1/com/android/dx/util/Mutf8.java
*/
char *decode_mutf8(uint8_t *stream, uint32_t mutf8_sz) {
	//I allocate the same space needed for MUTF-8
	char *decoded = calloc(mutf8_sz, sizeof(char));
	uint32_t sz = 0;
	char a;
	/*while(true) {
		a = (char)(*stream++ & 0xff);
		if(a == 0) break;
		decoded[sz] = a;
		if(a < 0x0080) {
			sz++;
		} else if((a & 0xe0) == 0xc0) {
			int b = *stream++ & 0xff;
			if((b & 0xc0) != 0x80) {
				printf("[-] Bad second byte\n");
				return decoded;
			}
			decoded[sz++] = (char)(((a & 0x1f) << 6) | (b & 0x3f));
		} else if((a & 0xf0) == 0xe0) {
			int b = *stream++ & 0xff;
			int c = *stream++ & 0xff;
			if(((b & 0xc0) != 0x80) || ((c & 0xc0) != 0x80)) {
				printf("[-] Bad second or third bytes\n");
				return decoded;
			}
			decoded[sz++] = (char)(((a & 0x0f) << 12) | ((b & 0x3f) << 6) | (c & 0x3f));
		} else {
			printf("[-] Bad byte\n");
			return decoded;
		}
	}*/
	//Resizing the allocated space because the used one maybe be less
	decoded = realloc(decoded, sz);
	return decoded;
}