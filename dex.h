typedef struct dex_magic {
	char dex[3];
	char nl;
	char version[3];
	char nb;
} dex_magic_t;

typedef struct dex_header {
	dex_magic_t magic;
	uint32_t checksum;
	uint8_t signature[20];
	uint32_t file_size;
    uint32_t header_size;
    uint32_t endian_tag;

    uint32_t link_size;
    uint32_t link_off;

    uint32_t map_off;

    uint32_t string_ids_size;
    uint32_t string_ids_off;

    uint32_t type_ids_size;
    uint32_t type_ids_off;

    uint32_t proto_ids_size;
    uint32_t proto_ids_off;

    uint32_t field_ids_size;
    uint32_t field_ids_off;

    uint32_t method_ids_size;
    uint32_t method_ids_off;

    uint32_t class_defs_size;
    uint32_t class_defs_off;
    
    uint32_t data_size;
    uint32_t data_off;
} dex_header_t;

typedef struct dex_file {
	void *dex;
	char *name;
	uint32_t sz;
} dex_file_t;

#define DEX_VERSION_API_13	"035"
#define DEX_VERSION_CURRENT "036"

#define ENDIAN_CONSTANT 0x12345678
#define REVERSE_ENDIAN_CONSTANT 0x78563412

enum access_flags {
	ACC_PUBLIC = 0x1,
	ACC_PRIVATE = 0x2,
	ACC_PROTECTED = 0x3,
	ACC_STATIC = 0x8,
	ACC_FINAL = 0x10,
	ACC_SYNCHRONIZED = 0x20,
	ACC_VOLATILE = 0x40,
	ACC_BRIDGE = 0x40,
	ACC_TRANSIENT = 0x80,
	ACC_VARARGS = 0x80,
	ACC_NATIVE = 0x100,
	ACC_INTERFACE = 0x200,
	ACC_ABSTRACT = 0x400,
	ACC_STRICT = 0x800,
	ACC_SYNTHETIC = 0x1000,
	ACC_ANNOTATION = 0x2000,
	ACC_ENUM = 0x4000,
	ACC_CONSTRUCTOR = 0x10000,
	ACC_DECLARED_SYNCHRONIZED = 0x20000
};

#define NO_INDEX -1