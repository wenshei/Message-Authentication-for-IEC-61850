typedef struct _mtdata {
	uint8_t* data; // in this implementation data is put linearly into this memory address
	uint8_t* hashed_data; // in this implementation hashes are put linearly into this memory address
	uint8_t* data_digest;
	uint32_t data_size;
	uint32_t data_type_size; // type of data in the unit of bytes
} mtdata_t;