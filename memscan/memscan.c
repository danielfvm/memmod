#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef enum {
	MATCH,
	INSIDE,
} ScanMode;

uint8_t memread(int fd, int64_t address, uint8_t* bytes, size_t size) {
	lseek(fd, address, SEEK_SET);

	if (!read(fd, bytes, size)) {
		free(bytes);
		return 0;
	}

	lseek(fd, 0, SEEK_SET);

	return 1;
}

typedef union convert {
	int64_t number;
	uint8_t bytes[8];
} convert;

int64_t* memscan(
	int fd, ScanMode type, int64_t start, int64_t end, 
	const uint8_t* arg1, const uint8_t* arg2, size_t argsize, 
	int64_t chunksize,
	size_t* count,
	uint8_t** data
) {
	uint8_t* buffer = (uint8_t*) malloc(chunksize);
	int64_t* addresses = (int64_t*) malloc(chunksize * sizeof(int64_t));

	*data = (uint8_t*) malloc(chunksize * argsize);

	int _count = 0;

	convert top, bottom, conv;

	if (type == INSIDE) {
		memset(bottom.bytes, 0, 8);
		memcpy(bottom.bytes, arg1, argsize);
		memset(top.bytes, 0, 8);
		memcpy(top.bytes, arg2, argsize);
	}

	for (int64_t adr = start; adr < end; adr += chunksize - argsize + 1) {
		int64_t size = min(chunksize, end-adr);
		memread(fd, adr, buffer, size);

		switch (type) {
		case MATCH:
			for (int i = 0; i < size - argsize; ++ i) {
				if (memcmp(buffer + i, arg1, argsize) == 0) {
					addresses[*count + _count] = adr + i;
					memcpy(*data + (*count + _count) * argsize, buffer + i, argsize);

					_count ++;

					if (_count >= chunksize) {
						*count += _count;
						addresses = (int64_t*) realloc(addresses, (*count + chunksize) * sizeof(int64_t));
						*data = (uint8_t*) realloc(*data, (*count + chunksize) * argsize);
						_count = 0;
						i += argsize-1;
					}
				}
			}
			break;
		case INSIDE: 
			for (int i = 0; i < size - argsize; ++ i) {
				memset(conv.bytes, 0, 8);
				memcpy(conv.bytes, buffer + i, argsize);
				if (bottom.number <= conv.number && conv.number < top.number) {
					addresses[*count + _count] = adr + i;
					memcpy(*data + (*count + _count) * argsize, buffer + i, argsize);

					_count ++;

					if (_count >= chunksize) {
						*count += _count;
						addresses = (int64_t*) realloc(addresses, (*count + chunksize) * sizeof(int64_t));
						*data = (uint8_t*) realloc(*data, (*count + chunksize) * argsize);
						_count = 0;
						i += argsize-1;
					}
				}
			}
			break;
		}
	}

	*count += _count;

	free(buffer);

	return addresses;
}
