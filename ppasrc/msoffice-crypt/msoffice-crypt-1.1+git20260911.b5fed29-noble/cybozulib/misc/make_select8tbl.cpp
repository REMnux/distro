#include <stdio.h>
#include <stdlib.h>
#include <cybozu/inttype.hpp>

inline uint64_t select8(uint64_t v, size_t r)
{
	size_t count = 0;
	for (int i = 0; i <  64; i++) {
		if (v & (uint64_t(1) << i))
			count++;
		if (count == r)
			return i;
	}
	return 64;
}

int main()
{
	for (int x = 0; x < 256; x++) {
		printf("{");
		for (int i = 0; i < 8; i++) {
			printf("%d, ", select8(x, i));
		}
		printf("},\n");
	}
}
