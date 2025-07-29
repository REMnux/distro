// Copyright (C) Markus Franz Xaver Johannes Oberhumer

#include <stddef.h>
#include <stdint.h>

// check ABI - require proper alignment of fundamental types for use in atomics
static_assert(alignof(char) == sizeof(char), "");
static_assert(alignof(signed char) == sizeof(signed char), "");
static_assert(alignof(unsigned char) == sizeof(unsigned char), "");
static_assert(alignof(short) == sizeof(short), "");
static_assert(alignof(unsigned short) == sizeof(unsigned short), "");
static_assert(alignof(int) == sizeof(int), "");
static_assert(alignof(unsigned int) == sizeof(unsigned int), "");
static_assert(alignof(long) == sizeof(long), "");
static_assert(alignof(unsigned long) == sizeof(unsigned long), "");
static_assert(alignof(ptrdiff_t) == sizeof(ptrdiff_t), "");
static_assert(alignof(size_t) == sizeof(size_t), "");
static_assert(alignof(intptr_t) == sizeof(intptr_t), "");
static_assert(alignof(uintptr_t) == sizeof(uintptr_t), "");
static_assert(alignof(void *) == sizeof(void *), "");

int main() { return 0; }
