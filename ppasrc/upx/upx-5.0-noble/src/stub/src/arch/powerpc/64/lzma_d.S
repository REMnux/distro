// This file exists so that the LZMA_DEC10 and LZMA_DEC20 sections
// can contain endian-dependent code in the "64" and "64le" directories,
// but otherwise use lzma_d-common.S

#define BIG_ENDIAN 1

#include "../64le/lzma_d-common.S"

  section LZMA_DEC10
#include "lzma_d_cs.S"

  section LZMA_DEC20
#include "lzma_d_cf.S"

// vi:ts=8:et
