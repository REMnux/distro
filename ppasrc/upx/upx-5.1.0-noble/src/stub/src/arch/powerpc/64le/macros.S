#ifndef __ppc64le_macros__  //{
#define __ppc64le_macros__
#if !defined(BIG_ENDIAN) || BIG_ENDIAN
#error must "#define BIG_ENDIAN 0" for powerpc64le
#endif

#include "../64/macros.S"
#endif  //}
