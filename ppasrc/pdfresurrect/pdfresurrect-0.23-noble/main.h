/******************************************************************************
 * main.h
 *
 * pdfresurrect - PDF history extraction tool
 * https://github.com/enferex/pdfresurrect
 *
 * See https://github.com/enferex/pdfresurrect/blob/master/LICENSE for license
 * information.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Special thanks to all of the contributors:  See AUTHORS.
 * Special thanks to 757labs (757 crew), they are a great group
 * of people to hack on projects and brainstorm with.
 *****************************************************************************/

#ifndef MAIN_H_INCLUDE
#define MAIN_H_INCLUDE

#include <stdio.h>


#define EXEC_NAME "pdfresurrect"
#define VER_MAJOR "0"
#define VER_MINOR "23"
#define VER       VER_MAJOR"."VER_MINOR


#define TAG "[pdfresurrect]"
#define ERR(...) {fprintf(stderr, TAG" -- Error -- " __VA_ARGS__);}

/* Returns a zero'd buffer of 'size' bytes or exits in failure. */
extern void *safe_calloc(size_t bytes);

#endif /* MAIN_H_INCLUDE */
