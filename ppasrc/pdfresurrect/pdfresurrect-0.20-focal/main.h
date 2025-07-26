/******************************************************************************
 * main.h 
 *
 * pdfresurrect - PDF history extraction tool
 *
 * Copyright (C) 2008, 2009, 2010, 2012, 2019 Matt Davis (enferex).
 *
 * Special thanks to all of the contributors:  See AUTHORS.
 *
 * Special thanks to 757labs (757 crew), they are a great group
 * of people to hack on projects and brainstorm with.
 *
 * main.h is part of pdfresurrect.
 * pdfresurrect is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * pdfresurrect is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pdfresurrect.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************/

#ifndef MAIN_H_INCLUDE
#define MAIN_H_INCLUDE

#include <stdio.h>


#define EXEC_NAME "pdfresurrect"
#define VER_MAJOR "0"
#define VER_MINOR "20"
#define VER       VER_MAJOR"."VER_MINOR 


#define TAG "[pdfresurrect]"
#define ERR(...) {fprintf(stderr, TAG" -- Error -- " __VA_ARGS__);}

/* Returns a zero'd buffer of 'size' bytes or exits in failure. */
extern void *safe_calloc(size_t bytes);

#endif /* MAIN_H_INCLUDE */
