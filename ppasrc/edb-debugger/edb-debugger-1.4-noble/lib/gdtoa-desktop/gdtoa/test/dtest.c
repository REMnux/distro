/****************************************************************

The author of this software is David M. Gay.

Copyright (C) 1998-2001 by Lucent Technologies
All Rights Reserved

Permission to use, copy, modify, and distribute this software and
its documentation for any purpose and without fee is hereby
granted, provided that the above copyright notice appear in all
copies and that both that the copyright notice and this
permission notice and warranty disclaimer appear in supporting
documentation, and that the name of Lucent or any of its entities
not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

LUCENT DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
IN NO EVENT SHALL LUCENT OR ANY OF ITS ENTITIES BE LIABLE FOR ANY
SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.

****************************************************************/

/* Please send bug reports to David M. Gay (dmg at acm dot org,
 * with " at " changed at "@" and " dot " changed to ".").	*/

/* Test program for g_dfmt, strtoId, strtod, strtopd, and strtord.
 *
 * Inputs (on stdin):
 *		r rounding_mode
 *		n ndig
 *		number
 *		#hex0 hex1
 *
 *	rounding_mode values:
 *		0 = toward zero
 *		1 = nearest
 *		2 = toward +Infinity
 *		3 = toward -Infinity
 *
 * where number is a decimal floating-point number,
 * hex0 is a string of Hex <= 8 digits for the most significant
 * word of the number, hex1 is a similar string for the other
 * (least significant) word, and ndig is a parameters to g_dfmt.
 */

#include "gdtoaimp.h"
#include <stdio.h>
#include <stdlib.h>

 extern int getround ANSI((int,char*));

 static char ibuf[2048], obuf[2048], obuf1[2048];

#define UL (unsigned long)

 int
main(Void)
{
	U fI[2], u;
	char *s, *se, *se1;
	double f1;
	int i, i1, ndig = 0, nik, nike, r = 1;
	long LL[2];

	while( (s = fgets(ibuf, sizeof(ibuf), stdin)) !=0) {
		while(*s <= ' ')
			if (!*s++)
				continue;
		switch(*s) {
		  case 'r':
			r = getround(r, s);
			continue;
		  case 'n':
			i = s[1];
			if (i <= ' ' || (i >= '0' && i <= '9')) {
				ndig = atoi(s+1);
				continue;
				}
			break; /* nan? */
		  case '#':
			LL[0] = u.L[_0];
			LL[1] = u.L[_1];
			sscanf(s+1, "%lx %lx", &LL[0], &LL[1]);
			u.L[_0] = LL[0];
			u.L[_1] = LL[1];
			printf("\nInput: %s", ibuf);
			printf("--> f = #%lx %lx\n", (long)u.L[_0], (long)u.L[_1]);
			i = 0;
			goto fmt_test;
			}
		printf("\nInput: %s", ibuf);
		i = strtord(ibuf, &se, r, &u.d);
		if (r == 1) {
			if ((u.d != strtod(ibuf, &se1) || se1 != se))
				printf("***strtod and strtord disagree!!\n");
			i1 = strtopd(ibuf, &se, &f1);
			if (i != i1 || u.d != f1 || se != se1)
				printf("***strtord and strtopd disagree!!\n");
			}
		printf("strtord consumes %d bytes and returns %d with f = %.17g = #%lx %lx\n",
				(int)(se-ibuf), i, u.d, UL u.L[_0], UL u.L[_1]);
 fmt_test:
		se = g_dfmt(obuf, &u.d, ndig, sizeof(obuf));
		printf("g_dfmt(%d) gives %d bytes: \"%s\"\n\n",
			ndig, (int)(se-obuf), se ? obuf : "<null>");
		se1 = g_dfmt_p(obuf1, &u.d, ndig, sizeof(obuf1), 0);
		if (se1 - obuf1 != se - obuf || strcmp(obuf, obuf1))
			printf("Botch: g_dfmt_p gives \"%s\" rather than \"%s\"\n",
				obuf1, obuf);
		if (*s == '#')
			continue;
		printf("strtoId returns %d,", strtoId(ibuf, &se, &fI[0].d, &fI[1].d));
		printf(" consuming %d bytes.\n", (int)(se-ibuf));
		if (fI[0].d == fI[1].d) {
			if (fI[0].d == u.d)
				printf("fI[0] == fI[1] == strtod\n");
			else
				printf("fI[0] == fI[1] = #%lx %lx = %.17g\n",
					UL fI[0].L[_0], UL fI[0].L[_1], fI[0].d);
			}
		else {
			printf("fI[0] = #%lx %lx = %.17g\n",
				UL fI[0].L[_0], UL fI[0].L[_1], fI[0].d);
			printf("fI[1] = #%lx %lx = %.17g\n",
				UL fI[1].L[_0], UL fI[1].L[_1], fI[1].d);
			if (fI[0].d == u.d)
				printf("fI[0] == strtod\n");
			else if (fI[1].d == u.d)
				printf("fI[1] == strtod\n");
			else
				printf("**** Both differ from strtod ****\n");
			}
		printf("\n");
		switch(i & STRTOG_Retmask) {
		  case STRTOG_Infinite:
			for(nik = 0; nik < 6; ++nik) {
				se1 = g_dfmt_p(obuf1, &u.d, ndig, sizeof(obuf1), nik);
				printf("g_dfmt_p(...,%d): \"%s\"\n", nik, obuf1);
				}
			break;
		  case STRTOG_NaN:
		  case STRTOG_NaNbits:
			for(i = 0; i < 3; ++i)
				for(nik = 6*i, nike = nik + 3; nik < nike; ++nik) {
					se1 = g_dfmt_p(obuf1, &u.d, ndig, sizeof(obuf1), nik);
					printf("g_dfmt_p(...,%d): \"%s\"\n", nik, obuf1);
					}
		  }
		}
	return 0;
	}
