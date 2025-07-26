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

/* Test program for g_ddfmt, strtoIdd, strtopdd, and strtordd.
 *
 * Inputs (on stdin):
 *		r rounding_mode
 *		n ndig
 *		number
 *		#hex0 hex1 hex2 hex3
 *
 *	rounding_mode values:
 *		0 = toward zero
 *		1 = nearest
 *		2 = toward +Infinity
 *		3 = toward -Infinity
 *
 * where number is a decimal floating-point number,
 * hex0 is a string of <= 8 Hex digits for the most significant
 * word of the number, hex1 is a similar string for the next
 * word, etc., and ndig is a parameters to g_ddfmt.
 */

#include "gdtoaimp.h"
#include <stdio.h>
#include <stdlib.h>

 extern int getround ANSI((int,char*));

 static char ibuf[2048], obuf[1024], obuf1[2048];

#define UL (unsigned long)

 static void
#ifdef KR_headers
dprint(what, d) char *what; double d;
#else
dprint(char *what, double d)
#endif
{
	U u;
	char buf[32];

	u.d = d;
	g_dfmt(buf,&d,0,sizeof(buf));
	printf("%s = %s = #%lx %lx\n", what, buf, UL u.L[_0], UL u.L[_1]);
	}

 int
main(Void)
{
	U ddI[4], u[2];
	char *s, *s1, *se, *se1;
	int dItry, i, j, nik, nike, r = 1, ndig = 0;
	long LL[4];

	while( (s = fgets(ibuf, sizeof(ibuf), stdin)) !=0) {
		while(*s <= ' ')
			if (!*s++)
				continue;
		dItry = 0;
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
			LL[0] = u[0].L[_0];
			LL[1] = u[0].L[_1];
			LL[2] = u[1].L[_0];
			LL[3] = u[1].L[_1];
			sscanf(s+1, "%lx %lx %lx %lx", &LL[0], &LL[1],
				&LL[2], &LL[3]);
			u[0].L[_0] = LL[0];
			u[0].L[_1] = LL[1];
			u[1].L[_0] = LL[2];
			u[1].L[_1] = LL[3];
			printf("\nInput: %s", ibuf);
			printf(" --> f = #%lx %lx %lx %lx\n",
				LL[0],LL[1],LL[2],LL[3]);
			i = 0;
			goto fmt_test;
			}
		printf("\nInput: %s", ibuf);
		for(s1 = s; *s1 > ' '; s1++){};
		while(*s1 <= ' ' && *s1) s1++;
		if (!*s1) {
			dItry = 1;
			i = strtordd(ibuf, &se, r, &u[0].d);
			if (r == 1) {
				j = strtopdd(ibuf, &se1, &ddI[0].d);
				if (i != j || u[0].d != ddI[0].d
				 || u[1].d != ddI[1].d || se != se1)
					printf("***strtopdd and strtordd disagree!!\n:");
				}
			printf("strtopdd consumes %d bytes and returns %d\n",
				(int)(se-ibuf), i);
			}
		else {
			u[0].d = strtod(s, &se);
			u[1].d = strtod(se, &se);
			}
 fmt_test:
		dprint("dd[0]", u[0].d);
		dprint("dd[1]", u[1].d);
		se = g_ddfmt(obuf, &u[0].d, ndig, sizeof(obuf));
		printf("g_ddfmt(%d) gives %d bytes: \"%s\"\n\n",
			ndig, (int)(se-obuf), se ? obuf : "<null>");
		se1 = g_ddfmt_p(obuf1, &u[0].d, ndig, sizeof(obuf1), 0);
		if (se1 - obuf1 != se - obuf || strcmp(obuf, obuf1))
			printf("Botch: g_ddfmt_p gives \"%s\" rather than \"%s\"\n",
				obuf1, obuf);
		if (!dItry)
			continue;
		printf("strtoIdd returns %d,", strtoIdd(ibuf, &se, &ddI[0].d, &ddI[2].d));
		printf(" consuming %d bytes.\n", (int)(se-ibuf));
		if (ddI[0].d == ddI[2].d && ddI[1].d == ddI[3].d) {
			if (ddI[0].d == u[0].d && ddI[1].d == u[1].d)
				printf("ddI[0] == ddI[1] == strtopdd\n");
			else
				printf("ddI[0] == ddI[1] = #%lx %lx + %lx %lx\n= %.17g + %17.g\n",
					UL ddI[0].L[_0],
					UL ddI[0].L[_1],
					UL ddI[1].L[_0],
					UL ddI[1].L[_1],
					ddI[0].d, ddI[1].d);
			}
		else {
			printf("ddI[0] = #%lx %lx + %lx %lx\n= %.17g + %.17g\n",
				UL ddI[0].L[_0], UL ddI[0].L[_1],
				UL ddI[1].L[_0],UL ddI[1].L[_1],
				ddI[0].d, ddI[1].d);
			printf("ddI[1] = #%lx %lx + %lx %lx\n= %.17g + %.17g\n",
				UL ddI[2].L[_0], UL ddI[2].L[_1],
				UL ddI[3].L[_0],UL ddI[3].L[_1],
				ddI[2].d, ddI[3].d);
			if (ddI[0].d == u[0].d && ddI[1].d == u[1].d)
				printf("ddI[0] == strtod\n");
			else if (ddI[2].d == u[0].d && ddI[3].d == u[1].d)
				printf("ddI[1] == strtod\n");
			else
				printf("**** Both differ from strtopdd ****\n");
			}
		switch(i & STRTOG_Retmask) {
		  case STRTOG_Infinite:
			for(nik = 0; nik < 6; ++nik) {
				se1 = g_ddfmt_p(obuf1, &u[0].d, ndig, sizeof(obuf1), nik);
				printf("g_ddfmt_p(...,%d): \"%s\"\n", nik, obuf1);
				}
			break;
		  case STRTOG_NaN:
		  case STRTOG_NaNbits:
			for(i = 0; i < 3; ++i)
				for(nik = 6*i, nike = nik + 3; nik < nike; ++nik) {
					se1 = g_ddfmt_p(obuf1, &u[0].d, ndig, sizeof(obuf1), nik);
					printf("g_ddfmt_p(...,%d): \"%s\"\n", nik, obuf1);
					}
		  }
		printf("\n");
		}
	return 0;
	}
