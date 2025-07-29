/*
	29/12/2006 - 15/07/2020
	XORSearch V1.11.4, search for a XOR, ROL, ROT, SHIFT or ADD encoded string in a file
	Use -s to save the XOR, ROL, ROT, SHIFT or ADD encoded file containing the string
	Use -l length to limit the number of printed characters (50 by default)
	Use -i to ignore the case when searching
	Use -u to search for Unicode strings (limited support)
	Use -f to provide a file with search strings
	Use -n length to print the length neighbouring charaters (before & after the found keyword)
	Use -h to search for hex strings
	Use -k to decode with embedded keys
	Source code put in public domain by Didier Stevens, no Copyright
	https://DidierStevens.com
	Use at your own risk

	Shortcommings, or todo's ;-)
	- optimize embedded keys algos for speed
	- file must fit in memory

	History:
		15/01/2007: multiple hits, only printable characters, length argument
		08/08/2007: 1.2: added ROL 1 to 7 encoding
		17/12/2007: 1.3: findfile
		18/04/2009: 1.4: ROT encoding
		12/01/2010: 1.5: added (limited) Unicode support; -n option
		15/01/2010: 1.6: added hex support
		29/10/2012: 1.7: Dropped malloc.h
		16/02/2013: 1.8: Added SHIFT encoding
		15/06/2013: 1.9: Added embedded keys decoding
		16/06/2013: Continued embedded keys decoding
		10/07/2013: Added InsertSorted to optimize embedded keys algos for speed
		11/07/2013: Continued InsertSorted
		19/07/2013: 1.9.1: code cleanup, refactoring
		13/10/2013: 1.9.2: Added ucOffset to PrintFinds
		14/02/2014: 1.10.0: Added option -p and -e
		17/02/2014: Compatibility checking of option -p with other options
		20/03/2014: changed ulE_lfanew (unsigned long) to uiE_lfanew (unsigned int)
		23/03/2014: 1.10.0: fixes for xcode gcc warnings
		27/08/2014: 1.11.0 added ADD encoding, bugfix ParseNumericArg, wildcards search engine
		29/08/2014: XORSearch returns 0 when strings are found, 1 when nothing is found, and -1 if error
		30/08/2014: added wildcard rules parsing, score, option -d
		04/09/2014: added support for jumps in rules (J;?)
		15/09/2014: added Realloc
		27/09/2014: added option -L
		11/10/2014: 1.11.1: fixes for xcode gcc warnings
		13/10/2014: added option -x
		15/11/2014: 1.11.2: increased line size for rule files (1024 -> 4096)
		25/03/2018: added option -r
		24/04/2018: added support for stdin
		24/08/2018: fixed bug: initialize ucOPRIter before ADD
		10/11/2018: changed ?? to \?\? to avoid trigram warning; added option -S
		11/11/2018: option -S UNICODE
		12/11/2018: continue
		26/12/2018: fixed gcc -Wall warnings; fixed bug: off by one InsertSorted
		07/04/2020: 1.11.3: changed option -n to accept signed numbers
		15/07/2020: 1.11.4: fixed printf formatstring bug for Linux

*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#define countof(array)	(sizeof(array) / sizeof(array[0]))

#define XSIZE 1024

#define OPR_XOR "XOR"
#define OPR_ROL "ROL"
#define OPR_ROT "ROT"
#define OPR_SHIFT "SHIFT"
#define OPR_XOR32 "XOR32"
#define OPR_ADD "ADD"

#define SEARCHTYPE_STOP			0
#define SEARCHTYPE_ASCII		1
#define SEARCHTYPE_UNICODE	2
#define SEARCHTYPE_HEX			3
#define SEARCHTYPE_WILDCARD 4

#define WILDCARD_MODE_BYTE 0
#define WILDCARD_MODE_BITS 1
#define WILDCARD_MODE_JUMP 2
#define WILDCARD_MODE_STOP 3

#define NUMBER_UNDEFINED         0
#define NUMBER_NEGATIVE          1
#define NUMBER_POSITIVE          2
#define NUMBER_EXPLICIT_POSITIVE 3

typedef struct
{
	unsigned char ucMode; //WILDCARD_MODE_
	unsigned char ucByte;
	unsigned char ucMaskFixed;
	unsigned char ucBitsFixed;
	unsigned char ucMaskVariable1;
	char cVariableName1;
	unsigned char ucMaskVariable2;
	char cVariableName2;
	unsigned char ucJumpBytes;
} WILDCARD;

typedef struct
{
	int iSearchType;
	char *pcSearchString;
	int iSearchLength;
	char *pcWildcardName;
	int iScore;
	WILDCARD *pWildcards;
	int iPrintASCII;
} SEARCH;

typedef struct
{
	unsigned int uiNumberType;
	int iNumberValue;
} NUMBER;

int *piFoundIndex;
int *piFoundSize;

int StartsWith(char *szString, char *szPrefix)
{
	if (strlen(szString) < strlen(szPrefix))
		return 0;
	return !strncmp(szString, szPrefix, strlen(szPrefix));
}

int compare(char cX, char cY, int iFlagIgnoreCase)
{
	if (iFlagIgnoreCase && isalpha(cX) && isalpha(cY))
		return tolower(cX) == tolower(cY);
	else
		return cX == cY;
}

// Search algorithm: http://www-igm.univ-mlv.fr/~lecroq/string/node8.html#SECTION0080
void PreKMP(char *pcX, int iXLength, int aiKMPNext[], int iFlagIgnoreCase)
{
	int iIter1, iIter2;

	iIter1 = 0;
	iIter2 = aiKMPNext[0] = -1;
	while (iIter1 < iXLength)
	{
		while (iIter2 > -1 && !compare(pcX[iIter1], pcX[iIter2], iFlagIgnoreCase))
			iIter2 = aiKMPNext[iIter2];
		iIter1++;
		iIter2++;
		if (compare(pcX[iIter1], pcX[iIter2], iFlagIgnoreCase))
			aiKMPNext[iIter1] = aiKMPNext[iIter2];
		else
			aiKMPNext[iIter1] = iIter2;
	}
}

int KMP(char *pcX, int iXLength, char *pcY, int iYLength, int iFlagIgnoreCase)
{
	int iIter1, iIter2, aiKMPNext[XSIZE];
	int iCountFinds = 0;

	if (iXLength > XSIZE)
	{
		fprintf(stderr, "KMP size error\n");
		return 0;
	}

	/* Preprocessing */
	PreKMP(pcX, iXLength, aiKMPNext, iFlagIgnoreCase);

	/* Searching */
	iIter1 = iIter2 = 0;
	while (iIter2 < iYLength)
	{
		while (iIter1 > -1 && !compare(pcX[iIter1], pcY[iIter2], iFlagIgnoreCase))
			iIter1 = aiKMPNext[iIter1];
		iIter1++;
		iIter2++;
		if (iIter1 >= iXLength)
		{
			piFoundIndex[iCountFinds] = iIter2-iIter1;
			piFoundSize[iCountFinds++] = iXLength;
			iIter1 = aiKMPNext[iIter1];
		}
	}
	return iCountFinds;
}

int WildcardSearch(SEARCH *pSearch, unsigned char *pucBuffer, long lSize, char *sOperation, unsigned char ucOffset, unsigned int uiOperand, int iMaxLength, int *piScore)
{
	int iFound;
	unsigned char *pucFoundCharFirst;
	unsigned char *pucSearchBuffer;
	int iIter;
	int iPosition;
	unsigned char *pucLastByteInBuffer;
	int aiVariables[26];

	pucSearchBuffer = pucBuffer;
	pucLastByteInBuffer = pucBuffer + lSize - 1;
	iFound = 0;
	while(1)
	{
		pucFoundCharFirst = memchr(pucSearchBuffer, pSearch->pWildcards[0].ucByte, lSize - (pucSearchBuffer - pucBuffer));
		if (pucFoundCharFirst == NULL)
			break;
		for (iIter = 0; iIter < 26; iIter ++)
			aiVariables[iIter] = -1;
		iIter = 1;
		iPosition = 1;
		while (pSearch->pWildcards[iIter].ucMode != WILDCARD_MODE_STOP)
		{
			if (pSearch->pWildcards[iIter].ucMode == WILDCARD_MODE_BYTE)
			{
				if ((pucFoundCharFirst + iPosition) > pucLastByteInBuffer || pSearch->pWildcards[iIter].ucByte != *(pucFoundCharFirst + iPosition))
					break;
				iIter++;
				iPosition++;
			}
			else if (pSearch->pWildcards[iIter].ucMode == WILDCARD_MODE_BITS)
			{
				if ((pucFoundCharFirst + iPosition) > pucLastByteInBuffer || pSearch->pWildcards[iIter].ucBitsFixed != (*(pucFoundCharFirst + iPosition) & pSearch->pWildcards[iIter].ucMaskFixed))
					break;
				if (pSearch->pWildcards[iIter].ucMaskVariable1 != 0)
				{
					unsigned char ucMask = pSearch->pWildcards[iIter].ucMaskVariable1;
					unsigned char ucValue = *(pucFoundCharFirst + iPosition) & ucMask;
					while ((ucMask & 0x01) == 0)
					{
						ucMask = ucMask >> 1;
						ucValue = ucValue >> 1;
					}
					if (aiVariables[(int)pSearch->pWildcards[iIter].cVariableName1] == -1)
						aiVariables[(int)pSearch->pWildcards[iIter].cVariableName1] = ucValue;
					else if (aiVariables[(int)pSearch->pWildcards[iIter].cVariableName1] != ucValue)
						break;
				}
				if (pSearch->pWildcards[iIter].ucMaskVariable2 != 0)
				{
					unsigned char ucMask = pSearch->pWildcards[iIter].ucMaskVariable2;
					unsigned char ucValue = *(pucFoundCharFirst + iPosition) & ucMask;
					while ((ucMask & 0x01) == 0)
					{
						ucMask = ucMask >> 1;
						ucValue = ucValue >> 1;
					}
					if (aiVariables[(int)pSearch->pWildcards[iIter].cVariableName2] == -1)
						aiVariables[(int)pSearch->pWildcards[iIter].cVariableName2] = ucValue;
					else if (aiVariables[(int)pSearch->pWildcards[iIter].cVariableName2] != ucValue)
						break;
				}
				iIter++;
				iPosition++;
			}
			else if (pSearch->pWildcards[iIter].ucMode == WILDCARD_MODE_JUMP)
			{
				if (4 == pSearch->pWildcards[iIter].ucJumpBytes && (pucFoundCharFirst + iPosition + 3) > pucLastByteInBuffer)
					break;
				switch (pSearch->pWildcards[iIter].ucJumpBytes)
				{
					case 1:
						iPosition += 1 + *(char *)(pucFoundCharFirst + iPosition);
						break;
					case 4:
						iPosition += 4 + *(int *)(pucFoundCharFirst + iPosition);
						break;
				}
				//a// fix for integer overflow
				if ((pucFoundCharFirst + iPosition) < pucBuffer || (pucFoundCharFirst + iPosition) > pucLastByteInBuffer)
					break;
				iIter++;
			}
		}
		if (pSearch->pWildcards[iIter].ucMode == WILDCARD_MODE_STOP)
		{
			iFound = 1;
			*piScore += pSearch->iScore;
			if (!strcmp(sOperation, OPR_XOR32))
#ifndef __WINNT__
				printf("Found %s %08X offset +%d position %08llX: %s ", sOperation, uiOperand, ucOffset, (long long unsigned int)(pucFoundCharFirst - pucBuffer), pSearch->pcWildcardName);
#else
				printf("Found %s %08X offset +%d position %08I64X: %s ", sOperation, uiOperand, ucOffset, (long long unsigned int)(pucFoundCharFirst - pucBuffer), pSearch->pcWildcardName);
#endif
			else if (strcmp(sOperation, OPR_ROT))
#ifndef __WINNT__
				printf("Found %s %02X position %08llX: %s ", sOperation, uiOperand, (long long unsigned int)(pucFoundCharFirst - pucBuffer), pSearch->pcWildcardName);
#else
				printf("Found %s %02X position %08I64X: %s ", sOperation, uiOperand, (long long unsigned int)(pucFoundCharFirst - pucBuffer), pSearch->pcWildcardName);
#endif
			else
#ifndef __WINNT__
				printf("Found %s %02d position %08llX: %s ", sOperation, uiOperand, (long long unsigned int)(pucFoundCharFirst - pucBuffer), pSearch->pcWildcardName);
#else
				printf("Found %s %02d position %08I64X: %s ", sOperation, uiOperand, (long long unsigned int)(pucFoundCharFirst - pucBuffer), pSearch->pcWildcardName);
#endif
			for (iIter = 0; iIter < iMaxLength && pSearch->pWildcards[iIter].ucMode != WILDCARD_MODE_STOP && pucFoundCharFirst + iIter <= pucLastByteInBuffer; iIter++)
				if (pSearch->pWildcards[iIter].ucMode == WILDCARD_MODE_JUMP)
				{
					int iIter2;
					for (iIter2 = 0; iIter2 < pSearch->pWildcards[iIter].ucJumpBytes; iIter2++)
						printf("%02X", ((unsigned char *)pucFoundCharFirst)[iIter + iIter2]);
					break;
				}
				else if (pSearch->iPrintASCII)
					putchar(((unsigned char *)pucFoundCharFirst)[iIter]);
				else
					printf("%02X", ((unsigned char *)pucFoundCharFirst)[iIter]);
			putchar('\n');
		}
		pucSearchBuffer = pucFoundCharFirst + 1;
	}

	return iFound;
}

int WildcardSearches(SEARCH *pSearch, unsigned char *pucBuffer, long lSize, char *sOperation, unsigned char ucOffset, unsigned int uiOperand, int iMaxLength, int *piScore)
{
	int iFound = 0;
	int iIter;

	for (iIter = 0; pSearch[iIter].iSearchType != SEARCHTYPE_STOP; iIter++)
	{
		if (WildcardSearch(&pSearch[iIter], pucBuffer, lSize, sOperation, ucOffset, uiOperand, iMaxLength, piScore))
			iFound = 1;
	}
	return iFound;
}

long ParseIntegerArg(const char *szArg)
{
	char *szError;
	long lResult;

	lResult = strtol(szArg, &szError, 0);
	if (*szError != '\0' || lResult == LONG_MIN || lResult == LONG_MAX)
		return -1;
	else
		return lResult;
}

long ParseHexArg(const char *szArg)
{
	long lResult = 0;

	while (*szArg != '\0')
	{
		if (*szArg >= '0' && *szArg <= '9')
			lResult = lResult * 0x10 + *szArg - '0';
		else if (*szArg >= 'a' && *szArg <= 'f')
			lResult = lResult * 0x10 + *szArg - 'a' + 10;
		else if (*szArg >= 'A' && *szArg <= 'F')
			lResult = lResult * 0x10 + *szArg - 'A' + 10;
		else
			return -1;
		if (lResult == LONG_MIN || lResult == LONG_MAX)
			return -1;
		szArg++;
	}
	return lResult;
}

long ParseNumericArg(const char *szArg)
{
	if (!strncmp(szArg, "0x", 2))
		return(ParseHexArg(szArg + 2));
	else
		return(ParseIntegerArg(szArg));
}

int ParseArgs(int argc, char **argv, int *piSave, int *piMaxLength, int *piIgnoreCase, char **ppcFile, char **ppcSearch, char **ppcSearchFile, int *piUnicode, NUMBER *psNUMBERNeighbourLength, int *piHex, int *piKeys, int *piPEFile, int *piExcludeByte, int *piWildcard, int *piWildcardEmbedded, char **ppcDisable, int *piList, int *piHexFile, int *piReverse, int *piStrings)
{
	int iIterArgv;
	int iCountParameters;
	int iFlagMaxLength;
	int iFlagNeighbourLength;
	int iFlagSearchFile;
	int iFlagExcludeByte;
	int iFlagDisable;
	char *pcFlags;

	iCountParameters = 0;
	iFlagMaxLength = 0;
	iFlagNeighbourLength = 0;
	iFlagSearchFile = 0;
	iFlagExcludeByte = 0;
	iFlagDisable = 0;
	*piSave = 0;
	*piMaxLength = -1;
	psNUMBERNeighbourLength->uiNumberType = NUMBER_UNDEFINED;
	*piIgnoreCase = 0;
	*ppcSearch = NULL;
	*ppcSearchFile = NULL;
	*piUnicode = 0;
	*piHex = 0;
	*piKeys = 0;
	*piPEFile = 0;
	*piExcludeByte = -1;
	*piWildcard = 0;
	*piWildcardEmbedded = 0;
	*ppcDisable = NULL;
	*piList = 0;
	*piHexFile = 0;
	*piReverse = 0;
	*piStrings = 0;

	for (iIterArgv = 1; iIterArgv < argc; iIterArgv++)
	{
		if (argv[iIterArgv][0] == '-' && argv[iIterArgv][1] == '\0' && iCountParameters == 0)
		{
			*ppcFile = argv[iIterArgv];
			iCountParameters++;
		}
		else if (argv[iIterArgv][0] == '-' && 1 != iFlagNeighbourLength)
		{
			if (iFlagMaxLength || iFlagSearchFile || iFlagDisable)
				return 1;
			pcFlags = argv[iIterArgv] + 1;
			while (*pcFlags)
				switch (*pcFlags++)
				{
					case 's':
						*piSave = 1;
						break;
					case 'i':
						*piIgnoreCase = 1;
						break;
					case 'l':
						iFlagMaxLength = 1;
						break;
					case 'f':
						iFlagSearchFile = 1;
						break;
					case 'u':
						*piUnicode = 1;
						break;
					case 'n':
						iFlagNeighbourLength = 1;
						break;
					case 'h':
						*piHex = 1;
						break;
					case 'k':
						*piKeys = 1;
						break;
					case 'p':
						*piPEFile = 1;
						break;
					case 'e':
						iFlagExcludeByte = 1;
						break;
					case 'w':
						*piWildcard = 1;
						break;
					case 'W':
						*piWildcardEmbedded = 1;
						break;
					case 'd':
						iFlagDisable = 1;
						break;
					case 'L':
						*piList = 1;
						break;
					case 'x':
						*piHexFile = 1;
						break;
					case 'r':
						*piReverse = 1;
						break;
					case 'S':
						*piStrings = 1;
						break;
					default:
						return 1;
				}
		}
		else if (iFlagMaxLength)
		{
			*piMaxLength = ParseNumericArg(argv[iIterArgv]);
			if (*piMaxLength < 1)
				return 1;
			iFlagMaxLength = 0;
		}
		else if (iFlagExcludeByte)
		{
			*piExcludeByte = ParseNumericArg(argv[iIterArgv]);
			if (*piExcludeByte < 0x00 || *piExcludeByte > 0xFF)
				return 1;
			iFlagExcludeByte = 0;
		}
		else if (iFlagNeighbourLength)
		{
			psNUMBERNeighbourLength->iNumberValue = ParseNumericArg(argv[iIterArgv]);
			if (0 == psNUMBERNeighbourLength->iNumberValue)
				return 1;
			else if (psNUMBERNeighbourLength->iNumberValue < 0)
				psNUMBERNeighbourLength->uiNumberType = NUMBER_NEGATIVE;
			else if ('+' == argv[iIterArgv][0])
				psNUMBERNeighbourLength->uiNumberType = NUMBER_EXPLICIT_POSITIVE;
			else
				psNUMBERNeighbourLength->uiNumberType = NUMBER_POSITIVE;
			iFlagNeighbourLength = 0;
		}
		else if (iFlagSearchFile)
		{
			*ppcSearchFile = argv[iIterArgv];
			iFlagSearchFile = 0;
		}
		else if (iFlagDisable)
		{
			*ppcDisable = argv[iIterArgv];
			iFlagDisable = 0;
		}
		else if (iCountParameters == 0)
		{
			*ppcFile = argv[iIterArgv];
			iCountParameters++;
		}
		else if (iCountParameters == 1)
		{
			*ppcSearch = argv[iIterArgv];
			iCountParameters++;
		}
		else
			iCountParameters++;
	}
	if (1 == *piList)
		return iCountParameters == 0 ? 0 : 1;
	else if (iCountParameters != 2 && *ppcSearchFile == NULL && *piPEFile == 0 && *piWildcardEmbedded == 0 && *piStrings == 0)
		return 1;
	else if (iCountParameters != 1 && *ppcSearchFile != NULL)
		return 1;
	else if (iCountParameters != 1 && *piPEFile != 0)
		return 1;
	else if (iCountParameters != 1 && *piStrings != 0)
		return 1;
	else if (iCountParameters != 1 && *piWildcardEmbedded != 0)
		return 1;
	else if (*piMaxLength != -1 && NUMBER_UNDEFINED != psNUMBERNeighbourLength->uiNumberType)
		return 1;
	else if ((*piUnicode && *piHex) || (*piUnicode && (*piWildcard || *piWildcardEmbedded)) || (*piHex && (*piWildcard || *piWildcardEmbedded)) || (*piWildcard && *piWildcardEmbedded))
		return 1;
	else if (*piKeys && *piExcludeByte != -1)
		return 1;
	else if ((*piPEFile != 0 || *piStrings != 0) && *ppcSearchFile != NULL)
		return 1;
	else if ((*piPEFile != 0 || *piStrings != 0) && *piIgnoreCase != 0)
		return 1;
	else if ((*piPEFile != 0 || *piStrings != 0) && *piUnicode != 0)
		return 1;
	else if ((*piPEFile != 0 || *piStrings != 0) && *piHex != 0)
		return 1;
	else if ((*piPEFile != 0 || *piStrings != 0) && NUMBER_UNDEFINED != psNUMBERNeighbourLength->uiNumberType)
		return 1;
	else if (*piWildcardEmbedded != 0 && *ppcSearchFile != NULL)
		return 1;
	else
		return 0;
}

void XOR(unsigned char *pcBuffer, long lSize, unsigned char cXOR, int iExcludeByte)
{
	unsigned char *pucLastByteInBuffer;

	pucLastByteInBuffer = pcBuffer + lSize - 1;
	while (pcBuffer <= pucLastByteInBuffer)
	{
		if (iExcludeByte < 0 || iExcludeByte != *pcBuffer)
			*pcBuffer ^= cXOR;
		pcBuffer++;
	}
}

void XOR32(unsigned int *puiBuffer, long lSize, unsigned int uiOffset, unsigned int uiXOR)
{
	unsigned int *pucLastUIntInBuffer;

	pucLastUIntInBuffer = ((unsigned int *)((unsigned char *)puiBuffer + lSize)) - 1;
	puiBuffer = (unsigned int *)((unsigned char *)puiBuffer + uiOffset);
	while (puiBuffer <= pucLastUIntInBuffer)
		*puiBuffer++ ^= uiXOR;
}

void ROL(unsigned char *pcBuffer, long lSize, int iExcludeByte)
{
	unsigned char *pucLastByteInBuffer;

	pucLastByteInBuffer = pcBuffer + lSize - 1;
	while (pcBuffer <= pucLastByteInBuffer)
	{
		if (iExcludeByte < 0 || iExcludeByte != *pcBuffer)
			*pcBuffer = *pcBuffer << 1 | *pcBuffer >> 7;
		pcBuffer++;
	}
}

void ROT(unsigned char *pcBuffer, long lSize, int iExcludeByte)
{
	unsigned char *pucLastByteInBuffer;

	pucLastByteInBuffer = pcBuffer + lSize - 1;
	while (pcBuffer <= pucLastByteInBuffer)
	{
		if (iExcludeByte < 0 || iExcludeByte != *pcBuffer)
		{
			if ((*pcBuffer >= 'a' && *pcBuffer < 'z') || (*pcBuffer >= 'A' && *pcBuffer < 'Z'))
				(*pcBuffer)++;
			else if (*pcBuffer == 'z')
				*pcBuffer = 'a';
			else if (*pcBuffer == 'Z')
				*pcBuffer = 'A';
		}
		pcBuffer++;
	}
}

void SHIFT(unsigned char *pcBuffer, long lSize, int iExcludeByte)
{
	unsigned char *pucLastByteInBuffer;
	unsigned char ucFirstBit;

	pucLastByteInBuffer = pcBuffer + lSize - 1;
	ucFirstBit = *pcBuffer >> 7;
	while (pcBuffer <= pucLastByteInBuffer - 1)
	{
		if (iExcludeByte < 0 || iExcludeByte != *pcBuffer)
			*pcBuffer = *pcBuffer << 1 | *(pcBuffer + 1) >> 7;
		pcBuffer++;
	}
	if (iExcludeByte < 0 || iExcludeByte != *pucLastByteInBuffer)
		*pucLastByteInBuffer = *pucLastByteInBuffer << 1 | ucFirstBit;
}

void ADD(unsigned char *pcBuffer, long lSize, int iExcludeByte)
{
	unsigned char *pucLastByteInBuffer;

	pucLastByteInBuffer = pcBuffer + lSize - 1;
	while (pcBuffer <= pucLastByteInBuffer)
	{
		if (iExcludeByte < 0 || iExcludeByte != *pcBuffer)
			*pcBuffer = *pcBuffer + 1;
		pcBuffer++;
	}
}

void SaveFile(char *pcFile, char *sOperation, unsigned char ucXOR, void *pBuffer, long lSize)
{
	char szFileNameSave[XSIZE];
	FILE *fOut;

	snprintf(szFileNameSave, XSIZE, "%s.%s.%02X", pcFile, sOperation, ucXOR);
	if ((fOut = fopen(szFileNameSave, "wb")) == NULL)
		fprintf(stderr, "error opening file %s\n", szFileNameSave);
	else
	{
		if (fwrite(pBuffer, lSize, 1, fOut) != 1)
			fprintf(stderr, "error writing file %s\n", szFileNameSave);
		fclose(fOut);
	}
}

void PrintFinds(int iCountFinds, int iMaxLength, char *sOperation, unsigned char ucOffset, unsigned int uiOperand, off_t otFileSize, void *pBuffer, int iSearchType, NUMBER *psNUMBERNeighbourLength)
{
	int iIter1, iIter2;
	int iMaxPrint;
	int iStart;
	int iStop;
	int iStep;

	for (iIter1 = 0; iIter1 < iCountFinds; iIter1++)
	{
		if (!strcmp(sOperation, OPR_XOR32))
			printf("Found %s %08X offset +%d position %04X", sOperation, uiOperand, ucOffset, piFoundIndex[iIter1]);
		else if (strcmp(sOperation, OPR_ROT))
			printf("Found %s %02X position %04X", sOperation, uiOperand, piFoundIndex[iIter1]);
		else
			printf("Found %s %02d position %04X", sOperation, uiOperand, piFoundIndex[iIter1]);
		if (NUMBER_POSITIVE == psNUMBERNeighbourLength->uiNumberType)
			printf("(-%d): ", psNUMBERNeighbourLength->iNumberValue);
		else if (NUMBER_NEGATIVE == psNUMBERNeighbourLength->uiNumberType)
			printf("(%d): ", psNUMBERNeighbourLength->iNumberValue);
		else
			printf(": ");
		if (NUMBER_UNDEFINED != psNUMBERNeighbourLength->uiNumberType)
		{
			iStep = iSearchType == SEARCHTYPE_UNICODE ? 2 : 1;
			if (NUMBER_POSITIVE == psNUMBERNeighbourLength->uiNumberType)
			{
				iStart = piFoundIndex[iIter1] - psNUMBERNeighbourLength->iNumberValue * iStep;
				iStop = piFoundIndex[iIter1] + piFoundSize[iIter1] + psNUMBERNeighbourLength->iNumberValue * iStep;
			}
			else if (NUMBER_NEGATIVE == psNUMBERNeighbourLength->uiNumberType)
			{
				iStart = piFoundIndex[iIter1] + psNUMBERNeighbourLength->iNumberValue * iStep;
				iStop = piFoundIndex[iIter1] + piFoundSize[iIter1];
			}
			else if (NUMBER_EXPLICIT_POSITIVE == psNUMBERNeighbourLength->uiNumberType)
			{
				iStart = piFoundIndex[iIter1];
				iStop = piFoundIndex[iIter1] + piFoundSize[iIter1] + psNUMBERNeighbourLength->iNumberValue * iStep;
			}
			else
				return;
			if (iStart < 0)
				iStart = 0;
			if (iStop > otFileSize)
				iStop = otFileSize;
			for (iIter2 = iStart; iIter2 < iStop; iIter2 += iStep)
				if (SEARCHTYPE_HEX == iSearchType)
					printf("%02X", ((unsigned char *)pBuffer)[iIter2]);
				else
					if (isprint(((unsigned char *)pBuffer)[iIter2]))
						putchar(((unsigned char *)pBuffer)[iIter2]);
					else
						putchar('.');
		}
		else
		{
			iMaxPrint = iMaxLength;
			iStep = iSearchType == SEARCHTYPE_UNICODE ? 2 : 1;
			for (iIter2 = piFoundIndex[iIter1]; iIter2 < otFileSize && (SEARCHTYPE_HEX == iSearchType || ((unsigned char *)pBuffer)[iIter2]); iIter2 += iStep)
			{
				if (SEARCHTYPE_HEX == iSearchType)
					printf("%02X", ((unsigned char *)pBuffer)[iIter2]);
				else
					if (isprint(((unsigned char *)pBuffer)[iIter2]))
						putchar(((unsigned char *)pBuffer)[iIter2]);
					else
						putchar('.');
				if (iMaxLength > 0 && --iMaxPrint == 0)
					break;
			}
		}
		putchar('\n');
	}
}


char *strncpy0(char *pszDestination, char *pszSource, size_t stNum)
{
	strncpy(pszDestination, pszSource, stNum);
	pszDestination[stNum - 1] = '\0';
	return pszDestination;
}

int IsHexDigit(char cHexDigit)
{
	return (cHexDigit >= '0' && cHexDigit <= '9') || (cHexDigit >= 'A' && cHexDigit <= 'F') || (cHexDigit >= 'a' && cHexDigit <= 'f');
}

int HexDigitToNibble(char cHexDigit)
{
	if (cHexDigit >= '0' && cHexDigit <= '9')
		return cHexDigit - '0';
	if (cHexDigit >= 'A' && cHexDigit <= 'F')
		return cHexDigit - 'A' + 10;
	if (cHexDigit >= 'a' && cHexDigit <= 'f')
		return cHexDigit - 'a' + 10;
	return -1;
}

int Hexstring2Binary(char *pcHexString, char *pcBinary)
{
	int iCount = 0;

	while ('\0' != *pcHexString && '\0' != *(pcHexString + 1) && iCount < XSIZE)
		if (IsHexDigit(*pcHexString) && IsHexDigit(*(pcHexString + 1)))
		{
			pcBinary[iCount++] = (char) HexDigitToNibble(*pcHexString) * 0x10 + HexDigitToNibble(*(pcHexString + 1));
			pcHexString += 2;
		}
		else
			return -1;
	if ('\0' != *pcHexString)
		return -2;
	else
		return iCount;
}

char *GetSearchString(char *pcArgSearch, char *pcArgSearchFile, int iSearchType, int *piLength)
{
	static char szSearch[XSIZE+1];
	static int iArgSearchReturned;
	static FILE *fSearchFile;
	int iIter;

	if (iArgSearchReturned)
	{
		iArgSearchReturned = 0;
		return NULL;
	}

	if (pcArgSearch == NULL)
	{
		if (fSearchFile == NULL)
			if ((fSearchFile = fopen(pcArgSearchFile, "r")) == NULL)
			{
				fprintf(stderr, "error opening file %s\n", pcArgSearchFile);
				exit(-1);
			}
		if (fgets(szSearch, XSIZE, fSearchFile) == NULL)
		{
			fclose(fSearchFile);
			fSearchFile = NULL;
			return NULL;
		}
		else
		{
			if (strlen(szSearch) > 0 && szSearch[strlen(szSearch) - 1] == '\n')
				szSearch[strlen(szSearch) - 1] = '\0';
			switch (iSearchType)
			{
				case SEARCHTYPE_ASCII:
					*piLength = strlen(szSearch);
					break;
				case SEARCHTYPE_UNICODE:
					*piLength = 2 * strlen(szSearch);
					for (iIter = XSIZE / 2; iIter > 0; iIter--)
						szSearch[2 * iIter] = szSearch[iIter];
					for (iIter = 1; iIter <= XSIZE; iIter += 2)
						szSearch[iIter] = '\0';
					break;
				case SEARCHTYPE_HEX:
					*piLength = Hexstring2Binary(szSearch, szSearch);
					if (*piLength < 0)
					{
						fprintf(stderr, "Error parsing hex string\n");
						exit(-1);
					}
					break;
				default:
					fprintf(stderr, "Panic: 0001\n");
					exit(-1);
			}
			return szSearch;
		}
	}
	else
	{
		iArgSearchReturned = 1;
		switch (iSearchType)
		{
			case SEARCHTYPE_ASCII:
				strncpy0(szSearch, pcArgSearch, XSIZE);
				*piLength = strlen(szSearch);
				break;
			case SEARCHTYPE_UNICODE:
				strncpy0(szSearch, pcArgSearch, XSIZE / 2);
				*piLength = 2 * strlen(szSearch);
				for (iIter = XSIZE / 2; iIter > 0; iIter--)
					szSearch[2 * iIter] = szSearch[iIter];
				for (iIter = 1; iIter <= XSIZE; iIter += 2)
					szSearch[iIter] = '\0';
				break;
			case SEARCHTYPE_HEX:
				*piLength = Hexstring2Binary(pcArgSearch, szSearch);
				if (*piLength < 0)
				{
					fprintf(stderr, "Error parsing hex string: %s\n", pcArgSearch);
					exit(-1);
				}
				break;
			case SEARCHTYPE_WILDCARD:
				break;
			default:
				fprintf(stderr, "Panic: 0002\n");
				exit(-1);
		}
		return szSearch;
	}
}

int BinarySearch(unsigned int *puiArray, unsigned int uiElement, int iMinimum, int iMaximum, unsigned int *puiIndex)
{
	int iMiddle;

	if (iMaximum < iMinimum)
	{
		*puiIndex = iMinimum;
		return 0;
	}
	else
	{
		iMiddle = iMinimum + ((iMaximum - iMinimum) / 2);
		if (puiArray[iMiddle] > uiElement)
			return BinarySearch(puiArray, uiElement, iMinimum, iMiddle - 1, puiIndex);
		else if (puiArray[iMiddle] < uiElement)
			return BinarySearch(puiArray, uiElement, iMiddle + 1, iMaximum, puiIndex);
		else
		{
			*puiIndex = iMiddle;
			return 1;
		}
	}
}

void InsertSorted(unsigned int uiElement, unsigned int *puiArray, unsigned int uiArraySize, unsigned int *puiArrayCount)
{
	unsigned int uiIndex;
	unsigned int uiIter;

	if (*puiArrayCount >= uiArraySize)
		return;
	if (*puiArrayCount == 0)
	{
		puiArray[(*puiArrayCount)++] = uiElement;
		return;
	}

	if (BinarySearch(puiArray, uiElement, 0, *puiArrayCount - 1, &uiIndex))
		return;

	if (uiIndex == *puiArrayCount)
	{
		if (puiArray[*puiArrayCount - 1] != uiElement)
			puiArray[(*puiArrayCount)++] = uiElement;
	}
	else
	{
		for (uiIter = *puiArrayCount; uiIndex < uiIter; uiIter--)
			puiArray[uiIter] = puiArray[uiIter - 1];
		puiArray[uiIndex] = uiElement;
		(*puiArrayCount)++;
	}
}

int SearchForPEFile(unsigned char *pucBuffer, long lSize, char *sOperation, unsigned char ucOffset, unsigned int uiOperand, int iMaxLength)
{
	int iFound;
	unsigned char *pucFoundCharM;
	unsigned char *pucSearchBuffer;
	unsigned char *pucLastByteInBuffer;
	unsigned int uiE_lfanew;
	unsigned char *pucPEHeader;
	int iIter;

	iFound = 0;
	pucSearchBuffer = pucBuffer;
	pucLastByteInBuffer = pucBuffer + lSize - 1;
	while(1)
	{
		pucFoundCharM = memchr(pucSearchBuffer, 'M', lSize - (pucSearchBuffer - pucBuffer));
		if (pucFoundCharM == NULL)
			break;
		if (pucFoundCharM + 0x40 - 1 > pucLastByteInBuffer) // Is the size OK for a IMAGE_DOS_HEADER?
			break;
		pucSearchBuffer = pucFoundCharM + 1;
		if (*(pucFoundCharM + 1) != 'Z')
			continue;
		uiE_lfanew = *(unsigned int *)(pucFoundCharM + 0x3C);
		pucPEHeader = pucFoundCharM + uiE_lfanew;
		if (pucPEHeader < pucBuffer || pucPEHeader + 0x01 > pucLastByteInBuffer) // Can we check for "PE" without buffer underrun/overrun?
			continue;
		if (*(pucPEHeader) != 'P' || *(pucPEHeader + 0x01) != 'E')
			continue;

		iFound = 1;
		if (!strcmp(sOperation, OPR_XOR32))
#ifndef __WINNT__
			printf("Found %s %08X offset +%d position %08llX: %08X ", sOperation, uiOperand, ucOffset, (long long unsigned int)(pucFoundCharM - pucBuffer), uiE_lfanew);
#else
			printf("Found %s %08X offset +%d position %08I64X: %08X ", sOperation, uiOperand, ucOffset, (long long unsigned int)(pucFoundCharM - pucBuffer), uiE_lfanew);
#endif
		else if (strcmp(sOperation, OPR_ROT))
#ifndef __WINNT__
			printf("Found %s %02X position %08llX: %08X ", sOperation, uiOperand, (long long unsigned int)(pucFoundCharM - pucBuffer), uiE_lfanew);
#else
			printf("Found %s %02X position %08I64X: %08X ", sOperation, uiOperand, (long long unsigned int)(pucFoundCharM - pucBuffer), uiE_lfanew);
#endif
		else
#ifndef __WINNT__
			printf("Found %s %02d position %08llX: %08X ", sOperation, uiOperand, (long long unsigned int)(pucFoundCharM - pucBuffer), uiE_lfanew);
#else
			printf("Found %s %02d position %08I64X: %08X ", sOperation, uiOperand, (long long unsigned int)(pucFoundCharM - pucBuffer), uiE_lfanew);
#endif
		for (iIter = 0; iIter < iMaxLength && pucFoundCharM + 0x40 + iIter <= pucLastByteInBuffer; iIter++)
		{
			if (isprint(*(pucFoundCharM + 0x40 + iIter)))
				putchar(*(pucFoundCharM + 0x40 + iIter));
			else
				putchar('.');
		}
		putchar('\n');
	}

	return iFound;
}

char *AllocAndCopyString(char *szArg, int iLength)
{
	char *szReturn;
	szReturn = calloc(iLength + 1, 1);

	if (NULL == szReturn)
		return NULL;
	return strncpy0(szReturn, szArg, iLength + 1);
}

void *Realloc(void* pvData, size_t sElement, int *piCount, int iIncrement)
{
	void *pvResult;
	size_t sOld;
	size_t sNew;

	sOld = sElement * *piCount;
	*piCount += iIncrement;
	sNew = sElement * *piCount;
	pvResult = realloc(pvData, sNew);
	if (NULL == pvResult)
		return NULL;
	memset((void *)((unsigned char *)pvResult + sOld), 0, sNew - sOld);
	return pvResult;
}

int CheckHexDigit(char cDigit)
{
	if (cDigit >= '0' && cDigit <= '9')
		return cDigit - '0';
	else if (cDigit >= 'a' && cDigit <= 'f')
		return cDigit - 'a' + 10;
	else if (cDigit >= 'A' && cDigit <= 'F')
		return cDigit - 'A' + 10;
	else
		return -1;
}

int ParseBits(char *szBits, WILDCARD *pWildcard)
{
	int iIter;
	int iCountVariable = 0;

	pWildcard->ucMode = WILDCARD_MODE_BITS;
	pWildcard->ucMaskFixed = 0;
	pWildcard->ucBitsFixed = 0;
	pWildcard->ucMaskVariable1 = 0;
	pWildcard->cVariableName1 = 0;
	pWildcard->ucMaskVariable2 = 0;
	pWildcard->cVariableName2 = 0;

	for (iIter = 0; iIter < 8; iIter++)
	{
		if ('0' == szBits[iIter])
		{
			pWildcard->ucMaskFixed |= 1 << (7 - iIter);
		}
		else if ('1' == szBits[iIter])
		{
			pWildcard->ucMaskFixed |= 1 << (7 - iIter);
			pWildcard->ucBitsFixed |= (szBits[iIter] - '0') * 1 << (7 - iIter);
		}
		else if ('?' == szBits[iIter])
		{
			if (1 == iCountVariable)
				pWildcard->ucMaskVariable1 |= 1 << (7 - iIter);
			else if (2 == iCountVariable)
				pWildcard->ucMaskVariable2 |= 1 << (7 - iIter);
		}
		else if (szBits[iIter] >= 'A' && szBits[iIter] <= 'Z')
		{
			if (0 == iCountVariable)
			{
				pWildcard->ucMaskVariable1 |= 1 << (7 - iIter);
				pWildcard->cVariableName1 = szBits[iIter] - 'A';
				iCountVariable++;
			}
			else if (1 == iCountVariable)
			{
				pWildcard->ucMaskVariable2 |= 1 << (7 - iIter);
				pWildcard->cVariableName2 = szBits[iIter] - 'A';
				iCountVariable++;
			}
			else
				return -1;
		}
		else
			return -1;
	}

	return 0;
}

int ParseJump(char *szJump, WILDCARD *pWildcard)
{
	pWildcard->ucMode = WILDCARD_MODE_JUMP;
	pWildcard->ucJumpBytes = 0;

	if ('1' == szJump[0] || '4' == szJump[0])
	{
		pWildcard->ucJumpBytes = szJump[0] - '0';
		return 0;
	}
	else
		return -1;
}

#define PREFIX_STRE "str="

WILDCARD *ParseWildcards(char *szWildcard)
{
	WILDCARD *pWildcards;
	char *pcWildcard;
	int iIter;
	int iSizeBuffer;

	iSizeBuffer = 0x100;
	iIter = 0;
	pWildcards = calloc(sizeof(WILDCARD), iSizeBuffer);
	if (NULL == pWildcards)
		return NULL;

	pcWildcard = szWildcard;
	if (strlen(pcWildcard) > strlen(PREFIX_STRE) && StartsWith(pcWildcard, PREFIX_STRE))
	{
		pcWildcard += strlen(PREFIX_STRE);
		while (strlen(pcWildcard) != 0)
		{
			pWildcards[iIter].ucMode = WILDCARD_MODE_BYTE;
			pWildcards[iIter++].ucByte = pcWildcard[0];
			pcWildcard++;
			if (iIter == iSizeBuffer)
			{
				pWildcards = Realloc(pWildcards, sizeof(WILDCARD), &iSizeBuffer, 0x100);
				if (NULL == pWildcards)
					return NULL;
			}
		}
	}
	else
		while (strlen(pcWildcard) != 0)
		{
			if (strlen(pcWildcard) >= 2 && -1 != CheckHexDigit(pcWildcard[0]) && -1 != CheckHexDigit(pcWildcard[1]))
			{
				pWildcards[iIter].ucMode = WILDCARD_MODE_BYTE;
				pWildcards[iIter++].ucByte = CheckHexDigit(pcWildcard[0]) * 0x10 + CheckHexDigit(pcWildcard[1]);
				pcWildcard += 2;
			}
			else if ('(' == *pcWildcard && strlen(pcWildcard) >= 12 && 'B' == pcWildcard[1] && ';' == pcWildcard[2] && ')' == pcWildcard[11])
			{
				if (0 == iIter)
					return 0;
				if (-1 == ParseBits(AllocAndCopyString(pcWildcard + 3, 8), &pWildcards[iIter++]))
					return NULL;
				pcWildcard += 12;
			}
			else if ('(' == *pcWildcard && strlen(pcWildcard) >= 5 && 'J' == pcWildcard[1] && ';' == pcWildcard[2] && ')' == pcWildcard[4])
			{
				if (0 == iIter)
					return 0;
				if (-1 == ParseJump(AllocAndCopyString(pcWildcard + 3, 1), &pWildcards[iIter++]))
					return NULL;
				pcWildcard += 5;
			}
			else
				return NULL;
			if (iIter == iSizeBuffer)
			{
				pWildcards = Realloc(pWildcards, sizeof(WILDCARD), &iSizeBuffer, 0x100);
				if (NULL == pWildcards)
					return NULL;
			}
		}

	pWildcards[iIter].ucMode = WILDCARD_MODE_STOP;

	pWildcards = realloc(pWildcards, sizeof(WILDCARD) * (iIter + 1));
	if (NULL == pWildcards)
		return NULL;

	return pWildcards;
}

unsigned int ParseRule(char *pcRule, char **ppcName, int *piScore, char **ppcWildcards, WILDCARD **ppWildcards)
{
	char *pcSeparator1;
	char *pcSeparator2;
	char *pcSeparator3;
	char *szScore;

	pcSeparator1 = strchr(pcRule, ':');
	if (NULL == pcSeparator1)
		return -1;
	pcSeparator2 = strchr(pcSeparator1 + 1, ':');
	if (NULL == pcSeparator2)
		return -1;
	pcSeparator3 = strchr(pcSeparator2 + 1, ':');
	if (NULL != pcSeparator3)
		return -1;

	*ppcName = AllocAndCopyString(pcRule, pcSeparator1 - pcRule);
	if (NULL == *ppcName)
		return -1;
	szScore = AllocAndCopyString(pcSeparator1 + 1, pcSeparator2 - pcSeparator1 - 1);
	if (NULL == szScore)
		return -1;
	*piScore = (int) ParseIntegerArg(szScore);
	if (-1 == *piScore)
		return -1;
	*ppcWildcards = AllocAndCopyString(pcSeparator2 + 1, strlen(pcSeparator2 + 1));
	if (NULL == *ppcWildcards)
		return -1;

	*ppWildcards = ParseWildcards(pcSeparator2 + 1);
	if (NULL == *ppWildcards)
		return -1;

	return 0;
}

int AddRule(SEARCH **ppSearch, int *piSize, int *piIndex, char *pcRule)
{
	char *pcName;
	int iScore;
	char *pcWildcards;
	WILDCARD *pWildcards;

	if (0 == *piSize)
	{
		*piSize = 10;
		*ppSearch = calloc(sizeof(SEARCH), *piSize);
		if (NULL == *ppSearch)
			return -1;
	}

	if (*piIndex >= *piSize - 1)
	{
		*ppSearch = Realloc(*ppSearch, sizeof(SEARCH), piSize, 10);
		if (NULL == *ppSearch)
			return -1;
	}

	if (ParseRule(pcRule, &pcName, &iScore, &pcWildcards, &pWildcards))
		return -1;

	(*ppSearch)[*piIndex].iSearchType = SEARCHTYPE_WILDCARD;
	(*ppSearch)[*piIndex].pcWildcardName = pcName;
	(*ppSearch)[*piIndex].iScore = iScore;
	(*ppSearch)[*piIndex].iPrintASCII = StartsWith(pcWildcards, PREFIX_STRE);
	(*ppSearch)[(*piIndex)++].pWildcards = pWildcards;

	(*ppSearch)[*piIndex].iSearchType = SEARCHTYPE_STOP;

	return 0;
}

SEARCH *InitializeSearch(char *pcRule, char *szFile, int iFlagEmbedded)
{
	SEARCH *pSearch;
	int iSize;
	int iIndex;
	int iIter;
	FILE *fRules;
	char szLine[4096];
	char *aszEmbeddedRules[] =
	{
		"Function prolog signature:10:558bec83c4",
		"Function prolog signature:10:558bec81ec",
		"Function prolog signature:10:558beceb",
		"Function prolog signature:10:558bece8",
		"Function prolog signature:10:558bece9",
		"Indirect function call tris:10:FFB7(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?)FF57(B;\?\?\?\?\?\?\?\?)",
		"GetEIP method 4 FLDZ/FSTENV [esp-12]:10:D9EED97424F4(B;01011\?\?\?)",
		"GetEIP method 1:10:E800000000(B;01011\?\?\?)",
		"GetEIP method 2:10:EB(J;1)E8(J;4)(B;01011\?\?\?)",
		"GetEIP method 3:10:E9(J;4)E8(J;4)(B;01011\?\?\?)",
		"GetEIP method 4:10:D9EE9BD97424F4(B;01011\?\?\?)",
		"Find kernel32 base method 1:10:648B(B;00\?\?\?101)30000000",
		"Find kernel32 base method 1bis:10:64A130000000",
		"Find kernel32 base method 2:10:31(B;11A\?\?A\?\?)(B;10100A\?\?)30648B(B;00B\?\?A\?\?)",
		"Find kernel32 base method 3:10:6830000000(B;01011A\?\?)648B(B;00B\?\?A\?\?)",
		"Structured exception handling :10:648B(B;00\?\?\?101)00000000",
		"Structured exception handling bis:10:64A100000000",
		"API Hashing:10:AC84C07407C1CF0D01C7EBF481FF",
		"API Hashing bis:10:AC84C07407C1CF0701C7EBF481FF",
//	"API-Hashing signature:10:74(B;\?\?\?\?\?\?\?\?)c1(B;\?\?\?\?\?\?\?\?)0d(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?), // too many false positives
//	"API-Hashing signature:10:74(B;\?\?\?\?\?\?\?\?)c1(B;\?\?\?\?\?\?\?\?)07(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?), // too many false positives
//	"API-Hashing signature:10:74(B;\?\?\?\?\?\?\?\?)c1(B;\?\?\?\?\?\?\?\?)0b03(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?)(B;\?\?\?\?\?\?\?\?), // too many false positives
		"Indirect function call:10:FF75(B;A\?\?\?\?\?\?\?)FF55(B;A\?\?\?\?\?\?\?)",
		"Indirect function call bis:10:FFB5(B;A\?\?\?\?\?\?\?)(B;B\?\?\?\?\?\?\?)(B;C\?\?\?\?\?\?\?)(B;D\?\?\?\?\?\?\?)FF95(B;A\?\?\?\?\?\?\?)(B;B\?\?\?\?\?\?\?)(B;C\?\?\?\?\?\?\?)(B;D\?\?\?\?\?\?\?)",
		"OLE file magic number:10:D0CF11E0",
		"Suspicious strings:2:str=UrlDownloadToFile",
		"Suspicious strings:2:str=GetTempPath",
		"Suspicious strings:2:str=GetWindowsDirectory",
		"Suspicious strings:2:str=GetSystemDirectory",
		"Suspicious strings:2:str=WinExec",
		"Suspicious strings:2:str=ShellExecute",
		"Suspicious strings:2:str=IsBadReadPtr",
		"Suspicious strings:2:str=IsBadWritePtr",
		"Suspicious strings:2:str=CreateFile",
		"Suspicious strings:2:str=CloseHandle",
		"Suspicious strings:2:str=ReadFile",
		"Suspicious strings:2:str=WriteFile",
		"Suspicious strings:2:str=SetFilePointer",
		"Suspicious strings:2:str=VirtualAlloc",
		"Suspicious strings:2:str=GetProcAddr",
		"Suspicious strings:2:str=LoadLibrary",
	};

	pSearch = NULL;
	iSize = 0;
	iIndex = 0;

	if (iFlagEmbedded)
	{
		for (iIter = 0; iIter < countof(aszEmbeddedRules); iIter++)
			if (AddRule(&pSearch, &iSize, &iIndex, aszEmbeddedRules[iIter]) != 0)
				return NULL;
	}
	else if (NULL != szFile)
	{
		if ((fRules = fopen(szFile, "r")) == NULL)
		{
			fprintf(stderr, "error opening file %s\n", szFile);
			exit(-1);
		}
		while (fgets(szLine, sizeof(szLine), fRules) != NULL)
		{
			if (strlen(szLine) > 0 && szLine[strlen(szLine) - 1] == '\n')
				szLine[strlen(szLine) - 1] = '\0';
			if (strlen(szLine) > 0 && szLine[0] != '#')
				if (AddRule(&pSearch, &iSize, &iIndex, szLine) != 0)
				{
					fclose(fRules);
					return NULL;
				}
		}
		fclose(fRules);
	}
	else
	{
		if (AddRule(&pSearch, &iSize, &iIndex, pcRule) != 0)
			return NULL;
	}

	return pSearch;
}

void List(SEARCH *pSearch)
{
	int iIter1;
	int iIter2;
	int iIter3;
	int iVariable1WasPrinted;
	int iVariable2WasPrinted;

	for (iIter1 = 0; pSearch[iIter1].iSearchType != SEARCHTYPE_STOP; iIter1++)
	{
		printf("%s:%d:", pSearch[iIter1].pcWildcardName, pSearch[iIter1].iScore);
		if (1 == pSearch[iIter1].iPrintASCII)
		{
			printf("str=");
			for (iIter2 = 0; pSearch[iIter1].pWildcards[iIter2].ucMode != WILDCARD_MODE_STOP; iIter2++)
				printf("%c", pSearch[iIter1].pWildcards[iIter2].ucByte);
		}
		else
		{
			for (iIter2 = 0; pSearch[iIter1].pWildcards[iIter2].ucMode != WILDCARD_MODE_STOP; iIter2++)
				switch (pSearch[iIter1].pWildcards[iIter2].ucMode)
				{
					case WILDCARD_MODE_BYTE:
						printf("%02X", pSearch[iIter1].pWildcards[iIter2].ucByte);
						break;
					case WILDCARD_MODE_BITS:
						iVariable1WasPrinted = 0;
						iVariable2WasPrinted = 0;
						printf("(B;");
						for (iIter3 = 7; iIter3 >= 0; iIter3--)
							if ((pSearch[iIter1].pWildcards[iIter2].ucMaskFixed >> iIter3) & 0x01)
								printf("%d", (pSearch[iIter1].pWildcards[iIter2].ucBitsFixed >> iIter3) & 0x01);
							else if ((pSearch[iIter1].pWildcards[iIter2].ucMaskVariable1 >> iIter3) & 0x01)
							{
								if (0 == iVariable1WasPrinted)
								{
									printf("%c", pSearch[iIter1].pWildcards[iIter2].cVariableName1 + 'A');
									iVariable1WasPrinted = 1;
								}
								else
									printf("?");
							}
							else if ((pSearch[iIter1].pWildcards[iIter2].ucMaskVariable2 >> iIter3) & 0x01)
							{
								if (0 == iVariable2WasPrinted)
								{
									printf("%c", pSearch[iIter1].pWildcards[iIter2].cVariableName2 + 'A');
									iVariable2WasPrinted = 1;
								}
								else
									printf("?");
							}
							else
								printf("?");
						printf(")");
						break;
					case WILDCARD_MODE_JUMP:
						printf("(J;%d)", pSearch[iIter1].pWildcards[iIter2].ucJumpBytes);
						break;
				}
		}
		printf("\n");
	}
}

int ReadFile(char *pcArgFile, off_t *potFileSize, void **ppBuffer)
{
	struct stat statFile;
	FILE *fIn;
	off_t otSizeRead;
	void *pBufferRealloc;

  if (!strcmp(pcArgFile, "-"))
  {

#ifdef _WIN32
		_setmode(_fileno(stdin), _O_BINARY);
#else
		freopen(NULL, "rb", stdin);
#endif

		*potFileSize = 100 * 1024 * 1024;
		if ((*ppBuffer = malloc(*potFileSize)) == NULL)
		{
			fprintf(stderr, "memory allocation failed\n");
			return -1;
		}
		otSizeRead = fread(*ppBuffer, 1, *potFileSize, stdin);
		if (0 == otSizeRead)
		{
			fprintf(stderr, "stdin is empty %d\n", ferror(stdin));
  		free(*ppBuffer);
			return -1;
		}
#ifndef __WINNT__
		fprintf(stderr, "Number of bytes read from stdin: %lld\n", otSizeRead);
#else
		fprintf(stderr, "Number of bytes read from stdin: %ld\n", otSizeRead);
#endif
		pBufferRealloc = realloc(*ppBuffer, otSizeRead);
		if (NULL == pBufferRealloc)
		{
			fprintf(stderr, "memory reallocation failed\n");
  		free(*ppBuffer);
			return -1;
		}
		*potFileSize = otSizeRead;
		*ppBuffer = pBufferRealloc;
  }
  else
	{
		if (stat(pcArgFile, &statFile) != 0)
		{
			fprintf(stderr, "error opening file %s\n", pcArgFile);
			return -1;
		}

		*potFileSize = statFile.st_size;
		if (*potFileSize == 0)
		{
			fprintf(stderr, "file %s is empty\n", pcArgFile);
			return -1;
		}
		if ((*ppBuffer = malloc(*potFileSize)) == NULL)
		{
#ifndef __WINNT__
			fprintf(stderr, "file %s is too large %lld\n", pcArgFile, *potFileSize);
#else
			fprintf(stderr, "file %s is too large %ld\n", pcArgFile, *potFileSize);
#endif
			return -1;
		}

		if ((fIn = fopen(pcArgFile, "rb")) == NULL)
		{
			fprintf(stderr, "error opening file %s\n", pcArgFile);
			free(*ppBuffer);
			return -1;
		}
		if (fread(*ppBuffer, *potFileSize, 1, fIn) != 1)
		{
			fprintf(stderr, "error reading file %s\n", pcArgFile);
			fclose(fIn);
			free(*ppBuffer);
			return -1;
		}
		fclose(fIn);
	}

	return 0;
}

int IsWhitespace(char cHexDigit)
{
	return (cHexDigit >= 0x09 && cHexDigit <= 0x0D) || (cHexDigit == 0x20);
}

int ReadHexFile(char *pcArgFile, off_t *potFileSize, void **ppBuffer)
{
	FILE *fIn;
	int iChar;
	int iFirstNibble;
	int iCountCharacters;
	off_t otBufferSize;
	void *pBuffer;

	otBufferSize = 1024*1024;
	if ((*ppBuffer = malloc(otBufferSize)) == NULL)
	{
		fprintf(stderr, "file %s is too large\n", pcArgFile);
		return -1;
	}

	if ((fIn = fopen(pcArgFile, "r")) == NULL)
	{
		fprintf(stderr, "error opening file %s\n", pcArgFile);
		free(*ppBuffer);
		return -1;
	}

	iFirstNibble = -1;
	*potFileSize = 0;
	iCountCharacters = 0;
	do
	{
		if (EOF != (iChar = fgetc(fIn)) && !IsWhitespace(iChar))
		{
			iCountCharacters++;
			if (IsHexDigit(iChar))
			{
				if (-1 == iFirstNibble)
					iFirstNibble = HexDigitToNibble(iChar);
				else
				{
					if (*potFileSize < otBufferSize)
					{
						*((char *)(*ppBuffer) + *potFileSize) = iFirstNibble * 0x10 + HexDigitToNibble(iChar);
						(*potFileSize)++;
						iFirstNibble = -1;
					}
					else
					{
						otBufferSize = otBufferSize + 1024*1024;
						pBuffer = realloc(*ppBuffer, otBufferSize);
						if (NULL == pBuffer)
						{
							fprintf(stderr, "file %s is too large\n", pcArgFile);
							free(*ppBuffer);
							fclose(fIn);
							return -1;
						}
						*ppBuffer = pBuffer;
						*((char *)(*ppBuffer) + *potFileSize) = iFirstNibble * 0x10 + HexDigitToNibble(iChar);
						(*potFileSize)++;
						iFirstNibble = -1;
					}
				}
			}
			else
			{
				fprintf(stderr, "file %s contains unexpected character at 0x%X (not hex digit and not whitespace): 0x%02X\n", pcArgFile, iCountCharacters, iChar);
				free(*ppBuffer);
				fclose(fIn);
				return -1;
			}
		}
	} while (EOF != iChar);
	fclose(fIn);

	if (-1 != iFirstNibble)
	{
		fprintf(stderr, "file %s contains uneven number of hex digits\n", pcArgFile);
		free(*ppBuffer);
		return -1;
	}

	if (*potFileSize == 0)
	{
		fprintf(stderr, "file %s is empty\n", pcArgFile);
		free(*ppBuffer);
		return -1;
	}

	return 0;
}

void StringsPrint(const unsigned char *pucBuffer, long lSize, int iMinimumStringLength)
{
	long lIter;
	long lIter2;
	long lStringStartASCII = -1;
	long lStringStartUNILE = -1;
	long lStringFoundBeginUNILE = -1;
	long lStringFoundEndUNILE = -1;
	long lStringStartUNIBE = -1;
	long lStringFoundBeginUNIBE = -1;
	long lStringFoundEndUNIBE = -1;
	unsigned char ucByte;
	unsigned char ucPrintable;

	for (lIter = 0; lIter < lSize + 2; lIter++)
	{
		if (lIter >= lSize)
			ucByte = 0;
		else
			ucByte = pucBuffer[lIter];
		ucPrintable = ucByte >= 0x20 && ucByte <= 0x7E;

		if (ucPrintable)
		{
			if (lStringStartASCII == -1)
				lStringStartASCII = lIter;
		}
		else if (lStringStartASCII != -1)
		{
			if (lIter - lStringStartASCII >= iMinimumStringLength)
				printf("%.*s\n", (int)(lIter - lStringStartASCII), pucBuffer + lStringStartASCII);
			lStringStartASCII = -1;
		}

		if (lStringStartUNILE == -1)
		{
			if (ucPrintable)
				lStringStartUNILE = lIter;
		}
		else if ((lIter - lStringStartUNILE) & 0x01)
		{
			if (ucByte != 0)
			{
				if (lIter - lStringStartUNILE - 2 >= iMinimumStringLength * 2)
				{
					lStringFoundBeginUNILE = lStringStartUNILE;
					lStringFoundEndUNILE = lIter - 3;
				}
				lStringStartUNILE = -1;
			}
		}
		else
		{
			if (!ucPrintable)
			{
				if (lIter - lStringStartUNILE - 1 >= iMinimumStringLength * 2)
				{
					lStringFoundBeginUNILE = lStringStartUNILE;
					lStringFoundEndUNILE = lIter - 2;
				}
				lStringStartUNILE = -1;
			}
		}

		if (lStringStartUNIBE == -1)
		{
			if (ucByte == 0)
				lStringStartUNIBE = lIter;
		}
		else if ((lIter - lStringStartUNIBE) & 0x01)
		{
			if (!ucPrintable)
			{
				if (lIter - lStringStartUNIBE - 2 >= iMinimumStringLength * 2)
				{
					lStringFoundBeginUNIBE = lStringStartUNIBE + 1;
					lStringFoundEndUNIBE = lIter - 2;
				}
				lStringStartUNIBE = -1;
			}
		}
		else
		{
			if (ucByte != 0)
			{
				if (lIter - lStringStartUNIBE - 1 >= iMinimumStringLength * 2)
				{
					lStringFoundBeginUNIBE = lStringStartUNIBE + 1;
					lStringFoundEndUNIBE = lIter - 3;
				}
				lStringStartUNIBE = -1;
			}
		}

		if (lStringFoundBeginUNIBE != -1 && lStringFoundBeginUNILE != -1)
		{
			if (lStringFoundEndUNILE - lStringFoundBeginUNILE >= lStringFoundEndUNIBE - lStringFoundBeginUNIBE)
			{
					for (lIter2 = lStringFoundBeginUNILE; lIter2 <= lStringFoundEndUNILE; lIter2 += 2)
						putchar(pucBuffer[lIter2]);
					putchar('\n');
			}
			else
			{
					for (lIter2 = lStringFoundBeginUNIBE; lIter2 <= lStringFoundEndUNIBE; lIter2 += 2)
						putchar(pucBuffer[lIter2]);
					putchar('\n');
			}
			lStringFoundBeginUNILE = -1;
			lStringFoundEndUNILE = -1;
			lStringFoundBeginUNIBE = -1;
			lStringFoundEndUNIBE = -1;
		}

		if (lStringFoundBeginUNILE != -1)
		{
			for (lIter2 = lStringFoundBeginUNILE; lIter2 <= lStringFoundEndUNILE; lIter2 += 2)
				putchar(pucBuffer[lIter2]);
			putchar('\n');
			lStringFoundBeginUNILE = -1;
			lStringFoundEndUNILE = -1;
		}

		if (lStringFoundBeginUNIBE != -1)
		{
			for (lIter2 = lStringFoundBeginUNIBE; lIter2 <= lStringFoundEndUNIBE; lIter2 += 2)
				putchar(pucBuffer[lIter2]);
			putchar('\n');
			lStringFoundBeginUNIBE = -1;
			lStringFoundEndUNIBE = -1;
		}
	}
}

int main(int argc, char **argv)
{
	struct stat statFile;
	void *pBuffer;
	void *pBufferCopy;
	unsigned char ucOPRIter;
	char *pcArgFile;
	char *pcArgSearch;
	char *pcArgSearchFile;
	char *pcSearch;
	char *pcDisable;
	int iFlagSave;
	int iFlagIgnoreCase;
	int iMaxLength;
	int iCountFinds;
	int iFound;
	int iFlagUnicode;
	int iSearchLength;
	NUMBER sNUMBERNeighbourLength;
	sNUMBERNeighbourLength.uiNumberType = NUMBER_UNDEFINED;
	sNUMBERNeighbourLength.iNumberValue = 0;
	int iFlagHex;
	int iFlagKeys;
	int iFlagPEFile;
	int iSearchType;
	int iExcludeByte;
	int iFlagWildcard;
	int iFlagWildcardEmbedded;
	int iFlagList;
	int iFlagHexFile;
	int iFlagReverse;
	int iFlagStrings;
	unsigned int *pui32bitKeys;
	unsigned int uiSize32bitKeys;
	unsigned int uiCount32bitKeys;
	unsigned int uiIter32bitKeys;
	int iIterBuffer;
	int iScore;
	union
	{
		unsigned int uiKey;
		unsigned char ucKey[4];
	} uk1, uk2;
	SEARCH *pSearch;
	int iFoundSomething;
	off_t otFileSize;
	int iResult;

	if (ParseArgs(argc, argv, &iFlagSave, &iMaxLength, &iFlagIgnoreCase, &pcArgFile, &pcArgSearch, &pcArgSearchFile, &iFlagUnicode, &sNUMBERNeighbourLength, &iFlagHex, &iFlagKeys, &iFlagPEFile, &iExcludeByte, &iFlagWildcard, &iFlagWildcardEmbedded, &pcDisable, &iFlagList, &iFlagHexFile, &iFlagReverse, &iFlagStrings))
	{
		fprintf(stderr, "Usage: XORSearch [-siuhkpwWLxrS] [-l length] [-n [-+]length] [-f search-file] [-e byte] [-d encodings] file [string|hex|rule]\n"
										"XORSearch V1.11.4, search for a XOR, ROL, ROT, SHIFT or ADD encoded string in a file\n"
										"Use filename - to read from stdin\n"
										"Use -x when the file to search is a hexdump\n"
										"Use -s to save the XOR, ROL, ROT, SHIFT or ADD encoded file containing the string\n"
										"Use -l length to limit the number of printed characters (50 by default, 38 with option -p)\n"
										"Use -i to ignore the case when searching\n"
										"Use -u to search for Unicode strings (limited support)\n"
										"Use -r to reverse the file before searching\n"
										"Use -f to provide a file with search strings\n"
										"Use -n [-+]length to print neighbouring characters (before & after the found keyword)\n"
										"Use -h to search for hex strings\n"
										"Use -k to decode with embedded keys\n"
										"Use -S to print all strings\n"
										"Use -p to search for PE-files\n"
										"Use -w to search with wildcards\n"
										"Use -W to search with embedded wildcards\n"
										"Use -L to list embedded wildcards\n"
										"Use -e to exclude a particular byte-value from encoding\n"
										"Use -d to disable encoding(s) 1: XOR 2: ROL 3: ROT 4: SHIFT 5: ADD\n"
										"Options -l and -n are mutually exclusive\n"
										"Options -u and -h are mutually exclusive\n"
										"Options -k and -e are mutually exclusive\n"
										"Option -p is not compatible with options -i, -u, -h, -n and -r\n"
										"When using -p, do not provide a search string or use -f\n"
										"When using -W, do not provide a search string or use -f\n"
										"Use option -L without arguments or other options\n"
										"Source code put in the public domain by Didier Stevens, no Copyright\n"
										"Use at your own risk\n"
										"https://DidierStevens.com\n");
		return -1;
	}
	if (iMaxLength == -1)
	{
		if (iFlagPEFile)
			iMaxLength = 38;
		else
			iMaxLength = 50;
	}

	if (iFlagList)
	{
		pSearch = InitializeSearch(NULL, NULL, 1);
		if (NULL == pSearch)
		{
			fprintf(stderr, "Error: parsing rule\n");
			return -1;
		}

		List(pSearch);

		return 0;
	}

	if (iFlagUnicode)
		iSearchType = SEARCHTYPE_UNICODE;
	else if (iFlagHex)
		iSearchType = SEARCHTYPE_HEX;
	else if (iFlagWildcard || iFlagWildcardEmbedded)
		iSearchType = SEARCHTYPE_WILDCARD;
	else
		iSearchType = SEARCHTYPE_ASCII;

	if (iFlagWildcard || iFlagWildcardEmbedded)
	{
		pSearch = InitializeSearch(pcArgSearch, pcArgSearchFile, iFlagWildcardEmbedded);
		if (NULL == pSearch)
		{
			fprintf(stderr, "Error: parsing rule\n");
			return -1;
		}
	}

	if (strlen(pcArgFile) >= XSIZE-1)
	{
		fprintf(stderr, "Error: filename is too long\n");
		return -1;
	}

	if (pcArgSearchFile != NULL)
	{
		if (stat(pcArgSearchFile, &statFile) != 0)
		{
			fprintf(stderr, "error opening file %s\n", pcArgSearchFile);
			return -1;
		}
	}
	else if (pcArgSearch != NULL && strlen(pcArgSearch) >= XSIZE-2)
	{
		fprintf(stderr, "Error: search string is too long\n");
		return -1;
	}

	if (iFlagHexFile)
		iResult = ReadHexFile(pcArgFile, &otFileSize, &pBuffer);
	else
		iResult = ReadFile(pcArgFile, &otFileSize, &pBuffer);
	if (0 != iResult)
		return iResult;

	if (iFlagReverse)
	{
		char *pchrFirst, *pchrSecond;
		char chrTmp;

		pchrFirst = (char *) pBuffer;
		pchrSecond = pchrFirst + otFileSize - 1;

		while (pchrSecond > pchrFirst)
		{
			chrTmp = *pchrFirst;
			*pchrFirst++ = *pchrSecond;
			*pchrSecond-- = chrTmp;
		}
	}

	if ((pBufferCopy = malloc(otFileSize)) == NULL)
	{
#ifndef __WINNT__
		fprintf(stderr, "file %s is too large %lld\n", pcArgFile, otFileSize);
#else
		fprintf(stderr, "file %s is too large %ld\n", pcArgFile, otFileSize);
#endif
		free(pBuffer);
		return -1;
	}
	memcpy(pBufferCopy, pBuffer, otFileSize);

	if (iFlagKeys && otFileSize < 4)
	{
		fprintf(stderr, "file %s is too small for option -k\n", pcArgFile);
		free(pBuffer);
		free(pBufferCopy);
		return -1;
	}

	pui32bitKeys = NULL;
	uiSize32bitKeys = (otFileSize - 3) * 2;
	if (iFlagKeys)
		if ((pui32bitKeys = malloc(uiSize32bitKeys * sizeof(unsigned int))) == NULL)
		{
#ifndef __WINNT__
			fprintf(stderr, "file %s is too large for copy %lld\n", pcArgFile, otFileSize);
#else
			fprintf(stderr, "file %s is too large for copy %ld\n", pcArgFile, otFileSize);
#endif
			uiSize32bitKeys = 0;
		}

	if (NULL != pui32bitKeys)
	{
		uiCount32bitKeys = 0;
		for (iIterBuffer = 0; iIterBuffer < otFileSize - 3; iIterBuffer++)
		{
			uk1.uiKey = *(unsigned int *)((unsigned char *)pBuffer + iIterBuffer);
			if (!(uk1.ucKey[0] == uk1.ucKey[1] && uk1.ucKey[0] == uk1.ucKey[2] && uk1.ucKey[0] == uk1.ucKey[3]))
			{
				InsertSorted(uk1.uiKey, pui32bitKeys, uiSize32bitKeys, &uiCount32bitKeys);
				uk2.ucKey[3] = uk1.ucKey[0];
				uk2.ucKey[2] = uk1.ucKey[1];
				uk2.ucKey[1] = uk1.ucKey[2];
				uk2.ucKey[0] = uk1.ucKey[3];
				InsertSorted(uk2.uiKey, pui32bitKeys, uiSize32bitKeys, &uiCount32bitKeys);
			}
		}
	}

	if ((piFoundIndex = (int *)malloc(otFileSize * sizeof(int))) == NULL)
	{
#ifndef __WINNT__
		fprintf(stderr, "file %s is too large %lld\n", pcArgFile, otFileSize);
#else
		fprintf(stderr, "file %s is too large %ld\n", pcArgFile, otFileSize);
#endif
		free(pBuffer);
		free(pBufferCopy);
		if (NULL != pui32bitKeys)
			free(pui32bitKeys);
		return -1;
	}

	if ((piFoundSize = (int *)malloc(otFileSize * sizeof(int))) == NULL)
	{
#ifndef __WINNT__
		fprintf(stderr, "file %s is too large %lld\n", pcArgFile, otFileSize);
#else
		fprintf(stderr, "file %s is too large %ld\n", pcArgFile, otFileSize);
#endif
		free(pBuffer);
		free(pBufferCopy);
		if (NULL != pui32bitKeys)
			free(pui32bitKeys);
		free(piFoundIndex);
		return -1;
	}

	iFoundSomething = 0;
	iScore = 0;
	if (iFlagKeys)
	{
		printf("Testing %d keys\n", uiCount32bitKeys);
		for (uiIter32bitKeys = 0; uiIter32bitKeys < uiCount32bitKeys; uiIter32bitKeys++)
		{
			for (ucOPRIter = 0; ucOPRIter < 4; ucOPRIter++)
			{
				XOR32(pBuffer, otFileSize, ucOPRIter, pui32bitKeys[uiIter32bitKeys]);

				iFound = 0;
				if (iFlagPEFile)
					iFound = SearchForPEFile((unsigned char *)pBuffer, otFileSize, OPR_XOR32, ucOPRIter, pui32bitKeys[uiIter32bitKeys], iMaxLength);
				else if (iFlagStrings)
					StringsPrint((unsigned char *)pBuffer, otFileSize, 4);
				else if (iSearchType == SEARCHTYPE_WILDCARD)
					iFound = WildcardSearches(pSearch, pBuffer, otFileSize, OPR_XOR32, 0, ucOPRIter, iMaxLength, &iScore);
				else
					do
					{
						pcSearch = GetSearchString(pcArgSearch, pcArgSearchFile, iSearchType, &iSearchLength);
						if (pcSearch && iSearchLength > 0)
						{
							iCountFinds = KMP(pcSearch, iSearchLength, pBuffer, otFileSize, iFlagIgnoreCase);
							if (iCountFinds > 0)
							{
								PrintFinds(iCountFinds, iMaxLength, OPR_XOR32, ucOPRIter, pui32bitKeys[uiIter32bitKeys], otFileSize, pBuffer, iSearchType, &sNUMBERNeighbourLength);
								iFound = 1;
							}
						}
					} while (pcSearch);

				if (iFound && iFlagSave)
					SaveFile(pcArgFile, OPR_XOR32, pui32bitKeys[uiIter32bitKeys], pBuffer, otFileSize);

				iFoundSomething |= iFound;

				memcpy(pBuffer, pBufferCopy, otFileSize);
			}
		}
	}
	else
	{
		ucOPRIter = 0;

		if (NULL == pcDisable || !strchr(pcDisable, '1'))
		{
			do
			{
				XOR((unsigned char *) pBuffer, otFileSize, ucOPRIter, iExcludeByte);

				iFound = 0;
				if (iFlagPEFile)
					iFound = SearchForPEFile((unsigned char *)pBuffer, otFileSize, OPR_XOR, 0, ucOPRIter, iMaxLength);
				else if (iFlagStrings)
					StringsPrint((unsigned char *)pBuffer, otFileSize, 4);
				else if (iSearchType == SEARCHTYPE_WILDCARD)
					iFound = WildcardSearches(pSearch, pBuffer, otFileSize, OPR_XOR, 0, ucOPRIter, iMaxLength, &iScore);
				else
					do
					{
						pcSearch = GetSearchString(pcArgSearch, pcArgSearchFile, iSearchType, &iSearchLength);
						if (pcSearch && iSearchLength > 0)
						{
							iCountFinds = KMP(pcSearch, iSearchLength, pBuffer, otFileSize, iFlagIgnoreCase);
							if (iCountFinds > 0)
							{
								PrintFinds(iCountFinds, iMaxLength, OPR_XOR, 0, ucOPRIter, otFileSize, pBuffer, iSearchType, &sNUMBERNeighbourLength);
								iFound = 1;
							}
						}
					} while (pcSearch);

				if (iFound && iFlagSave)
					SaveFile(pcArgFile, OPR_XOR, ucOPRIter, pBuffer, otFileSize);

				iFoundSomething |= iFound;

				memcpy(pBuffer, pBufferCopy, otFileSize);
			} while (++ucOPRIter);
		}

		if (NULL == pcDisable || !strchr(pcDisable, '2'))
		{
			for (ucOPRIter = 1; ucOPRIter < 8; ucOPRIter++)
			{
				ROL((unsigned char *) pBuffer, otFileSize, iExcludeByte);

				iFound = 0;
				if (iFlagPEFile)
					iFound = SearchForPEFile((unsigned char *)pBuffer, otFileSize, OPR_ROL, 0, ucOPRIter, iMaxLength);
				else if (iFlagStrings)
					StringsPrint((unsigned char *)pBuffer, otFileSize, 4);
				else if (iSearchType == SEARCHTYPE_WILDCARD)
					iFound = WildcardSearches(pSearch, pBuffer, otFileSize, OPR_ROL, 0, ucOPRIter, iMaxLength, &iScore);
				else
					do
					{
						pcSearch = GetSearchString(pcArgSearch, pcArgSearchFile, iSearchType, &iSearchLength);
						if (pcSearch && iSearchLength > 0)
						{
							iCountFinds = KMP(pcSearch, iSearchLength, pBuffer, otFileSize, iFlagIgnoreCase);
							if (iCountFinds > 0)
							{
								PrintFinds(iCountFinds, iMaxLength, OPR_ROL, 0, ucOPRIter, otFileSize, pBuffer, iSearchType, &sNUMBERNeighbourLength);
								iFound = 1;
							}
						}
					} while (pcSearch);

				if (iFound && iFlagSave)
					SaveFile(pcArgFile, OPR_ROL, ucOPRIter, pBuffer, otFileSize);

				iFoundSomething |= iFound;
			}
			memcpy(pBuffer, pBufferCopy, otFileSize);
		}

		if (NULL == pcDisable || !strchr(pcDisable, '3'))
		{
			for (ucOPRIter = 25; ucOPRIter >= 1; ucOPRIter--)
			{
				ROT((unsigned char *) pBuffer, otFileSize, iExcludeByte);

				iFound = 0;
				if (iFlagPEFile)
					iFound = SearchForPEFile((unsigned char *)pBuffer, otFileSize, OPR_ROT, 0, ucOPRIter, iMaxLength);
				else if (iFlagStrings)
					StringsPrint((unsigned char *)pBuffer, otFileSize, 4);
				else if (iSearchType == SEARCHTYPE_WILDCARD)
					iFound = WildcardSearches(pSearch, pBuffer, otFileSize, OPR_ROT, 0, ucOPRIter, iMaxLength, &iScore);
				else
					do
					{
						pcSearch = GetSearchString(pcArgSearch, pcArgSearchFile, iSearchType, &iSearchLength);
						if (pcSearch && iSearchLength > 0)
						{
							iCountFinds = KMP(pcSearch, iSearchLength, pBuffer, otFileSize, iFlagIgnoreCase);
							if (iCountFinds > 0)
							{
								PrintFinds(iCountFinds, iMaxLength, OPR_ROT, 0, ucOPRIter, otFileSize, pBuffer, iSearchType, &sNUMBERNeighbourLength);
								iFound = 1;
							}
						}
					} while (pcSearch);

				if (iFound && iFlagSave)
					SaveFile(pcArgFile, OPR_ROT, ucOPRIter, pBuffer, otFileSize);

				iFoundSomething |= iFound;
			}
			memcpy(pBuffer, pBufferCopy, otFileSize);
		}

		if (NULL == pcDisable || !strchr(pcDisable, '4'))
		{
			for (ucOPRIter = 1; ucOPRIter < 8; ucOPRIter++)
			{
				SHIFT((unsigned char *) pBuffer, otFileSize, iExcludeByte);

				iFound = 0;
				if (iFlagPEFile)
					iFound = SearchForPEFile((unsigned char *)pBuffer, otFileSize, OPR_SHIFT, 0, ucOPRIter, iMaxLength);
				else if (iFlagStrings)
					StringsPrint((unsigned char *)pBuffer, otFileSize, 4);
				else if (iSearchType == SEARCHTYPE_WILDCARD)
					iFound = WildcardSearches(pSearch, pBuffer, otFileSize, OPR_SHIFT, 0, ucOPRIter, iMaxLength, &iScore);
				else
					do
					{
						pcSearch = GetSearchString(pcArgSearch, pcArgSearchFile, iSearchType, &iSearchLength);
						if (pcSearch && iSearchLength > 0)
						{
							iCountFinds = KMP(pcSearch, iSearchLength, pBuffer, otFileSize, iFlagIgnoreCase);
							if (iCountFinds > 0)
							{
								PrintFinds(iCountFinds, iMaxLength, OPR_SHIFT, 0, ucOPRIter, otFileSize, pBuffer, iSearchType, &sNUMBERNeighbourLength);
								iFound = 1;
							}
						}
					} while (pcSearch);

				if (iFound && iFlagSave)
					SaveFile(pcArgFile, OPR_SHIFT, ucOPRIter, pBuffer, otFileSize);

				iFoundSomething |= iFound;
			}
			memcpy(pBuffer, pBufferCopy, otFileSize);
		}

		if (NULL == pcDisable || !strchr(pcDisable, '5'))
		{
			ucOPRIter = 1;
			do
			{
				ADD((unsigned char *) pBuffer, otFileSize, iExcludeByte);

				iFound = 0;
				if (iFlagPEFile)
					iFound = SearchForPEFile((unsigned char *)pBuffer, otFileSize, OPR_ADD, 0, ucOPRIter, iMaxLength);
				else if (iFlagStrings)
					StringsPrint((unsigned char *)pBuffer, otFileSize, 4);
				else if (iSearchType == SEARCHTYPE_WILDCARD)
					iFound = WildcardSearches(pSearch, pBuffer, otFileSize, OPR_ADD, 0, ucOPRIter, iMaxLength, &iScore);
				else
					do
					{
						pcSearch = GetSearchString(pcArgSearch, pcArgSearchFile, iSearchType, &iSearchLength);
						if (pcSearch && iSearchLength > 0)
						{
							iCountFinds = KMP(pcSearch, iSearchLength, pBuffer, otFileSize, iFlagIgnoreCase);
							if (iCountFinds > 0)
							{
								PrintFinds(iCountFinds, iMaxLength, OPR_ADD, 0, ucOPRIter, otFileSize, pBuffer, iSearchType, &sNUMBERNeighbourLength);
								iFound = 1;
							}
						}
					} while (pcSearch);

				if (iFound && iFlagSave)
					SaveFile(pcArgFile, OPR_ADD, ucOPRIter, pBuffer, otFileSize);

				iFoundSomething |= iFound;
			} while (++ucOPRIter);
		}
	}

	free(pBuffer);
	free(pBufferCopy);
	if (NULL != pui32bitKeys)
		free(pui32bitKeys);
	free(piFoundIndex);
	free(piFoundSize);

	if (iSearchType == SEARCHTYPE_WILDCARD)
	{
		printf("Score: %d\n", iScore);
		return iScore;
	}
	else
		return iFoundSomething ? 0 : 1;
}
