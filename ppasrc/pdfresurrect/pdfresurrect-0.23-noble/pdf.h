/******************************************************************************
 * pdf.h
 *
 * pdfresurrect - PDF history extraction tool
 *
 * See https://github.com/enferex/pdfresurrect/blob/master/LICENSE for license
 * information.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Special thanks to all of the contributors:  See AUTHORS.
 * Special thanks to 757labs (757 crew), they are a great group
 * of people to hack on projects and brainstorm with.
 *****************************************************************************/

#ifndef PDF_H_INCLUDE
#define PDF_H_INCLUDE

#include <stdio.h>


/* Bit-maskable flags */
typedef unsigned short pdf_flag_t;
#define PDF_FLAG_NONE         0
#define PDF_FLAG_QUIET        1
#define PDF_FLAG_DISP_CREATOR 2


/* Generic key/value structure */
#define KV_MAX_KEY_LENGTH   32
#define KV_MAX_VALUE_LENGTH 128
typedef struct _kv_t
{
    char key[KV_MAX_KEY_LENGTH];
    char value[KV_MAX_VALUE_LENGTH];
} kv_t;


/* Information about who/what created the PDF
 * From 1.7 Spec for non-metadata entries
 */
typedef kv_t pdf_creator_t;


typedef struct _xref_entry
{
    int obj_id;
    long offset;
    int gen_num;
    char f_or_n;
} xref_entry_t;


typedef struct _xref_t
{
    long start;
    long end;

    /* Array of metadata about the pdf */
    pdf_creator_t *creator;
    int n_creator_entries;

    int n_entries;
    xref_entry_t *entries;


    /* PDF 1.5 or greater: xref can be encoded as a stream */
    int is_stream;

    /* If the PDF is linear multiple xrefs make up one single version */
    int is_linear;

    /* Version of the document this xref belongs */
    int version;
} xref_t;


typedef struct _pdf_t
{
    char  *name;
    short  pdf_major_version;
    short  pdf_minor_version;

    int     n_xrefs;
    xref_t *xrefs;

    /* PDF 1.5 or greater: xref can be encoded as a stream */
    int has_xref_streams;
} pdf_t;


extern pdf_t *pdf_new(const char *name);
extern void pdf_delete(pdf_t *pdf);

extern int pdf_is_pdf(FILE *fp);
extern void pdf_get_version(FILE *fp, pdf_t *pdf);

extern int pdf_load_xrefs(FILE *fp, pdf_t *pdf);

extern char pdf_get_object_status(
    const pdf_t *pdf,
    int          xref_idx,
    int          entry_idx);

extern void pdf_zero_object(
    FILE        *fp,
    const pdf_t *pdf,
    int          xref_idx,
    int          entry_idx);

extern void pdf_summarize(
    FILE        *fp,
    const pdf_t *pdf,
    const char  *name,
    pdf_flag_t   flags);

/* Returns '1' if we successfully display data (means its probably not xml) */
extern int pdf_display_creator(const pdf_t *pdf, int xref_idx);


#endif /* PDF_H_INCLUDE */
