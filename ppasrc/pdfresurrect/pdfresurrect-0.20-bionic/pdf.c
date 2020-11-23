/******************************************************************************
 * pdf.c 
 *
 * pdfresurrect - PDF history extraction tool
 *
 * Copyright (C) 2008-2010, 2012-2013, 2017-20, Matt Davis (enferex).
 *
 * Special thanks to all of the contributors:  See AUTHORS.
 *
 * Special thanks to 757labs (757 crew), they are a great group
 * of people to hack on projects and brainstorm with.
 *
 * pdf.c is part of pdfresurrect.
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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "pdf.h"
#include "main.h"


/* 
 * Macros
 */

/* SAFE_F
 *
 * Safe file read: use for fgetc() calls, this is really ugly looking. 
 * _fp:   FILE * handle
 * _expr: The expression with fgetc() in it:
 * 
 *  example: If we get a character from the file and it is ascii character 'a'
 *           This assumes the coder wants to store the 'a' in variable ch
 *           Kinda pointless if you already know that you have 'a', but for
 *           illustrative purposes.
 *
 *  if (SAFE_F(my_fp, ((c=fgetc(my_fp)) == 'a')))
 *              do_way_cool_stuff();
 */
#define SAFE_F(_fp, _expr) \
    ((!ferror(_fp) && !feof(_fp) && (_expr)))


/* FAIL
 *
 * Emit the diagnostic '_msg' and exit.
 * _msg: Message to emit prior to exiting.
 */
#define FAIL(_msg)      \
  do {                  \
    ERR(_msg);          \
    exit(EXIT_FAILURE); \
  } while (0)


/* SAFE_E
 *
 * Safe expression handling.  This macro is a wrapper
 * that compares the result of an expression (_expr) to the expected
 * value (_cmp).
 *
 * _expr: Expression to test.
 * _cmp:  Expected value, error if this returns false.
 * _msg:  What to say when an error occurs.
 */
#define SAFE_E(_expr, _cmp, _msg) \
 do {                             \
    if ((_expr) != (_cmp)) {      \
      FAIL(_msg);                  \
    }                             \
  } while (0)


/*
 * Forwards
 */

static int is_valid_xref(FILE *fp, pdf_t *pdf, xref_t *xref);
static void load_xref_entries(FILE *fp, xref_t *xref);
static void load_xref_from_plaintext(FILE *fp, xref_t *xref);
static void load_xref_from_stream(FILE *fp, xref_t *xref);
static void get_xref_linear_skipped(FILE *fp, xref_t *xref);
static void resolve_linearized_pdf(pdf_t *pdf);

static pdf_creator_t *new_creator(int *n_elements);
static void load_creator(FILE *fp, pdf_t *pdf);
static void load_creator_from_buf(
    FILE       *fp,
    xref_t     *xref,
    const char *buf,
    size_t      buf_size);
static void load_creator_from_xml(xref_t *xref, const char *buf);
static void load_creator_from_old_format(
    FILE       *fp,
    xref_t     *xref,
    const char *buf,
    size_t      buf_size);

static char *get_object_from_here(FILE *fp, size_t *size, int *is_stream);

static char *get_object(
    FILE         *fp,
    int           obj_id,
    const xref_t *xref,
    size_t       *size,
    int          *is_stream);

static void add_kid(int id, xref_t *xref);
static void load_kids(FILE *fp, int pages_id, xref_t *xref);

static const char *get_type(FILE *fp, int obj_id, const xref_t *xref);
/* static int get_page(int obj_id, const xref_t *xref); */
static char *get_header(FILE *fp);

static char *decode_text_string(const char *str, size_t str_len);
static int get_next_eof(FILE *fp);


/*
 * Defined
 */

pdf_t *pdf_new(const char *name)
{
    const char *n;
    pdf_t      *pdf;
   
    pdf = safe_calloc(sizeof(pdf_t));

    if (name)
    {
        /* Just get the file name (not path) */
        if ((n = strrchr(name, '/')))
          ++n;
        else
          n = name;

        pdf->name = safe_calloc(strlen(n) + 1);
        strcpy(pdf->name, n);
    }
    else /* !name */
    {
        pdf->name = safe_calloc(strlen("Unknown") + 1);
        strcpy(pdf->name, "Unknown");
    }

    return pdf;
}


void pdf_delete(pdf_t *pdf)
{
    int i;

    for (i=0; i<pdf->n_xrefs; i++)
    {
        free(pdf->xrefs[i].creator);
        free(pdf->xrefs[i].entries);
        free(pdf->xrefs[i].kids);
    }

    free(pdf->name);
    free(pdf->xrefs);
    free(pdf);
}


int pdf_is_pdf(FILE *fp)
{
    int   is_pdf;
    char *header;

    header = get_header(fp);

    if (header && strstr(header, "%PDF-"))
      is_pdf = 1;
    else 
      is_pdf = 0;

    free(header);
    return is_pdf;
}


void pdf_get_version(FILE *fp, pdf_t *pdf)
{
    char *header, *c;

    header = get_header(fp);

    /* Locate version string start and make sure we dont go past header */
    if ((c = strstr(header, "%PDF-")) && 
        (c + strlen("%PDF-M.m") + 2))
    {
        pdf->pdf_major_version = atoi(c + strlen("%PDF-"));
        pdf->pdf_minor_version = atoi(c + strlen("%PDF-M."));
    }

    free(header);
}


int pdf_load_xrefs(FILE *fp, pdf_t *pdf)
{
    int  i, ver, is_linear;
    long pos, pos_count;
    char x, *c, buf[256];
    
    c = NULL;

    /* Count number of xrefs */
    pdf->n_xrefs = 0;
    fseek(fp, 0, SEEK_SET);
    while (get_next_eof(fp) >= 0)
      ++pdf->n_xrefs;

    if (!pdf->n_xrefs)
      return 0;

    /* Load in the start/end positions */
    fseek(fp, 0, SEEK_SET);
    pdf->xrefs = safe_calloc(sizeof(xref_t) * pdf->n_xrefs);
    ver = 1;
    for (i=0; i<pdf->n_xrefs; i++)
    {
        /* Seek to %%EOF */
        if ((pos = get_next_eof(fp)) < 0)
          break;

        /* Set and increment the version */
        pdf->xrefs[i].version = ver++;

        /* Rewind until we find end of "startxref" */
        pos_count = 0;
        while (SAFE_F(fp, ((x = fgetc(fp)) != 'f')))
          fseek(fp, pos - (++pos_count), SEEK_SET);
        
        /* Suck in end of "startxref" to start of %%EOF */
        if (pos_count >= sizeof(buf)) {
          FAIL("Failed to locate the startxref token. "
              "This might be a corrupt PDF.\n");
        }
        memset(buf, 0, sizeof(buf));
        SAFE_E(fread(buf, 1, pos_count, fp), pos_count,
               "Failed to read startxref.\n");
        c = buf;
        while (*c == ' ' || *c == '\n' || *c == '\r')
          ++c;
    
        /* xref start position */
        pdf->xrefs[i].start = atol(c);

        /* If xref is 0 handle linear xref table */
        if (pdf->xrefs[i].start == 0)
          get_xref_linear_skipped(fp, &pdf->xrefs[i]);

        /* Non-linear, normal operation, so just find the end of the xref */
        else
        {
            /* xref end position */
            pos = ftell(fp);
            fseek(fp, pdf->xrefs[i].start, SEEK_SET);
            pdf->xrefs[i].end = get_next_eof(fp);

            /* Look for next EOF and xref data */
            fseek(fp, pos, SEEK_SET);
        }

        /* Check validity */
        if (!is_valid_xref(fp, pdf, &pdf->xrefs[i]))
        {
            is_linear = pdf->xrefs[i].is_linear;
            memset(&pdf->xrefs[i], 0, sizeof(xref_t));
            pdf->xrefs[i].is_linear = is_linear;
            rewind(fp);
            get_next_eof(fp);
            continue;
        }

        /*  Load the entries from the xref */
        load_xref_entries(fp, &pdf->xrefs[i]);
    }

    /* Now we have all xref tables, if this is linearized, we need
     * to make adjustments so that things spit out properly
     */
    if (pdf->xrefs[0].is_linear)
      resolve_linearized_pdf(pdf);

    /* Ok now we have all xref data.  Go through those versions of the 
     * PDF and try to obtain creator information
     */
    load_creator(fp, pdf);

    return pdf->n_xrefs;
}


/* Load page information */
void pdf_load_pages_kids(FILE *fp, pdf_t *pdf)
{
    int     i, id, dummy;
    char   *buf, *c;
    long    start, sz;

    start = ftell(fp);

    /* Load all kids for all xref tables (versions) */
    for (i=0; i<pdf->n_xrefs; i++)
    {
        if (pdf->xrefs[i].version && (pdf->xrefs[i].end != 0))
        {
            fseek(fp, pdf->xrefs[i].start, SEEK_SET);
            while (SAFE_F(fp, (fgetc(fp) != 't')))
                ; /* Iterate to trailer */

            /* Get root catalog */
            sz = pdf->xrefs[i].end - ftell(fp);
            buf = safe_calloc(sz + 1);
            SAFE_E(fread(buf, 1, sz, fp), sz, "Failed to load /Root.\n");
            buf[sz] = '\0';
            if (!(c = strstr(buf, "/Root")))
            {
                free(buf);
                continue;
            }

            /* Jump to catalog (root) */
            id = atoi(c + strlen("/Root") + 1);
            free(buf);
            buf = get_object(fp, id, &pdf->xrefs[i], NULL, &dummy);
            if (!buf || !(c = strstr(buf, "/Pages")))
            {
                free(buf);
                continue;
            }

            /* Start at the first Pages obj and get kids */
            id = atoi(c + strlen("/Pages") + 1);
            load_kids(fp, id, &pdf->xrefs[i]);
            free(buf); 
        }
    }
            
    fseek(fp, start, SEEK_SET);
}


char pdf_get_object_status(
    const pdf_t *pdf,
    int          xref_idx,
    int          entry_idx)
{
    int                 i, curr_ver;
    const xref_t       *prev_xref;
    const xref_entry_t *prev, *curr;

    curr = &pdf->xrefs[xref_idx].entries[entry_idx];
    curr_ver = pdf->xrefs[xref_idx].version;

    if (curr_ver == 1)
      return 'A';

    /* Deleted (freed) */
    if (curr->f_or_n == 'f')
      return 'D';

    /* Get previous version */
    prev_xref = NULL;
    for (i=xref_idx; i>-1; --i)
      if (pdf->xrefs[i].version < curr_ver)
      {
          prev_xref = &pdf->xrefs[i];
          break;
      }

    if (!prev_xref)
      return '?';

    /* Locate the object in the previous one that matches current one */
    prev = NULL;
    for (i=0; i<prev_xref->n_entries; ++i)
      if (prev_xref->entries[i].obj_id == curr->obj_id)
      {
          prev = &prev_xref->entries[i];
          break;
      }

    /* Added in place of a previously freed id */
    if (!prev || ((prev->f_or_n == 'f') && (curr->f_or_n == 'n')))
      return 'A';

    /* Modified */
    else if (prev->offset != curr->offset)
      return 'M';
    
    return '?';
}


void pdf_zero_object(
    FILE        *fp,
    const pdf_t *pdf,
    int          xref_idx,
    int          entry_idx)
{
    int           i;
    char         *obj;
    size_t        obj_sz;
    xref_entry_t *entry;

    entry = &pdf->xrefs[xref_idx].entries[entry_idx];
    fseek(fp, entry->offset, SEEK_SET);

    /* Get object and size */
    obj = get_object(fp, entry->obj_id, &pdf->xrefs[xref_idx], NULL, NULL);
    i = obj_sz = 0;
    while (strncmp((++i)+obj, "endobj", 6))
      ++obj_sz;

    if (obj_sz)
      obj_sz += strlen("endobj") + 1;

    /* Zero object */
    for (i=0; i<obj_sz; i++)
      fputc('0', fp);

    printf("Zeroed object %d\n", entry->obj_id);
    free(obj);
}


/* Output information per version */
void pdf_summarize(
    FILE        *fp,
    const pdf_t *pdf,
    const char  *name,
    pdf_flag_t   flags)
{
    int   i, j, page, n_versions, n_entries;
    FILE *dst, *out;
    char *dst_name, *c;

    dst = NULL;
    dst_name = NULL;

    if (name)
    {
        dst_name = safe_calloc(strlen(name) * 2 + 16);
        sprintf(dst_name, "%s/%s", name, name);

        if ((c = strrchr(dst_name, '.')) && (strncmp(c, ".pdf", 4) == 0))
          *c = '\0';

        strcat(dst_name, ".summary");
        if (!(dst = fopen(dst_name, "w")))
        {
            ERR("Could not open file '%s' for writing\n", dst_name);
            return;
        }
    }
    
    /* Send output to file or stdout */
    out = (dst) ? dst : stdout;

    /* Count versions */
    n_versions = pdf->n_xrefs;
    if (n_versions && pdf->xrefs[0].is_linear)
      --n_versions;

    /* Ignore bad xref entry */
    for (i=1; i<pdf->n_xrefs; ++i)
      if (pdf->xrefs[i].end == 0)
        --n_versions;

    /* If we have no valid versions but linear, count that */
    if (!pdf->n_xrefs || (!n_versions && pdf->xrefs[0].is_linear))
      n_versions = 1;

    /* Compare each object (if we dont have xref streams) */
    n_entries = 0;
    for (i=0; !(const int)pdf->has_xref_streams && i<pdf->n_xrefs; i++)
    {
        if (flags & PDF_FLAG_QUIET)
          continue;

        for (j=0; j<pdf->xrefs[i].n_entries; j++)
        {
            ++n_entries;
            fprintf(out,
                    "%s: --%c-- Version %d -- Object %d (%s)",
                    pdf->name,
                    pdf_get_object_status(pdf, i, j),
                    pdf->xrefs[i].version,
                    pdf->xrefs[i].entries[j].obj_id,
                    get_type(fp, pdf->xrefs[i].entries[j].obj_id,
                             &pdf->xrefs[i]));

            /* TODO
            page = get_page(pdf->xrefs[i].entries[j].obj_id, &pdf->xrefs[i]);
            */

            if (0 /*page*/)
              fprintf(out, " Page(%d)\n", page);
            else
              fprintf(out, "\n");
        }
    }

    /* Trailing summary */
    if (!(flags & PDF_FLAG_QUIET))
    {
        /* Let the user know that we cannot we print a per-object summary.
         * If we have a 1.5 PDF using streams for xref, we have not objects
         * to display, so let the user know whats up.
         */
        if (pdf->has_xref_streams || !n_entries)
           fprintf(out,
               "%s: This PDF contains potential cross reference streams.\n"
               "%s: An object summary is not available.\n",
               pdf->name,
               pdf->name);

        fprintf(out,
                "---------- %s ----------\n"
                "Versions: %d\n", 
                pdf->name,
                n_versions);

        /* Count entries for summary */
        if (!pdf->has_xref_streams)
          for (i=0; i<pdf->n_xrefs; i++)
          {
              if (pdf->xrefs[i].is_linear)
                continue;

              n_entries = pdf->xrefs[i].n_entries;

              /* If we are a linearized PDF, all versions are made from those
               * objects too.  So count em'
               */
              if (pdf->xrefs[0].is_linear)
                n_entries += pdf->xrefs[0].n_entries; 

              if (pdf->xrefs[i].version && n_entries)
                fprintf(out,
                        "Version %d -- %d objects\n",
                        pdf->xrefs[i].version, 
                        n_entries);
           }
    }
    else /* Quiet output */
      fprintf(out, "%s: %d\n", pdf->name, n_versions);

    if (dst)
    {
        fclose(dst);
        free(dst_name);
    }
}


/* Returns '1' if we successfully display data (means its probably not xml) */
int pdf_display_creator(const pdf_t *pdf, int xref_idx)
{
    int i;

    if (!pdf->xrefs[xref_idx].creator)
      return 0;

    for (i=0; i<pdf->xrefs[xref_idx].n_creator_entries; ++i)
      printf("%s: %s\n",
             pdf->xrefs[xref_idx].creator[i].key,
             pdf->xrefs[xref_idx].creator[i].value);

    return (i > 0);
}


/* Checks if the xref is valid and sets 'is_stream' flag if the xref is a
 * stream (PDF 1.5 or higher)
 */
static int is_valid_xref(FILE *fp, pdf_t *pdf, xref_t *xref)
{
    int   is_valid;
    long  start;
    char *c, buf[16];
    
    memset(buf, 0, sizeof(buf));
    is_valid = 0;
    start = ftell(fp);
    fseek(fp, xref->start, SEEK_SET);

    if (fgets(buf, 16, fp) == NULL) {
      ERR("Failed to load xref string.");
      exit(EXIT_FAILURE);
    }

    if (strncmp(buf, "xref", strlen("xref")) == 0)
      is_valid = 1;
    else
    {  
        /* PDFv1.5+ allows for xref data to be stored in streams vs plaintext */
        fseek(fp, xref->start, SEEK_SET);
        c = get_object_from_here(fp, NULL, &xref->is_stream);

        if (c && xref->is_stream)
        {
            pdf->has_xref_streams = 1;
            is_valid = 1;
        }
        free(c);
    }

    fseek(fp, start, SEEK_SET);
    return is_valid;
}


static void load_xref_entries(FILE *fp, xref_t *xref)
{
    if (xref->is_stream)
      load_xref_from_stream(fp, xref);
    else
      load_xref_from_plaintext(fp, xref);
}


static void load_xref_from_plaintext(FILE *fp, xref_t *xref)
{
    int  i, obj_id, added_entries;
    char c, buf[32] = {0};
    long start, pos;
    size_t buf_idx;

    start = ftell(fp);

    /* Get number of entries */
    pos = xref->end;
    fseek(fp, pos, SEEK_SET);
    while (ftell(fp) != 0)
      if (SAFE_F(fp, (fgetc(fp) == '/' && fgetc(fp) == 'S')))
        break;
      else
        SAFE_E(fseek(fp, --pos, SEEK_SET), 0, "Failed seek to xref /Size.\n");

    SAFE_E(fread(buf, 1, 21, fp), 21, "Failed to load entry Size string.\n");
    xref->n_entries = atoi(buf + strlen("ize "));
    xref->entries = safe_calloc(xref->n_entries * sizeof(struct _xref_entry));

    /* Load entry data */
    obj_id = 0;
    fseek(fp, xref->start + strlen("xref"), SEEK_SET);
    added_entries = 0;
    for (i=0; i<xref->n_entries; i++)
    {
        /* Advance past newlines. */
        c = fgetc(fp);
        while (c == '\n' || c == '\r')
          c = fgetc(fp);

        /* Collect data up until the following newline. */
        buf_idx = 0;
        while (c != '\n' && c != '\r' && !feof(fp) &&
               !ferror(fp) && buf_idx < sizeof(buf))
        {
            buf[buf_idx++] = c;
            c = fgetc(fp);
        }
        if (buf_idx >= sizeof(buf)) {
            FAIL("Failed to locate newline character. "
                 "This might be a corrupt PDF.\n");
        }
        buf[buf_idx] = '\0';

        /* Went to far and hit start of trailer */
        if (strchr(buf, 't'))
          break;

        /* Entry or object id */
        if (strlen(buf) > 17)
        {
            const char *token = NULL;
            xref->entries[i].obj_id = obj_id++;
            token = strtok(buf, " ");
            if (!token) {
              FAIL("Failed to parse xref entry. "
                   "This might be a corrupt PDF.\n");
            }
            xref->entries[i].offset = atol(token);
            token = strtok(NULL, " ");
            if (!token) {
              FAIL("Failed to parse xref entry. "
                   "This might be a corrupt PDF.\n");
            }
            xref->entries[i].gen_num = atoi(token);
            xref->entries[i].f_or_n = buf[17];
            ++added_entries;
        }
        else
        {
            obj_id = atoi(buf);
            --i;
        }
    }

    xref->n_entries = added_entries;
    fseek(fp, start, SEEK_SET);
}


/* Load an xref table from a stream (PDF v1.5 +) */
static void load_xref_from_stream(FILE *fp, xref_t *xref)
{
    long    start;
    int     is_stream;
    char   *stream;
    size_t  size;

    start = ftell(fp);
    fseek(fp, xref->start, SEEK_SET);

    stream = NULL;
    stream = get_object_from_here(fp, &size, &is_stream);
    fseek(fp, start, SEEK_SET);

    /* TODO: decode and analyize stream */
    free(stream);
    return;
}


static void get_xref_linear_skipped(FILE *fp, xref_t *xref)
{
    int  err;
    char ch, buf[256];

    if (xref->start != 0)
      return;

    /* Special case (Linearized PDF with initial startxref at 0) */
    xref->is_linear = 1;

    /* Seek to %%EOF */
    if ((xref->end = get_next_eof(fp)) < 0)
      return;

    /* Locate the trailer */ 
    err = 0; 
    while (!(err = ferror(fp)) && fread(buf, 1, 8, fp))
    {
        if (strncmp(buf, "trailer", strlen("trailer")) == 0)
          break;
        else if ((ftell(fp) - 9) < 0)
          return;

        fseek(fp, -9, SEEK_CUR);
    }

    if (err)
      return;

    /* If we found 'trailer' look backwards for 'xref' */
    ch = 0;
    while (SAFE_F(fp, ((ch = fgetc(fp)) != 'x')))
      fseek(fp, -2, SEEK_CUR);

    if (ch == 'x')
    {
        xref->start = ftell(fp) - 1;
        fseek(fp, -1, SEEK_CUR);
    }

    /* Now continue to next eof ... */
    fseek(fp, xref->start, SEEK_SET);
}


/* This must only be called after all xref and entries have been acquired */
static void resolve_linearized_pdf(pdf_t *pdf)
{
    int    i;
    xref_t buf;

    if (pdf->n_xrefs < 2)
      return;

    if (!pdf->xrefs[0].is_linear)
      return;

    /* Swap Linear with Version 1 */
    buf = pdf->xrefs[0];
    pdf->xrefs[0] = pdf->xrefs[1];
    pdf->xrefs[1] = buf;

    /* Resolve is_linear flag and version */
    pdf->xrefs[0].is_linear = 1;
    pdf->xrefs[0].version = 1;
    pdf->xrefs[1].is_linear = 0;
    pdf->xrefs[1].version = 1;

    /* Adjust the other version values now */
    for (i=2; i<pdf->n_xrefs; ++i)
      --pdf->xrefs[i].version;
}


static pdf_creator_t *new_creator(int *n_elements)
{
    pdf_creator_t *daddy;

    static const pdf_creator_t creator_template[] = 
    {
        {"Title",        ""},
        {"Author",       ""},
        {"Subject",      ""},
        {"Keywords",     ""},
        {"Creator",      ""},
        {"Producer",     ""},
        {"CreationDate", ""},
        {"ModDate",      ""},
        {"Trapped",      ""},
    };

    daddy = safe_calloc(sizeof(creator_template));
    memcpy(daddy, creator_template, sizeof(creator_template));

    if (n_elements)
      *n_elements = sizeof(creator_template) / sizeof(creator_template[0]);

    return daddy;
}


#define END_OF_TRAILER(_c, _st, _fp) \
{                                    \
    if (_c == '>')                   \
    {                                \
        fseek(_fp, _st, SEEK_SET);   \
        continue;                    \
    }                                \
}
static void load_creator(FILE *fp, pdf_t *pdf)
{
    int    i, buf_idx;
    char   c, *buf, obj_id_buf[32] = {0};
    long   start;
    size_t sz;

    start = ftell(fp);

    /* For each PDF version */
    for (i=0; i<pdf->n_xrefs; ++i)
    {
        if (!pdf->xrefs[i].version)
          continue;

        /* Find trailer */
        fseek(fp, pdf->xrefs[i].start, SEEK_SET);
        while (SAFE_F(fp, (fgetc(fp) != 't')))
            ; /* Iterate to "trailer" */

        /* Look for "<< ....... /Info ......" */
        c = '\0';
        while (SAFE_F(fp, ((c = fgetc(fp)) != '>')))
          if (SAFE_F(fp, ((c == '/') &&
                          (fgetc(fp) == 'I') && ((fgetc(fp) == 'n')))))
            break;

        /* Could not find /Info in trailer */
        END_OF_TRAILER(c, start, fp);

        while (SAFE_F(fp, (!isspace(c = fgetc(fp)) && (c != '>'))))
            ; /* Iterate to first white space /Info<space><data> */

        /* No space between /Info and its data */
        END_OF_TRAILER(c, start, fp);

        while (SAFE_F(fp, (isspace(c = fgetc(fp)) && (c != '>'))))
            ; /* Iterate right on top of first non-whitespace /Info data */

        /* No data for /Info */
        END_OF_TRAILER(c, start, fp);

        /* Get obj id as number */
        buf_idx = 0;
        obj_id_buf[buf_idx++] = c;
        while ((buf_idx < (sizeof(obj_id_buf) - 1)) &&
               SAFE_F(fp, (!isspace(c = fgetc(fp)) && (c != '>'))))
          obj_id_buf[buf_idx++] = c;

        END_OF_TRAILER(c, start, fp);
     
        /* Get the object for the creator data.  If linear, try both xrefs */ 
        buf = get_object(fp, atoll(obj_id_buf), &pdf->xrefs[i], &sz, NULL);
        if (!buf && pdf->xrefs[i].is_linear && (i+1 < pdf->n_xrefs))
          buf = get_object(fp, atoll(obj_id_buf), &pdf->xrefs[i+1], &sz, NULL);

        load_creator_from_buf(fp, &pdf->xrefs[i], buf, sz);
        free(buf);
    }

    fseek(fp, start, SEEK_SET);
}


static void load_creator_from_buf(
    FILE       *fp,
    xref_t     *xref,
    const char *buf,
    size_t      buf_size)
{
    int   is_xml;
    char *c;

    if (!buf)
      return;

    /* Check to see if this is xml or old-school */
    if ((c = strstr(buf, "/Type")))
      while (*c && !isspace(*c))
        ++c;

    /* Probably "Metadata" */
    is_xml = 0;
    if (c && (*c == 'M'))
      is_xml = 1;

    /* Is the buffer XML(PDF 1.4+) or old format? */
    if (is_xml)
      load_creator_from_xml(xref, buf);
    else
      load_creator_from_old_format(fp, xref, buf, buf_size);
}


static void load_creator_from_xml(xref_t *xref, const char *buf)
{
    /* TODO */
}


static void load_creator_from_old_format(
    FILE       *fp,
    xref_t     *xref,
    const char *buf,
    size_t      buf_size)
{
    int            i, n_eles, length, is_escaped, obj_id;
    char          *c, *ascii, *start, *s, *saved_buf_search, *obj;
    size_t         obj_size;
    pdf_creator_t *info;

    info = new_creator(&n_eles);

    /* Mark the end of buf, so that we do not crawl past it */
    if (buf_size < 1) return;
    const char *buf_end = buf + buf_size - 1;

    /* Treat 'end' as either the end of 'buf' or the end of 'obj'.  Obj is if
     * the creator element (e.g., ModDate, Producer, etc) is an object and not
     * part of 'buf'.
     */
    const char *end = buf_end;

    for (i=0; i<n_eles; ++i)
    {
        if (!(c = strstr(buf, info[i].key)))
          continue;

        /* Find the value (skipping whitespace) */
        c += strlen(info[i].key);
        while (isspace(*c))
          ++c;
        if (c >= buf_end) {
          FAIL("Failed to locate space, likely a corrupt PDF.");
        }

        /* If looking at the start of a pdf token, we have gone too far */
        if (*c == '/')
          continue;

        /* If the value is a number and not a '(' then the data is located in
         * an object we need to fetch, and not inline
         */
        obj = saved_buf_search = NULL;
        obj_size = 0;
        end = buf_end; /* Init to be the buffer, this might not be an obj. */
        if (isdigit(*c))
        {
            obj_id = atoi(c);
            saved_buf_search = c;
            s = saved_buf_search;

            obj = get_object(fp, obj_id, xref, &obj_size, NULL);
            end = obj + obj_size;
            c = obj;

            /* Iterate to '(' */
            while (c && (*c != '(') && (c < end))
              ++c;
            if (c >= end)  {
              FAIL("Failed to locate a '(' character. "
                  "This might be a corrupt PDF.\n");
            }

            /* Advance the search to the next token */
            while (s && (*s == '/') && (s < buf_end))
              ++s;
            if (s >= buf_end)  {
              FAIL("Failed to locate a '/' character. "
                  "This might be a corrupt PDF.\n");
            }
            saved_buf_search = s;
        }
          
        /* Find the end of the value */
        start = c;
        length = is_escaped = 0;
        while (c && ((*c != '\r') && (*c != '\n') && (*c != '<')))
        {
            /* Bail out if we see an un-escaped ')' closing character */
            if (!is_escaped && (*c == ')'))
              break;
            else if (*c == '\\')
              is_escaped = 1;
            else
              is_escaped = 0;
            ++c;
            ++length;
            if (c > end) {
              FAIL("Failed to locate the end of a value. "
                   "This might be a corrupt PDF.\n");
            }
        }

        if (length == 0)
          continue;

        /* Add 1 to length so it gets the closing ')' when we copy */
        if (length)
          length += 1;
        length = (length > KV_MAX_VALUE_LENGTH) ? KV_MAX_VALUE_LENGTH : length;
        strncpy(info[i].value, start, length);
        info[i].value[KV_MAX_VALUE_LENGTH - 1] = '\0';

        /* Restore where we were searching from */
        if (saved_buf_search)
        {
            /* Release memory from get_object() called earlier */
            free(obj);
            c = saved_buf_search;
        }
    } /* For all creation information tags */

    /* Go through the values and convert if encoded */
    for (i = 0; i < n_eles; ++i) {
      const size_t val_str_len = strnlen(info[i].value, KV_MAX_VALUE_LENGTH);
      if ((ascii = decode_text_string(info[i].value, val_str_len))) {
        strncpy(info[i].value, ascii, val_str_len);
        free(ascii);
      }
    }

    xref->creator = info;
    xref->n_creator_entries = n_eles;
}


/* Returns object data at the start of the file pointer
 * This interfaces to 'get_object'
 */
static char *get_object_from_here(FILE *fp, size_t *size, int *is_stream)
{
    long         start;
    char         buf[256];
    int          obj_id;
    xref_t       xref;
    xref_entry_t entry;

    start = ftell(fp);

    /* Object ID */
    memset(buf, 0, 256);
    SAFE_E(fread(buf, 1, 255, fp), 255, "Failed to load object ID.\n");
    if (!(obj_id = atoi(buf)))
    {
        fseek(fp, start, SEEK_SET);
        return NULL;
    }
    
    /* Create xref entry to pass to the get_object routine */
    memset(&entry, 0, sizeof(xref_entry_t));
    entry.obj_id = obj_id;
    entry.offset = start;

    /* Xref and single entry for the object we want data from */
    memset(&xref, 0, sizeof(xref_t));
    xref.n_entries = 1;
    xref.entries = &entry;

    fseek(fp, start, SEEK_SET);
    return get_object(fp, obj_id, &xref, size, is_stream);
}


static char *get_object(
    FILE         *fp,
    int           obj_id,
    const xref_t *xref,
    size_t       *size,
    int          *is_stream)
{
    static const int    blk_sz = 256;
    int                 i, total_sz, read_sz, n_blks, search, stream;
    size_t              obj_sz;
    char               *c, *data;
    long                start;
    const xref_entry_t *entry;

    if (size)
      *size = 0;

    if (is_stream)
      *is_stream = 0;

    start = ftell(fp);

    /* Find object */
    entry = NULL;
    for (i=0; i<xref->n_entries; i++)
      if (xref->entries[i].obj_id == obj_id)
      {
          entry = &xref->entries[i];
          break;
      }

    if (!entry)
      return NULL;

    /* Jump to object start */
    fseek(fp, entry->offset, SEEK_SET);

    /* Initial allocation */
    obj_sz = 0;    /* Bytes in object */
    total_sz = 0;  /* Bytes read in   */
    n_blks = 1;
    data = safe_calloc(blk_sz * n_blks);

    /* Suck in data */
    stream = 0;
    while ((read_sz = fread(data+total_sz, 1, blk_sz-1, fp)) && !ferror(fp))
    {
        total_sz += read_sz;

        *(data + total_sz) = '\0';

        if (total_sz + blk_sz >= (blk_sz * n_blks))
          data = realloc(data, blk_sz * (++n_blks));
        if (!data) {
          ERR("Failed to reallocate buffer.\n");
          exit(EXIT_FAILURE);
        }

        search = total_sz - read_sz;
        if (search < 0)
          search = 0;

        if ((c = strstr(data + search, "endobj")))
        {
            *(c + strlen("endobj") + 1) = '\0';
            obj_sz = (char *)strstr(data + search, "endobj") - (char *)data;
            obj_sz += strlen("endobj") + 1;
            break;
        }
        else if (strstr(data, "stream"))
          stream = 1;
    }

    clearerr(fp);
    fseek(fp, start, SEEK_SET);

    if (size) {
      *size = obj_sz;
      if (!obj_sz && data) {
        free(data);
        data = NULL;
      }
    }
            
    if (is_stream)
      *is_stream = stream;

    return data;
}


static void add_kid(int id, xref_t *xref)
{
    /* Make some space */
    if (((xref->n_kids + 1) * KID_SIZE) > (xref->n_kids_allocs*KIDS_PER_ALLOC))
      xref->kids = realloc(
          xref->kids, (++xref->n_kids_allocs)*(KIDS_PER_ALLOC * KID_SIZE));

    xref->kids[xref->n_kids++] = id;
}


/* Recursive */
static void load_kids(FILE *fp, int pages_id, xref_t *xref)
{
    int   dummy, buf_idx, kid_id;
    char *data, *c, buf[32];

    /* Get kids */
    data = get_object(fp, pages_id, xref, NULL, &dummy);
    if (!data || !(c = strstr(data, "/Kids")))
    {
        free(data);
        return;
    }
    
    c = strchr(c, '[');
    if (c == NULL)
    {
        free(data);
        return;
    }
    buf_idx = 0;
    memset(buf, 0, sizeof(buf));
    while (*(++c) != ']')
    {
        if (isdigit(*c) || (*c == ' '))
          buf[buf_idx++] = *c;
        else if (isalpha(*c))
        {
            kid_id = atoi(buf);
            add_kid(kid_id, xref);
            buf_idx = 0;
            memset(buf, 0, sizeof(buf));

            /* Check kids of kid */
            load_kids(fp, kid_id, xref);
        }
        else if (*c == ']')
          break;
    }

    free(data);
}


static const char *get_type(FILE *fp, int obj_id, const xref_t *xref)
{
    int          is_stream;
    char        *c, *obj, *endobj;
    static char  buf[32];
    long         start;

    start = ftell(fp);

    if (!(obj = get_object(fp, obj_id, xref, NULL, &is_stream)) || 
        is_stream                                               ||
        !(endobj = strstr(obj, "endobj")))
    {
        free(obj);
        fseek(fp, start, SEEK_SET);

        if (is_stream)
          return "Stream";
        else
          return "Unknown";
    }

    /* Get the Type value (avoiding font names like Type1) */
    c = obj;
    while ((c = strstr(c, "/Type")) && (c < endobj))
      if (isdigit(*(c + strlen("/Type"))))
      {
          ++c;
          continue;
      }
      else
        break;

    if (!c || (c && (c > endobj)))
    {
        free(obj);
        fseek(fp, start, SEEK_SET);
        return "Unknown";
    }

    /* Skip to first blank/whitespace */
    c += strlen("/Type");
    while (isspace(*c) || *c == '/')
      ++c;

    /* 'c' should be pointing to the type name.  Find the end of the name. */
    size_t n_chars = 0;
    const char *name_itr = c;
    while ((name_itr < endobj) &&
           !(isspace(*name_itr) || *name_itr == '/' || *name_itr == '>')) {
        ++name_itr;
        ++n_chars;
    }
    if (n_chars >= sizeof(buf))
    {
        free(obj);
        fseek(fp, start, SEEK_SET);
        return "Unknown";
    }

    /* Return the value by storing it in static mem. */
    memcpy(buf, c, n_chars);
    buf[n_chars] = '\0';
    free(obj);
    fseek(fp, start, SEEK_SET);
    return buf;
}


/* TODO
static int get_page(int obj_id, const xref_t *xref)
{
    int i;

    for (i=0; i<xref->n_kids; i++)
      if (xref->kids[i] == obj_id)
        break;

    return i;
}
*/


static char *get_header(FILE *fp)
{
    /* First 1024 bytes of doc must be header (1.7 spec pg 1102) */
    char *header = safe_calloc(1024);
    long start = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    SAFE_E(fread(header, 1, 1023, fp), 1023, "Failed to load PDF header.\n");
    fseek(fp, start, SEEK_SET);
    return header;
}


static char *decode_text_string(const char *str, size_t str_len)
{
    int   idx, is_hex, is_utf16be, ascii_idx;
    char *ascii, hex_buf[5] = {0};

    is_hex = is_utf16be = idx = ascii_idx = 0;

    /* Regular encoding */
    if (str[0] == '(')
    {
        ascii = safe_calloc(str_len + 1);
        strncpy(ascii, str, str_len + 1);
        return ascii;
    }
    else if (str[0] == '<')
    {
        is_hex = 1;
        ++idx;
    }
    
    /* Text strings can be either PDFDocEncoding or UTF-16BE */
    if (is_hex && (str_len > 5) && 
        (str[idx] == 'F') && (str[idx+1] == 'E') &&
        (str[idx+2] == 'F') && (str[idx+3] == 'F'))
    {
        is_utf16be = 1;
        idx += 4;
    }
    else
      return NULL;

    /* Now decode as hex */
    ascii = safe_calloc(str_len);
    for ( ; idx<str_len; ++idx)
    {
        hex_buf[0] = str[idx++];
        hex_buf[1] = str[idx++];
        hex_buf[2] = str[idx++];
        hex_buf[3] = str[idx];
        ascii[ascii_idx++] = strtol(hex_buf, NULL, 16);
    }

    return ascii;
}


/* Return the offset to the beginning of the %%EOF string.
 * A negative value is returned when done scanning.
 */
static int get_next_eof(FILE *fp)
{
    int match, c;
    const char buf[] = "%%EOF";

    match = 0;
    while ((c = fgetc(fp)) != EOF)
    {
        if (c == buf[match])
          ++match;
        else
          match = 0;

        if (match == 5) /* strlen("%%EOF") */
          return ftell(fp) - 5;
    }

    return -1;
}
