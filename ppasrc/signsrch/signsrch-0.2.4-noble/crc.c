/*
    Copyright 2013 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/



typedef struct {
    u64     table[256];
    u64     poly;
    int     bits;
    u64     init;
    u64     final;
    int     type;
    int     rever;
    int     bitmask_side;
} crc_context;



static u64 crc_bitmask(int bits, int mask) {
    u64     ret;

         if(bits < 0)   ret = (u64)0;
    else if(bits >= 64) ret = (u64)0;
    else                ret = (u64)1 << (u64)bits;
    if(mask) ret--;
    return(ret);
}



static u64 crc_reflect(u64 v, int b) {
    u64     ret;
    int     i;

    ret = (u64)0;
    for(i = 0; i < b; i++) {
        ret = (u64)(ret << (u64)1) | (u64)(v & (u64)1);
        v >>= (u64)1;
    }
    return(ret);
}



static u64 crc_safe_limit(u64 crc, int bits) {
    if(bits < 64) {
        crc &= crc_bitmask(bits, 1);
    }
    return(crc);
}



static u64 crc_cm_tab(int inbyte, u64 poly, int bits, int rever, int bitmask_side) {
    u64     r,
            topbit;
    int     i;

    if(bitmask_side > 0) topbit = 1;
    else                 topbit = crc_bitmask(bits - 1, 0);

    if(rever) inbyte = crc_reflect(inbyte, 8);

    if(bitmask_side > 0) r = (u64)inbyte;
    else                 r = (u64)inbyte << (u64)(bits - 8);

    for(i = 0; i < 8; i++) {
        r = crc_safe_limit(r, bits);
        if(r & topbit) {
            if(bitmask_side > 0) r = (r >> (u64)1) ^ poly;
            else                 r = (r << (u64)1) ^ poly;
        } else {
            if(bitmask_side > 0) r = (r >> (u64)1);
            else                 r = (r << (u64)1);
        }
    }

    if(rever) r = crc_reflect(r, bits);

    r &= crc_bitmask(bits, 1);
    return(r);
}



u8 *crc_make_table(u8 *op, int *oplen, u64 poly, int bits, int endian, int rever, int bitmask_side, void *(*add_func)()) {
    u64     num,
            *p64;
    int     i,
            len;

    if(oplen) len = *oplen;
    else      len = 0;

    if(!op) {
        len = 0;
        if(!add_func) {
            op = calloc(256, sizeof(num));
            if(!op) return(NULL);
        }
    }
    p64 = (void *)op;

    for(i = 0; i < 256; i++) {
        num = crc_cm_tab(i, poly, bits, rever, bitmask_side);
        num = crc_safe_limit(num, bits);
        if(add_func) {
            op = add_func(op, &len, num, bits, endian);
        } else {
            p64[i] = num;
        }
    }

    if(oplen) *oplen = len;
    return(op);
}



u16 crc_in_cksum(u64 init, u8 *data, int len) {
    u64     sum;
    int     endian = 1; // big endian
    u16     crc,
            *p,
            *l;

    if(*(char *)&endian) endian = 0;
    sum = init;

    for(p = (u16 *)data, l = p + (len >> 1); p < l; p++) sum += *p;
    if(len & 1) sum += *p & (endian ? 0xff00 : 0xff);
    sum = (sum >> 16) + (sum & 0xffff);
    crc = sum + (sum >> 16);
    if(!endian) crc = (crc >> 8) | (crc << 8);
    return(crc);    // should be xored with 0xffff but this job is done later
}



u64 crc_calc(crc_context *ctx, u8 *data, int datalen) {
    #define CRC_MYCRC   crc_safe_limit(crc, ctx->bits)
    #define CRC_CALC_CYCLE(X) { \
        for(i = 0; i < datalen; i++) { \
            crc = X; \
        } \
    }
    u64     crc;
    int     i;

    crc = ctx->init;    // Init
         if(ctx->type == 0) CRC_CALC_CYCLE(ctx->table[(data[i] ^ CRC_MYCRC) & 0xff] ^ (CRC_MYCRC >> 8))
    else if(ctx->type == 1) CRC_CALC_CYCLE(ctx->table[(data[i] ^ (CRC_MYCRC >> (ctx->bits - 8))) & 0xff] ^ (CRC_MYCRC << 8))
    else if(ctx->type == 2) CRC_CALC_CYCLE(((CRC_MYCRC << 8) | data[i]) ^ ctx->table[(CRC_MYCRC >> (ctx->bits - 8)) & 0xff])
    else if(ctx->type == 3) CRC_CALC_CYCLE(((CRC_MYCRC >> 1) + ((CRC_MYCRC & 1) << (ctx->bits - 1))) + data[i])
    else if(ctx->type == 4) crc = crc_in_cksum(CRC_MYCRC, data, datalen);
    else if(ctx->type == 5) CRC_CALC_CYCLE(CRC_MYCRC ^ data[i])
    else if(ctx->type == 6) CRC_CALC_CYCLE(CRC_MYCRC + data[i])
    else if(ctx->type == 7) CRC_CALC_CYCLE(ctx->table[(data[i] ^ CRC_MYCRC) & 0xff] ^ CRC_MYCRC)
    else if(ctx->type == 8) CRC_CALC_CYCLE(ctx->table[(data[i] ^ CRC_MYCRC) & 0xff] ^ (CRC_MYCRC >> (ctx->bits - 8)))
    else {
        fprintf(stderr, "\nError: unsupported crc type %d\n", (int32_t)ctx->type);
        return(-1);
    }
    crc ^= ctx->final;  // XorOut
    crc = CRC_MYCRC;
    return(crc);
    #undef CRC_MYCRC
    #undef CRC_CALC_CYCLE
}

