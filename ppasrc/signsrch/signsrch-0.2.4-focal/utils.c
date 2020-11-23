// I don't trust memmove, it gave me problems in the past
int mymemmove(u8 *dst, u8 *src, int size) {
    int     i;

    if(!dst || !src) return(0);
    if(size < 0) size = strlen(src) + 1;
    if(dst < src) {
        for(i = 0; i < size; i++) {
            dst[i] = src[i];
        }
    } else {
        for(i = size - 1; i >= 0; i--) {
            dst[i] = src[i];
        }
    }
    return(i);
}



u8 *find_replace_string(u8 *buf, int *buflen, u8 *old, int oldlen, u8 *news, int newlen) {
    int     i,
            len,
            //len_bck,
            tlen,
            found;
    u8      *nbuf,
            *p;

    if(!buf) return(buf);
    found  = 0;
    len = -1;
    if(buflen) len = *buflen;
    if(len < 0) len = strlen(buf);
    if(oldlen < 0) {
        oldlen = 0;
        if(old) oldlen = strlen(old);
    }
    tlen    = len - oldlen;
    //len_bck = len;

    for(i = 0; i <= tlen; i++) {
        if(!strnicmp(buf + i, old, oldlen)) found++;
    }
    if(!found) return(buf); // nothing to change: return buf or a positive value

    //if(!news) return(NULL);  // if we want to know only if the searched string has been found, we will get NULL if YES and buf if NOT!!!
    if(newlen < 0) {
        newlen = 0;
        if(news) newlen = strlen(news);
    }

    if(newlen <= oldlen) {  // if the length of new string is equal/minor than the old one don't waste space for another buffer
        nbuf = buf;
    } else {                // allocate the new size
        nbuf = malloc(len + ((newlen - oldlen) * found) + 1);
    }

    p = nbuf;
    for(i = 0; i <= tlen;) {
        if(!strnicmp(buf + i, old, oldlen)) {
            memcpy(p, news, newlen);
            p += newlen;
            i += oldlen;
        } else {
            *p++ = buf[i];
            i++;
        }
    }
    while(i < len) {
        *p++ = buf[i];
        i++;
    }
    len = p - nbuf;
    if(buflen) *buflen = len;
    nbuf[len] = 0;  // hope the original input string has the +1 space
    return(nbuf);
}



u8 *skip_begin_string(u8 *p) {
    if(p) {
        while(*p) {
            if(*p > ' ') break;
            p++;
        }
    }
    return(p);
}



u8 *skip_end_string(u8 *p) {
    u8      *l;

    if(p) {
        for(l = p + strlen(p) - 1; l >= p; l--) {
            if(*l > ' ') return(l);
            *l = 0;
        }
    }
    return(p);
}



u8 *skip_delimit(u8 *p) {
    p = skip_begin_string(p);
    skip_end_string(p);
    return(p);
}


