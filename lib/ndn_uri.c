/**
 * @file ndn_uri.c
 * @brief Support for ndn:/URI/...
 * 
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008, 2009, 2010, 2013 Palo Alto Research Center, Inc.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. You should have received
 * a copy of the GNU Lesser General Public License along with this library;
 * if not, write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <string.h>
#include <ndn-tlv/ndn.h>
#include <ndn-tlv/charbuf.h>
#include <ndn-tlv/coding.h>
#include <ndn-tlv/uri.h>

/*********
RFC 3986                   URI Generic Syntax               January 2005


      reserved    = gen-delims / sub-delims

      gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"

      sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
                  / "*" / "+" / "," / ";" / "="
...
      unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"

*********/
static int
is_uri_reserved(const unsigned char ch)
{
    if (('a' <= ch && ch <= 'z') ||
        ('A' <= ch && ch <= 'Z') ||
        ('0' <= ch && ch <= '9') ||
        ch == '-' || ch == '.' || ch == '_' || ch == '~')
        return (0);
    else
        return (1);
}

/**
 * This appends to c a percent-escaped representation of the component
 * passed in.  Only generic URI unreserved characters are not escaped.
 * Components that consist solely of zero or more dots are converted
 * by adding 3 more dots so there are no ambiguities with . or .. or whether
 * a component is empty or absent. (cf. ndn_uri_append)
 */


void
ndn_uri_append_percentescaped(struct ndn_charbuf *c,
                              const unsigned char *data, size_t size)
{
    size_t i;
    unsigned char ch;
    for (i = 0; i < size && data[i] == '.'; i++)
        continue;
    /* For a component that consists solely of zero or more dots, add 3 more */
    if (i == size)
        ndn_charbuf_append(c, "...", 3);
    for (i = 0; i < size; i++) {
        ch = data[i];
        /*
         * Leave unescaped only the generic URI unreserved characters.
         * See RFC 3986. Here we assume the compiler uses ASCII.
         */
        if (is_uri_reserved(ch))
            ndn_charbuf_putf(c, "%%%02X", (unsigned)ch);
        else
            ndn_charbuf_append(c, &ch, 1);
    }
}

void
ndn_uri_append_mixedescaped(struct ndn_charbuf *c,
                              const unsigned char *data, size_t size)
{
    size_t i;
    unsigned char ch;
    int hexmode = 0;
    for (i = 0; i < size && data[i] == '.'; i++)
        continue;
    /* For a component that consists solely of zero or more dots, add 3 more */
    if (i == size)
        ndn_charbuf_append(c, "...", 3);
    if (size == 0)
        return;
    /* mixed escaping rules:
     * If the character following the unprintable character being processed
     * is printable use %xx.  If the first character being processed is %00 (segment)
     * or %FD (version) immediately shift into hex mode regardless of whether the
     * the next character is printable.
     */
    if (data[0] == '\0' || data[0] == (unsigned char)'\xFD') {
        hexmode = 1;
        ndn_charbuf_append(c, "=", 1);
    }
    for (i = 0; i < size; i++) {
        ch = data[i];
        /*
         * Leave unescaped only the generic URI unreserved characters.
         * See RFC 3986. Here we assume the compiler uses ASCII.
         */
        if (hexmode)
            ndn_charbuf_putf(c, "%02X", (unsigned)ch);
        else if (!is_uri_reserved(ch))
            ndn_charbuf_append(c, &ch, 1);
        else {  /* reserved character -- check for following character */
            if (ch > 0 && (i + 1 == size || !is_uri_reserved(data[i + 1])))
                ndn_charbuf_putf(c, "%%%02X", (unsigned)ch);
            else {
                hexmode = 1;
                ndn_charbuf_putf(c, "=%02X", (unsigned)ch);
            }
        }
    }
}
/**
 * This appends to c a URI representation of the ndnb-encoded Name element
 * passed in.  For convenience, it will also look inside of a ContentObject
 * or Interest object to find the Name.
 * Components that consist solely of zero or more dots are converted
 * by adding 3 more dots so there are no ambiguities with . or .. or whether
 * a component is empty or absent.
 * Will prepend "ndn:" if flags & NDN_URI_INCLUDESCHEME is not 0
 * Will escape with "%" and "=" if flags & NDN_URI_MIXEDESCAPES is not 0
 */

int
ndn_uri_append(struct ndn_charbuf *c,
               const unsigned char *ndnb,
               size_t size,
               int flags)
{
    int ncomp = 0;
    const unsigned char *comp = NULL;
    size_t compsize = 0;
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = ndn_buf_decoder_start(&decoder, ndnb, size);
    if (ndn_buf_match_dtag(d, NDN_DTAG_Interest)    ||
        ndn_buf_match_dtag(d, NDN_DTAG_ContentObject)) {
        ndn_buf_advance(d);
        if (ndn_buf_match_dtag(d, NDN_DTAG_Signature))
            ndn_buf_advance_past_element(d);
    }
    if (!ndn_buf_match_dtag(d, NDN_DTAG_Name))
        return(-1);
    if (flags & NDN_URI_INCLUDESCHEME)
        ndn_charbuf_append_string(c, "ndn:");
    ndn_buf_advance(d);
    while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
        ndn_buf_advance(d);
        compsize = 0;
        if (ndn_buf_match_blob(d, &comp, &compsize))
            ndn_buf_advance(d);
        ndn_buf_check_close(d);
        if (d->decoder.state < 0)
            return(d->decoder.state);
        ncomp += 1;
        ndn_charbuf_append(c, "/", 1);
        if ((flags & NDN_URI_ESCAPE_MASK) == 0)
            flags |= NDN_URI_DEFAULT_ESCAPE;
        if (flags & NDN_URI_MIXEDESCAPE) {
            ndn_uri_append_mixedescaped(c, comp, compsize);
        } else if (flags & NDN_URI_PERCENTESCAPE)
            ndn_uri_append_percentescaped(c, comp, compsize);
    }
    ndn_buf_check_close(d);
    if (d->decoder.state < 0)
        return (d->decoder.state);
    if (ncomp == 0)
        ndn_charbuf_append(c, "/", 1);
    return(ncomp);
}

static int
hexit(int c)
{
    if ('0' <= c && c <= '9')
        return(c - '0');
    if ('A' <= c && c <= 'F')
        return(c - 'A' + 10);
    if ('a' <= c && c <= 'f')
        return(c - 'a' + 10);
    return(-1);
}

/*
 * ndn_append_uri_component:
 * This takes as input the escaped URI component at s and appends it
 * to c.  This does not do any ndnb-related stuff.
 * Processing stops at an error or if an unescaped nul, '/', '?', or '#' is found.
 * A component that consists solely of dots gets special treatment to reverse
 * the addition of ... by ndn_uri_append_percentescaped.  Since '.' is an unreserved
 * character, percent-encoding is not supposed to change meaning and hence
 * the dot processing happens after percent-encoding is removed.
 * A positive return value indicates there were unescaped reserved or
 * non-printable characters found.  This might warrant some extra checking
 * by the caller.
 * A return value of -1 indicates the component was "..", so the caller
 * will need to do something extra to handle this as appropriate.
 * A return value of -2 indicates the component was empty or ".", so the caller
 * should do nothing with it.
 * A return value of -3 indicates a bad %-escaped sequence.
 * If cont is not NULL, *cont is set to the number of input characters processed.
 */
static int
ndn_append_uri_component(struct ndn_charbuf *c, const char *s, size_t limit, size_t *cont)
{
    size_t start = c->length;
    size_t i;
    int err = 0;
    int hex = 0;
    int d1, d2;
    unsigned char ch;
    for (i = 0; i < limit; i++) {
        ch = s[i];
        switch (ch) {
            case 0:
            case '/':
            case '?':
            case '#':
                limit = i;
                break;
            case '=':
                if (hex || i + 3 > limit) {
                    return(-3);
                }
                hex = 1;
                break;
            case '%':
                if (hex || i + 3 > limit || (d1 = hexit(s[i+1])) < 0 ||
                    (d2 = hexit(s[i+2])) < 0   ) {
                    return(-3);
                }
                ch = d1 * 16 + d2;
                i += 2;
                ndn_charbuf_append(c, &ch, 1);
                break;
            case ':': case '[': case ']': case '@':
            case '!': case '$': case '&': case '\'': case '(': case ')':
            case '*': case '+': case ',': case ';':
                err++;
                /* FALLTHROUGH */
            default:
                if (ch <= ' ' || ch > '~')
                    err++;
                if (hex) {
                    if ((d1 = hexit(s[i])) < 0 || (d2 = hexit(s[i+1])) < 0) {
                        return(-3);
                    }
                    ch = d1 * 16 + d2;
                    i++;
                }
                ndn_charbuf_append(c, &ch, 1);
                break;
        }
    }
    for (i = start; i < c->length && c->buf[i] == '.'; i++)
        continue;
    if (i == c->length) {
        /* all dots */
        i -= start;
        if (i <= 1) {
            c->length = start;
            err = -2;
        }
        else if (i == 2) {
            c->length = start;
            err = -1;
        }
        else
            c->length -= 3;
    }
    if (cont != NULL)
        *cont = limit;
    return(err);
}

static int
ndn_name_last_component_offset(const unsigned char *ndnb, size_t size)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = ndn_buf_decoder_start(&decoder, ndnb, size);
    int res = -1;
    if (ndn_buf_match_dtag(d, NDN_DTAG_Name)) {
        ndn_buf_advance(d);
        res = d->decoder.token_index; /* in case of 0 components */
        while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
            res = d->decoder.token_index;
            ndn_buf_advance(d);
            if (ndn_buf_match_blob(d, NULL, NULL))
                ndn_buf_advance(d);
            ndn_buf_check_close(d);
        }
        ndn_buf_check_close(d);
    }
    return ((d->decoder.state >= 0) ? res : -1);
}

/**
 * Convert a ndnx-scheme URI to a ndnb-encoded Name.
 * The converted result is placed in c.
 * On input, c may contain a base name, in which case relative URIs are allowed.
 * Otherwise c should start out empty, and the URI must be absolute.
 * @returns -1 if an error is found, otherwise returns the number of characters
 *          that were processed.
 */
int
ndn_name_from_uri(struct ndn_charbuf *c, const char *uri)
{
    int res = 0;
    struct ndn_charbuf *compbuf = NULL;
    const char *stop = uri + strlen(uri);
    const char *s = uri;
    size_t cont = 0;
    
    compbuf = ndn_charbuf_create();
    if (compbuf == NULL) return(-1);
    if (s[0] != '/') {
        res = ndn_append_uri_component(compbuf, s, stop - s, &cont);
        if (res < -2)
            goto Done;
        ndn_charbuf_reserve(compbuf, 1)[0] = 0;
        if (s[cont-1] == ':') {
            if ((0 == strcasecmp((const char *)(compbuf->buf), "ndn:") ||
                 0 == strcasecmp((const char *)(compbuf->buf), "ndn:"))) {
                s += cont;
                cont = 0;
            } else
                return (-1);
        }
    }
    if (s[0] == '/') {
        ndn_name_init(c);
        if (s[1] == '/') {
            /* Skip over hostname part - not used in ndnx scheme */
            s += 2;
            compbuf->length = 0;
            res = ndn_append_uri_component(compbuf, s, stop - s, &cont);
            if (res < 0 && res != -2)
                goto Done;
            s += cont; cont = 0;
        }
    }
    while (s[0] != 0 && s[0] != '?' && s[0] != '#') {
        if (s[0] == '/')
            s++;
        compbuf->length = 0;
        res = ndn_append_uri_component(compbuf, s, stop - s, &cont);
        s += cont; cont = 0;
        if (res < -2)
            goto Done;
        if (res == -2) {
            res = 0; /* process . or equiv in URI */
            continue;
        }
        if (res == -1) {
            /* process .. in URI - discard last name component */
            res = ndn_name_last_component_offset(c->buf, c->length);
            if (res < 0)
                goto Done;
            c->length = res;
            ndn_charbuf_append_closer(c);
            continue;
        }
        res = ndn_name_append(c, compbuf->buf, compbuf->length);
        if (res < 0)
            goto Done;
    }
Done:
    ndn_charbuf_destroy(&compbuf);
    if (res < 0)
        return(-1);
    if (c->length < 2 || c->buf[c->length-1] != NDN_CLOSE)
        return(-1);
    return(s - uri);
}
