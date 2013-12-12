/**
 * @file ndnd_main.c
 *
 * A NDNx program.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009-2011, 2013 Palo Alto Research Center, Inc.
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * This work is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include <signal.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "ndnd_private.h"

static int
stdiologger(void *loggerdata, const char *format, va_list ap)
{
    FILE *fp = (FILE *)loggerdata;
    return(vfprintf(fp, format, ap));
}

int
main(int argc, char **argv)
{
    struct ndnd_handle *h;
    
    if (argc > 1) {
        fprintf(stderr, "%s", ndnd_usage_message);
        exit(1);
    }
    signal(SIGPIPE, SIG_IGN);
    h = ndnd_create(argv[0], stdiologger, stderr);
    if (h == NULL)
        exit(1);
    ndnd_run(h);
    ndnd_msg(h, "exiting.");
    ndnd_destroy(&h);
    ERR_remove_state(0);
    EVP_cleanup();
    exit(0);
}
