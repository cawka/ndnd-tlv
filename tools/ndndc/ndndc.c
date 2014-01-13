/**
 * @file ndndc.c
 * @brief Bring up a link to another ndnd.
 *
 * A NDNx program.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2009-2012 Palo Alto Research Center, Inc.
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

#include "ndndc.h"
#include "ndndc-log.h"
#include "ndndc-srv.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#if defined(NEED_GETADDRINFO_COMPAT)
#include "getaddrinfo.h"
#include "dummyin6.h"
#endif
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0 /*IEEE Std 1003.1-2001/Cor 1-2002, item XSH/TC1/D6/20*/
#endif

#include <ndn/ndn.h>
#include <ndn/ndnd.h>
#include <ndn/uri.h>
#include <ndn/signing.h>
#include <ndn/face_mgmt.h>
#include <ndn/reg_mgmt.h>

#define ON_ERROR_CLEANUP(resval) {                                      \
if ((resval) < 0) {                                                 \
if (verbose > 0) ndndc_warn(__LINE__, "OnError cleanup\n");    \
goto Cleanup;                                                   \
}                                                                   \
}

#define ON_NULL_CLEANUP(resval) {                                       \
if ((resval) == NULL) {                                             \
if (verbose > 0) ndndc_warn(__LINE__, "OnNull cleanup\n");      \
goto Cleanup;                                                   \
}                                                                   \
}

#define ON_ERROR_EXIT(resval, msg) {                                    \
int _resval = (resval);                                             \
if (_resval < 0)                                                     \
ndndc_fatal(__LINE__, "fatal error, res = %d, %s\n", _resval, msg);  \
}

struct ndndc_data *
ndndc_initialize_data(void) {
    struct ndndc_data *self;
    const char *msg = "Unable to initialize ndndc";
    int res;
    
    self = calloc(1, sizeof(*self));
    if (self == NULL) {
        ON_ERROR_EXIT (-1, msg);
    }
    
    self->ndn_handle = ndn_create();
    ON_ERROR_EXIT(ndn_connect(self->ndn_handle, NULL), "Unable to connect to local ndnd");
    ON_ERROR_EXIT(ndndc_get_ndnd_id(self), "Unable to obtain ID of local ndnd");
    
    /* Set up an Interest template to indicate scope 1 (Local) */
    self->local_scope_template = ndn_charbuf_create();
    res = ndnb_element_begin(self->local_scope_template, NDN_DTAG_Interest);
    res |= ndnb_element_begin(self->local_scope_template, NDN_DTAG_Name);
    res |= ndnb_element_end(self->local_scope_template);	/* </Name> */
    res |= ndnb_tagged_putf(self->local_scope_template, NDN_DTAG_Scope, "1");
    res |= ndnb_element_end(self->local_scope_template);	/* </Interest> */
    ON_ERROR_EXIT(res, msg);
    
    /* Create a null name */
    self->no_name = ndn_charbuf_create();
    ON_ERROR_EXIT(ndn_name_init(self->no_name), msg);
    
    self->lifetime = (~0U) >> 1;
    
    return self;
}

void
ndndc_destroy_data(struct ndndc_data **data) {
    struct ndndc_data *self = *data;
    
    if (self != NULL) {
        ndn_charbuf_destroy(&self->no_name);
        ndn_charbuf_destroy(&self->local_scope_template);
        ndn_disconnect(self->ndn_handle);
        ndn_destroy(&self->ndn_handle);
        free(self);
        *data = NULL;
    }
}


int
ndndc_dispatch_cmd(struct ndndc_data *ndndc,
                   int check_only,
                   const char *cmd,
                   const char *options,
                   int num_options)
{
    if (strcasecmp(cmd, "add") == 0) {
        if (num_options >= 0 && (num_options < 3 || num_options > 7))
            return INT_MIN;
        return ndndc_add(ndndc, check_only, options);
    }
    if (strcasecmp(cmd, "del") == 0) {
        if (num_options >= 0 && (num_options < 3 || num_options > 7))
            return INT_MIN;
        return ndndc_del(ndndc, check_only, options);
    }
    if (strcasecmp(cmd, "create") == 0) {
        if (num_options >= 0 && (num_options < 2 || num_options > 5))
            return INT_MIN;
        return ndndc_create(ndndc, check_only, options);
    }
    if (strcasecmp(cmd, "destroy") == 0) {
        if (num_options >= 0 && (num_options < 2 || num_options > 5))
            return INT_MIN;
        return ndndc_destroy(ndndc, check_only, options);
    }
    if (strcasecmp(cmd, "destroyface") == 0) {
        if (num_options >= 0 && num_options != 1)
            return INT_MIN;
        return ndndc_destroyface(ndndc, check_only, options);
    }
    if (strcasecmp(cmd, "srv") == 0) {
        // attempt to guess parameters using SRV record of a domain in search list
        if (num_options >= 0 && num_options != 0)
            return INT_MIN;
        if (check_only) return 0;
        return ndndc_srv(ndndc, NULL, 0);
    }
    if (strcasecmp(cmd, "renew") == 0) {
        if (num_options >= 0 && (num_options < 3 || num_options > 7))
            return INT_MIN;
        return ndndc_renew(ndndc, check_only, options);
    }
    return INT_MIN;
}


#define GET_NEXT_TOKEN(_cmd, _token_var) do {       \
_token_var = strsep(&_cmd, " \t");             \
} while (_token_var != NULL && _token_var[0] == 0);

/*
 *   uri (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
 *   uri face faceid
 */
int
ndndc_add(struct ndndc_data *self,
          int check_only,
          const char *cmd_orig)
{
    int ret_code = -1;
    char *cmd, *cmd_token;
    char *cmd_uri = NULL;
    char *cmd_proto = NULL;
    char *cmd_host = NULL;
    char *cmd_port = NULL;
    char *cmd_flags = NULL;
    char *cmd_mcastttl = NULL;
    char *cmd_mcastif = NULL;
    struct ndn_face_instance *face = NULL;
    struct ndn_face_instance *newface = NULL;
    struct ndn_forwarding_entry *prefix = NULL;
    
    if (cmd_orig == NULL) {
        ndndc_warn(__LINE__, "command error\n");
        return -1;
    }
    
    cmd = strdup(cmd_orig);
    if (cmd == NULL) {
        ndndc_warn(__LINE__, "Cannot allocate memory for copy of the command\n");
        return -1;
    }            
    cmd_token = cmd;
    GET_NEXT_TOKEN(cmd_token, cmd_uri);
    GET_NEXT_TOKEN(cmd_token, cmd_proto);
    GET_NEXT_TOKEN(cmd_token, cmd_host);
    GET_NEXT_TOKEN(cmd_token, cmd_port);
    GET_NEXT_TOKEN(cmd_token, cmd_flags);
    GET_NEXT_TOKEN(cmd_token, cmd_mcastttl);
    GET_NEXT_TOKEN(cmd_token, cmd_mcastif);
    
    // perform sanity checking
    face = parse_ndn_face_instance(self, cmd_proto, cmd_host, cmd_port,
                                   cmd_mcastttl, cmd_mcastif, (~0U) >> 1);
    prefix = parse_ndn_forwarding_entry(self, cmd_uri, cmd_flags, self->lifetime);
    if (face == NULL || prefix == NULL)
        goto Cleanup;
    
    if (!check_only) {
        if (0 != strcasecmp(cmd_proto, "face")) {
            newface = ndndc_do_face_action(self, "newface", face);
            if (newface == NULL) {
                ndndc_warn(__LINE__, "Cannot create/lookup face");
                goto Cleanup;
            }
            prefix->faceid = newface->faceid;
            ndn_face_instance_destroy(&newface);
        } else {
            prefix->faceid = face->faceid;
        }
        ret_code = ndndc_do_prefix_action(self, "prefixreg", prefix);
        if (ret_code < 0) {
            ndndc_warn(__LINE__, "Cannot register prefix [%s]\n", cmd_uri);
            goto Cleanup;
        }
    }  
    ret_code = 0;
Cleanup:
    ndn_face_instance_destroy(&face);
    ndn_forwarding_entry_destroy(&prefix);
    free(cmd);
    return (ret_code);
}


int
ndndc_del(struct ndndc_data *self,
          int check_only,
          const char *cmd_orig)
{
    int ret_code = -1;
    char *cmd, *cmd_token;
    char *cmd_uri = NULL;
    char *cmd_proto = NULL;
    char *cmd_host = NULL;
    char *cmd_port = NULL;
    char *cmd_flags = NULL;
    char *cmd_mcastttl = NULL;
    char *cmd_mcastif = NULL;
    struct ndn_face_instance *face = NULL;
    struct ndn_face_instance *newface = NULL;
    struct ndn_forwarding_entry *prefix = NULL;
    
    if (cmd_orig == NULL) {
        ndndc_warn(__LINE__, "command error\n");
        return -1;
    }
    
    cmd = strdup(cmd_orig);
    if (cmd == NULL) {
        ndndc_warn(__LINE__, "Cannot allocate memory for copy of the command\n");
        return -1;
    }            
    cmd_token = cmd;
    GET_NEXT_TOKEN(cmd_token, cmd_uri);
    GET_NEXT_TOKEN(cmd_token, cmd_proto);
    GET_NEXT_TOKEN(cmd_token, cmd_host);
    GET_NEXT_TOKEN(cmd_token, cmd_port);
    GET_NEXT_TOKEN(cmd_token, cmd_flags);
    GET_NEXT_TOKEN(cmd_token, cmd_mcastttl);
    GET_NEXT_TOKEN(cmd_token, cmd_mcastif);
    
    face = parse_ndn_face_instance(self, cmd_proto, cmd_host, cmd_port,
                                   cmd_mcastttl, cmd_mcastif, (~0U) >> 1);
    prefix = parse_ndn_forwarding_entry(self, cmd_uri, cmd_flags, (~0U) >> 1);
    if (face == NULL || prefix == NULL)
        goto Cleanup;
    
    if (!check_only) {
        if (0 != strcasecmp(cmd_proto, "face")) {
            newface = ndndc_do_face_action(self, "newface", face);
            if (newface == NULL) {
                ndndc_warn(__LINE__, "Cannot create/lookup face");
                goto Cleanup;
            }
            prefix->faceid = newface->faceid;
            ndn_face_instance_destroy(&newface);
        } else {
            prefix->faceid = face->faceid;
        }
        ret_code = ndndc_do_prefix_action(self, "unreg", prefix);
        if (ret_code < 0) {
            ndndc_warn(__LINE__, "Cannot unregister prefix [%s]\n", cmd_uri);
            goto Cleanup;
        }
    }
    ret_code = 0;
Cleanup:
    ndn_face_instance_destroy(&face);
    ndn_forwarding_entry_destroy(&prefix);
    free(cmd);
    return (ret_code);
}

/*
 *   (udp|tcp) host [port [mcastttl [mcastif]]]
 */
int
ndndc_create(struct ndndc_data *self,
             int check_only,
             const char *cmd_orig)
{
    int ret_code = -1;
    char *cmd, *cmd_token;
    char *cmd_proto = NULL;
    char *cmd_host = NULL;
    char *cmd_port = NULL;
    char *cmd_mcastttl = NULL;
    char *cmd_mcastif = NULL;
    struct ndn_face_instance *face = NULL;
    struct ndn_face_instance *newface = NULL;
    
    if (cmd_orig == NULL) {
        ndndc_warn(__LINE__, "command error\n");
        return -1;
    }
    
    cmd = strdup(cmd_orig);
    if (cmd == NULL) {
        ndndc_warn(__LINE__, "Cannot allocate memory for copy of the command\n");
        return -1;
    }            
    cmd_token = cmd;
    GET_NEXT_TOKEN(cmd_token, cmd_proto);
    GET_NEXT_TOKEN(cmd_token, cmd_host);
    GET_NEXT_TOKEN(cmd_token, cmd_port);
    GET_NEXT_TOKEN(cmd_token, cmd_mcastttl);
    GET_NEXT_TOKEN(cmd_token, cmd_mcastif);
    
    // perform sanity checking
    face = parse_ndn_face_instance(self, cmd_proto, cmd_host, cmd_port,
                                   cmd_mcastttl, cmd_mcastif, self->lifetime);
    if (face == NULL)
        goto Cleanup;
    
    if (!check_only) {
        newface = ndndc_do_face_action(self, "newface", face);
        if (newface == NULL) {
            ndndc_warn(__LINE__, "Cannot create/lookup face");
            goto Cleanup;
        }
        ndn_face_instance_destroy(&newface);
    }
    ret_code = 0;
Cleanup:
    ndn_face_instance_destroy(&face);
    free(cmd);
    return (ret_code);
}    

/*
 *   (udp|tcp) host [port [mcastttl [mcastif]]]
 */
int
ndndc_destroy(struct ndndc_data *self,
              int check_only,
              const char *cmd_orig)
{
    int ret_code = -1;
    char *cmd, *cmd_token;
    char *cmd_proto = NULL;
    char *cmd_host = NULL;
    char *cmd_port = NULL;
    char *cmd_mcastttl = NULL;
    char *cmd_mcastif = NULL;
    struct ndn_face_instance *face = NULL;
    struct ndn_face_instance *newface = NULL;
    
    if (cmd_orig == NULL) {
        ndndc_warn(__LINE__, "command error\n");
        return -1;
    }
    
    cmd = strdup(cmd_orig);
    if (cmd == NULL) {
        ndndc_warn(__LINE__, "Cannot allocate memory for copy of the command\n");
        return -1;
    }            
    cmd_token = cmd;
    GET_NEXT_TOKEN(cmd_token, cmd_proto);
    GET_NEXT_TOKEN(cmd_token, cmd_host);
    GET_NEXT_TOKEN(cmd_token, cmd_port);
    GET_NEXT_TOKEN(cmd_token, cmd_mcastttl);
    GET_NEXT_TOKEN(cmd_token, cmd_mcastif);
    
    // perform sanity checking
    face = parse_ndn_face_instance(self, cmd_proto, cmd_host, cmd_port,
                                   cmd_mcastttl, cmd_mcastif, (~0U) >> 1);
    if (face == NULL)
        goto Cleanup;
    
    if (!check_only) {
        // TODO: should use queryface when implemented
        if (0 != strcasecmp(cmd_proto, "face")) {
            newface = ndndc_do_face_action(self, "newface", face);
            if (newface == NULL) {
                ndndc_warn(__LINE__, "Cannot create/lookup face");
                goto Cleanup;
            }
            face->faceid = newface->faceid;
            ndn_face_instance_destroy(&newface);
        }
        newface = ndndc_do_face_action(self, "destroyface", face);
        if (newface == NULL) {
            ndndc_warn(__LINE__, "Cannot destroy face %d or the face does not exist\n", face->faceid);
            goto Cleanup;
        }
        ndn_face_instance_destroy(&newface);
    }  
    ret_code = 0;
Cleanup:
    ndn_face_instance_destroy(&face);
    free(cmd);
    return ret_code;
}    

/*
 *   (udp|tcp) host [port [mcastttl [mcastif]]]
 */
/*
 *   uri (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
 *   uri face faceid
 */
int
ndndc_renew(struct ndndc_data *self,
            int check_only,
            const char *cmd_orig)
{
    int ret_code = -1;
    char *cmd, *cmd_token;
    char *cmd_uri = NULL;
    char *cmd_proto = NULL;
    char *cmd_host = NULL;
    char *cmd_port = NULL;
    char *cmd_flags = NULL;
    char *cmd_mcastttl = NULL;
    char *cmd_mcastif = NULL;
    struct ndn_face_instance *face = NULL;
    struct ndn_face_instance *newface = NULL;
    struct ndn_forwarding_entry *prefix = NULL;
    
    if (cmd_orig == NULL) {
        ndndc_warn(__LINE__, "command error\n");
        return -1;
    }
    
    cmd = strdup(cmd_orig);
    if (cmd == NULL) {
        ndndc_warn(__LINE__, "Cannot allocate memory for copy of the command\n");
        return -1;
    }            
    cmd_token = cmd;
    GET_NEXT_TOKEN(cmd_token, cmd_uri);
    GET_NEXT_TOKEN(cmd_token, cmd_proto);
    GET_NEXT_TOKEN(cmd_token, cmd_host);
    GET_NEXT_TOKEN(cmd_token, cmd_port);
    GET_NEXT_TOKEN(cmd_token, cmd_flags);
    GET_NEXT_TOKEN(cmd_token, cmd_mcastttl);
    GET_NEXT_TOKEN(cmd_token, cmd_mcastif);
    
    // perform sanity checking
    face = parse_ndn_face_instance(self, cmd_proto, cmd_host, cmd_port,
                                   cmd_mcastttl, cmd_mcastif, (~0U) >> 1);
    prefix = parse_ndn_forwarding_entry(self, cmd_uri, cmd_flags, self->lifetime);
    if (face == NULL || prefix == NULL)
        goto Cleanup;
    
    if (!check_only) {
        // look up the old face ("queryface" would be useful)
        newface = ndndc_do_face_action(self, "newface", face);
        if (newface == NULL) {
            ndndc_warn(__LINE__, "Cannot create/lookup face");
            goto Cleanup;
        }
        face->faceid = newface->faceid;
        ndn_face_instance_destroy(&newface);
        // destroy the old face
        newface = ndndc_do_face_action(self, "destroyface", face);
        if (newface == NULL) {
            ndndc_warn(__LINE__, "Cannot destroy face %d or the face does not exist\n", face->faceid);
            goto Cleanup;
        }
        ndn_face_instance_destroy(&newface);
        // recreate the face
        newface = ndndc_do_face_action(self, "newface", face);
        if (newface == NULL) {
            ndndc_warn(__LINE__, "Cannot create/lookup face");
            goto Cleanup;
        }
        prefix->faceid = newface->faceid;
        ndn_face_instance_destroy(&newface);
        // and add the prefix to it
        ret_code = ndndc_do_prefix_action(self, "prefixreg", prefix);
        if (ret_code < 0) {
            ndndc_warn(__LINE__, "Cannot register prefix [%s]\n", cmd_uri);
            goto Cleanup;
        }
    }  
    ret_code = 0;
Cleanup:
    ndn_face_instance_destroy(&face);
    ndn_forwarding_entry_destroy(&prefix);
    free(cmd);
    return (ret_code);
}


int
ndndc_destroyface(struct ndndc_data *self,
                  int check_only,
                  const char *cmd_orig)
{
    int ret_code = 0;
    char *cmd, *cmd_token;
    char *cmd_faceid = NULL;
    struct ndn_face_instance *face;
    struct ndn_face_instance *newface;
    
    if (cmd_orig == NULL) {
        ndndc_warn(__LINE__, "command error\n");
        return -1;
    }
    
    cmd = strdup(cmd_orig);
    if (cmd == NULL) {
        ndndc_warn(__LINE__, "Cannot allocate memory for copy of the command\n");
        return -1;
    }            
    
    cmd_token = cmd;    
    GET_NEXT_TOKEN(cmd_token, cmd_faceid);
    
    face = parse_ndn_face_instance_from_face(self, cmd_faceid);
    if (face == NULL) {
        ret_code = -1;
    }
    
    if (ret_code == 0 && check_only == 0) {
        newface = ndndc_do_face_action(self, "destroyface", face);
        if (newface == NULL) {
            ndndc_warn(__LINE__, "Cannot destroy face %d or the face does not exist\n", face->faceid);        
        }
        ndn_face_instance_destroy(&newface);
    }
    
    ndn_face_instance_destroy(&face);
    free(cmd);
    return ret_code;
}


int
ndndc_srv(struct ndndc_data *self,
          const unsigned char *domain,
          size_t domain_size)
{
    char *proto = NULL;
    char *host = NULL;
    int port = 0;
    char port_str[10];
    struct ndn_charbuf *uri;
    struct ndn_charbuf *uri_auto = NULL;
    struct ndn_face_instance *face;
    struct ndn_face_instance *newface;
    struct ndn_forwarding_entry *prefix;
    struct ndn_forwarding_entry *prefix_auto;
    int res;
    
    res = ndndc_query_srv(domain, domain_size, &host, &port, &proto);
    if (res < 0) {
        return -1;
    }
    
    uri = ndn_charbuf_create();
    ndn_charbuf_append_string(uri, "ndn:/");
    if (domain_size != 0) {
        ndn_uri_append_percentescaped(uri, domain, domain_size);
    }
    
    snprintf (port_str, sizeof(port_str), "%d", port);
    
    /* now process the results */
    /* pflhead, lineno=0, "add" "ndn:/asdfasdf.com/" "tcp|udp", host, portstring, NULL NULL NULL */
    
    ndndc_note(__LINE__, " >>> trying:   add %s %s %s %s <<<\n", ndn_charbuf_as_string(uri), proto, host, port_str);
    
    face = parse_ndn_face_instance(self, proto, host, port_str, NULL, NULL,
                                   (~0U) >> 1);
    
    prefix = parse_ndn_forwarding_entry(self, ndn_charbuf_as_string(uri), NULL,
                                        self->lifetime);
    if (face == NULL || prefix == NULL) {
        res = -1;
        goto Cleanup;
    }
    
    // crazy operation
    // First. "Create" face, which will do nothing if face already exists
    // Second. Destroy the face
    // Third. Create face for real
    
    newface = ndndc_do_face_action(self, "newface", face);
    if (newface == NULL) {
        ndndc_warn(__LINE__, "Cannot create/lookup face");
        res = -1;
        goto Cleanup;
    }
    
    face->faceid = newface->faceid;
    ndn_face_instance_destroy(&newface);
    
    newface = ndndc_do_face_action(self, "destroyface", face);
    if (newface == NULL) {
        ndndc_warn(__LINE__, "Cannot destroy face");
    } else {
        ndn_face_instance_destroy(&newface);
    }
    
    newface = ndndc_do_face_action(self, "newface", face);
    if (newface == NULL) {
        ndndc_warn(__LINE__, "Cannot create/lookup face");
        res = -1;
        goto Cleanup;
    }
    
    prefix->faceid = newface->faceid;
    ndn_face_instance_destroy(&newface);
    
    res = ndndc_do_prefix_action(self, "prefixreg", prefix);
    if (res < 0) {
        ndndc_warn(__LINE__, "Cannot register prefix [%s]\n", ndn_charbuf_as_string(uri));
    }

    uri_auto = ndn_charbuf_create();
    ndn_charbuf_append_string(uri_auto, "ndn:/autoconf-route");
    prefix_auto = parse_ndn_forwarding_entry(self, ndn_charbuf_as_string(uri_auto), NULL,
                                        self->lifetime);
    if (prefix_auto == NULL) {
        res = -1;
        goto Cleanup;
    }

    prefix_auto->faceid = prefix->faceid;
    res = ndndc_do_prefix_action(self, "prefixreg", prefix_auto);
    if (res < 0) {
        ndndc_warn(__LINE__, "Cannot register prefix_auto [%s]\n", ndn_charbuf_as_string(uri_auto));
    }
    
Cleanup:
    free(host);
    ndn_charbuf_destroy(&uri);
    ndn_charbuf_destroy(&uri_auto);
    ndn_face_instance_destroy(&face);
    ndn_forwarding_entry_destroy(&prefix);
    ndn_forwarding_entry_destroy(&prefix_auto);
    return res;
}


struct ndn_forwarding_entry *
parse_ndn_forwarding_entry(struct ndndc_data *self,
                           const char *cmd_uri,
                           const char *cmd_flags,
                           int freshness)
{
    int res = 0;
    struct ndn_forwarding_entry *entry;
    
    entry= calloc(1, sizeof(*entry));
    if (entry == NULL) {
        ndndc_warn(__LINE__, "Fatal error: memory allocation failed");
        goto ExitOnError;
    }
    
    entry->name_prefix = ndn_charbuf_create();
    if (entry->name_prefix == NULL) {
        ndndc_warn(__LINE__, "Fatal error: memory allocation failed");
        goto ExitOnError;
    }
    
    // copy static info
    entry->ndnd_id = (const unsigned char *)self->ndnd_id;
    entry->ndnd_id_size = self->ndnd_id_size;
    
    /* we will be creating the face to either add/delete a prefix on it */
    if (cmd_uri == NULL) {
        ndndc_warn(__LINE__, "command erro, missing NDNx URI\n");
        goto ExitOnError;
    }
    
    res = ndn_name_from_uri(entry->name_prefix, cmd_uri);
    if (res < 0) {
        ndndc_warn(__LINE__, "command error, bad NDNx URI '%s'\n", cmd_uri);
        goto ExitOnError;
    }
    
    entry->flags = -1;
    if (cmd_flags != NULL && cmd_flags[0] != 0) {
        char *endptr;
        entry->flags = strtol(cmd_flags, &endptr, 10);
        if ((endptr != &cmd_flags[strlen(cmd_flags)]) ||
            (entry->flags & ~NDN_FORW_PUBMASK) != 0) {
            ndndc_warn(__LINE__, "command error, invalid flags %s\n", cmd_flags);
            goto ExitOnError;
        }
    }
    
    entry->lifetime = freshness;
    return (entry);
    
ExitOnError:
    ndn_forwarding_entry_destroy(&entry);
    return (NULL);
}


// creates a full structure without action, if proto == "face" only the
// faceid (from cmd_host parameter) and lifetime will be filled in.
struct ndn_face_instance *
parse_ndn_face_instance(struct ndndc_data *self,
                        const char *cmd_proto,
                        const char *cmd_host,     const char *cmd_port,
                        const char *cmd_mcastttl, const char *cmd_mcastif,
                        int freshness)
{
    struct ndn_face_instance *entry;
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_flags = (AI_ADDRCONFIG)};
    struct addrinfo mcasthints = {.ai_family = AF_UNSPEC, .ai_flags = (AI_ADDRCONFIG | AI_NUMERICHOST)};
    struct addrinfo *raddrinfo = NULL;
    struct addrinfo *mcastifaddrinfo = NULL;
    char rhostnamebuf [NI_MAXHOST];
    char rhostportbuf [NI_MAXSERV];
    int off_address = -1, off_port = -1, off_source_address = -1;
    int res;
    int socktype;
    
    entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
        ndndc_warn(__LINE__, "Fatal error: memory allocation failed");
        goto ExitOnError;
    }
    // allocate storage for Face data
    entry->store = ndn_charbuf_create();
    if (entry->store == NULL) {
        ndndc_warn(__LINE__, "Fatal error: memory allocation failed");
        goto ExitOnError;
    }
    // copy static info
    entry->ndnd_id = (const unsigned char *)self->ndnd_id;
    entry->ndnd_id_size = self->ndnd_id_size;
    
    if (cmd_proto == NULL) {
        ndndc_warn(__LINE__, "command error, missing address type\n");
        goto ExitOnError;
    }
    if (strcasecmp(cmd_proto, "udp") == 0) {
        entry->descr.ipproto = IPPROTO_UDP;
        socktype = SOCK_DGRAM;
    } else if (strcasecmp(cmd_proto, "tcp") == 0) {
        entry->descr.ipproto = IPPROTO_TCP;
        socktype = SOCK_STREAM;
    } else if (strcasecmp(cmd_proto, "face") == 0) {
        errno = 0;
        unsigned long faceid = strtoul(cmd_host, (char **)NULL, 10);
        if (errno == ERANGE || errno == EINVAL || faceid > UINT_MAX || faceid == 0) {
            ndndc_warn(__LINE__, "command error, face number invalid or out of range '%s'\n", cmd_host);
            goto ExitOnError;
        }
        entry->faceid = (unsigned) faceid;
        entry->lifetime = freshness;
        return (entry);
    } else {
        ndndc_warn(__LINE__, "command error, unrecognized address type '%s'\n", cmd_proto);
        goto ExitOnError;
    }
    
    if (cmd_host == NULL) {
        ndndc_warn(__LINE__, "command error, missing hostname\n");
        goto ExitOnError;
    }
    
    if (cmd_port == NULL || cmd_port[0] == 0)
        cmd_port = NDN_DEFAULT_UNICAST_PORT;
    
    hints.ai_socktype = socktype;
    res = getaddrinfo(cmd_host, cmd_port, &hints, &raddrinfo);
    if (res != 0 || raddrinfo == NULL) {
        ndndc_warn(__LINE__, "command error, getaddrinfo for host [%s] port [%s]: %s\n", cmd_host, cmd_port, gai_strerror(res));
        goto ExitOnError;
    }
    res = getnameinfo(raddrinfo->ai_addr, raddrinfo->ai_addrlen,
                      rhostnamebuf, sizeof(rhostnamebuf),
                      rhostportbuf, sizeof(rhostportbuf),
                      NI_NUMERICHOST | NI_NUMERICSERV);
    freeaddrinfo(raddrinfo);
    if (res != 0) {
        ndndc_warn(__LINE__, "command error, getnameinfo: %s\n", gai_strerror(res));
        goto ExitOnError;
    }
    
    off_address = entry->store->length;
    res = ndn_charbuf_append(entry->store, rhostnamebuf, strlen(rhostnamebuf)+1);
    if (res != 0) {
        ndndc_warn(__LINE__, "Cannot append to charbuf");
        goto ExitOnError;
    }
    
    off_port = entry->store->length;
    res = ndn_charbuf_append(entry->store, rhostportbuf, strlen(rhostportbuf)+1);
    if (res != 0) {
        ndndc_warn(__LINE__, "Cannot append to charbuf");
        goto ExitOnError;
    }
    
    entry->descr.mcast_ttl = -1;
    if (cmd_mcastttl != NULL) {
        char *endptr;
        entry->descr.mcast_ttl = strtol(cmd_mcastttl, &endptr, 10); 
        if ((endptr != &cmd_mcastttl[strlen(cmd_mcastttl)]) ||
            entry->descr.mcast_ttl < 0 || entry->descr.mcast_ttl > 255) {
            ndndc_warn(__LINE__, "command error, invalid multicast ttl: %s\n", cmd_mcastttl);
            goto ExitOnError;
        }
    }
    
    if (cmd_mcastif != NULL) {
        res = getaddrinfo(cmd_mcastif, NULL, &mcasthints, &mcastifaddrinfo);
        if (res != 0) {
            ndndc_warn(__LINE__, "command error, incorrect multicat interface [%s]: "
                       "mcastifaddr getaddrinfo: %s\n", cmd_mcastif, gai_strerror(res));
            goto ExitOnError;
        }
        
        res = getnameinfo(mcastifaddrinfo->ai_addr, mcastifaddrinfo->ai_addrlen,
                          rhostnamebuf, sizeof(rhostnamebuf),
                          NULL, 0,
                          NI_NUMERICHOST | NI_NUMERICSERV);
        freeaddrinfo(mcastifaddrinfo);
        if (res != 0) {
            ndndc_warn(__LINE__, "command error, getnameinfo: %s\n", gai_strerror(res));
            goto ExitOnError;
        }
        
        off_source_address = entry->store->length;
        res = ndn_charbuf_append(entry->store, rhostnamebuf, strlen(rhostnamebuf)+1);
        if (res != 0) {
            ndndc_warn(__LINE__, "Cannot append to charbuf");
            goto ExitOnError;
        }
    }
    
    entry->descr.address = (const char *)(entry->store->buf + off_address);
    entry->descr.port = (const char *)(entry->store->buf + off_port);
    if (off_source_address >= 0) {
        entry->descr.source_address = (const char *)(entry->store->buf + off_source_address);
    }
    
    entry->lifetime = freshness;
    
    return entry;
    
ExitOnError:
    ndn_face_instance_destroy(&entry);
    return (NULL);
}

struct ndn_face_instance *
parse_ndn_face_instance_from_face(struct ndndc_data *self,
                                  const char *cmd_faceid)
{
    struct ndn_face_instance *entry = calloc(1, sizeof(*entry));
    
    // allocate storage for Face data
    entry->store = ndn_charbuf_create();
    
    // copy static info
    entry->ndnd_id = (const unsigned char *)self->ndnd_id;
    entry->ndnd_id_size = self->ndnd_id_size;
    
    /* destroy a face - the URI field will hold the face number */
    if (cmd_faceid == NULL) {
        ndndc_warn(__LINE__, "command error, missing face number for destroyface\n");
        goto ExitOnError;
    }
    
    char *endptr;
    int facenumber = strtol(cmd_faceid, &endptr, 10);
    if ((endptr != &cmd_faceid[strlen(cmd_faceid)]) ||
        facenumber < 0) {
        ndndc_warn(__LINE__, "command error invalid face number for destroyface: %d\n", facenumber);
        goto ExitOnError;
    }
    
    entry->faceid = facenumber;
    
    return entry;
    
ExitOnError:
    ndn_face_instance_destroy(&entry);
    return (NULL);
}



///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
// "private section
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

int
ndndc_get_ndnd_id(struct ndndc_data *self)
{
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *resultbuf = NULL;
    struct ndn_parsed_ContentObject pcobuf = {0};
    char ndndid_uri[] = "ndn:/%C1.M.S.localhost/%C1.M.SRV/ndnd/KEY";
    const unsigned char *ndndid_result;
    int res = 0;
    
    name = ndn_charbuf_create();
    if (name == NULL) {
        ndndc_warn(__LINE__, "Unable to allocate storage for service locator name charbuf\n");
        return -1;
    }
    
    resultbuf = ndn_charbuf_create();
    if (resultbuf == NULL) {
        ndndc_warn(__LINE__, "Unable to allocate storage for result charbuf");
        res = -1;
        goto Cleanup;
    }
    
    res = ndn_name_from_uri(name, ndndid_uri);
    if (res < 0) {
        ndndc_warn(__LINE__, "Unable to parse service locator URI for ndnd key");
        goto Cleanup;
    }
    
    res = ndn_get(self->ndn_handle,
                  name,
                  self->local_scope_template,
                  4500, resultbuf, &pcobuf, NULL, 0);
    if (res < 0) {
        ndndc_warn(__LINE__, "Unable to get key from ndnd");
        goto Cleanup;
    }
    
    res = ndn_ref_tagged_BLOB (NDN_DTAG_PublisherPublicKeyDigest,
                               resultbuf->buf,
                               pcobuf.offset[NDN_PCO_B_PublisherPublicKeyDigest],
                               pcobuf.offset[NDN_PCO_E_PublisherPublicKeyDigest],
                               &ndndid_result, &self->ndnd_id_size);
    if (res < 0) {
        ndndc_warn(__LINE__, "Unable to parse ndnd response for ndnd id");
        goto Cleanup;
    }
    
    if (self->ndnd_id_size > sizeof (self->ndnd_id))
    {
        ndndc_warn(__LINE__, "Incorrect size for ndnd id in response");
        goto Cleanup;
    }
    
    memcpy(self->ndnd_id, ndndid_result, self->ndnd_id_size);
    
Cleanup:
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&resultbuf);
    return (res);
}


struct ndn_face_instance *
ndndc_do_face_action(struct ndndc_data *self,
                     const char *action,
                     struct ndn_face_instance *face_instance)
{
    struct ndn_charbuf *newface = NULL;
    struct ndn_charbuf *signed_info = NULL;
    struct ndn_charbuf *temp = NULL;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *resultbuf = NULL;
    struct ndn_parsed_ContentObject pcobuf = {0};
    struct ndn_face_instance *new_face_instance = NULL;
    const unsigned char *ptr = NULL;
    size_t length = 0;
    int res = 0;
    
    face_instance->action = action;
    
    /* Encode the given face instance */
    newface = ndn_charbuf_create();
    ON_NULL_CLEANUP(newface);
    ON_ERROR_CLEANUP(ndnb_append_face_instance(newface, face_instance));
    
    temp = ndn_charbuf_create();
    ON_NULL_CLEANUP(temp);
    res = ndn_sign_content(self->ndn_handle, temp, self->no_name, NULL, newface->buf, newface->length);
    ON_ERROR_CLEANUP(res);
    resultbuf = ndn_charbuf_create();
    ON_NULL_CLEANUP(resultbuf);
    
    /* Construct the Interest name that will create the face */
    name = ndn_charbuf_create();
    ON_NULL_CLEANUP(name);
    ON_ERROR_CLEANUP(ndn_name_init(name));
    ON_ERROR_CLEANUP(ndn_name_append_str(name, "ndnx"));
    ON_ERROR_CLEANUP(ndn_name_append(name, face_instance->ndnd_id, face_instance->ndnd_id_size));
    ON_ERROR_CLEANUP(ndn_name_append_str(name, face_instance->action));
    ON_ERROR_CLEANUP(ndn_name_append(name, temp->buf, temp->length));
    
    res = ndn_get(self->ndn_handle, name, self->local_scope_template, 1000, resultbuf, &pcobuf, NULL, 0);
    ON_ERROR_CLEANUP(res);
    
    ON_ERROR_CLEANUP(ndn_content_get_value(resultbuf->buf, resultbuf->length, &pcobuf, &ptr, &length));
    new_face_instance = ndn_face_instance_parse(ptr, length);
    ON_NULL_CLEANUP(new_face_instance);
    ndn_charbuf_destroy(&newface);
    ndn_charbuf_destroy(&signed_info);
    ndn_charbuf_destroy(&temp);
    ndn_charbuf_destroy(&resultbuf);
    ndn_charbuf_destroy(&name);
    return (new_face_instance);
    
Cleanup:
    ndn_charbuf_destroy(&newface);
    ndn_charbuf_destroy(&signed_info);
    ndn_charbuf_destroy(&temp);
    ndn_charbuf_destroy(&resultbuf);
    ndn_charbuf_destroy(&name);
    ndn_face_instance_destroy(&new_face_instance);
    return (NULL);
}

int
ndndc_do_prefix_action(struct ndndc_data *self,
                       const char *action,
                       struct ndn_forwarding_entry *forwarding_entry)
{
    struct ndn_charbuf *temp = NULL;
    struct ndn_charbuf *resultbuf = NULL;
    struct ndn_charbuf *signed_info = NULL;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *prefixreg = NULL;
    struct ndn_parsed_ContentObject pcobuf = {0};
    struct ndn_forwarding_entry *new_forwarding_entry = NULL;
    
    const unsigned char *ptr = NULL;
    size_t length = 0;
    int res;
    
    forwarding_entry->action = action;
    
    prefixreg = ndn_charbuf_create();
    ON_NULL_CLEANUP(prefixreg);
    ON_ERROR_CLEANUP(ndnb_append_forwarding_entry(prefixreg, forwarding_entry));
    temp = ndn_charbuf_create();
    ON_NULL_CLEANUP(temp);
    res = ndn_sign_content(self->ndn_handle, temp, self->no_name, NULL, prefixreg->buf, prefixreg->length);
    ON_ERROR_CLEANUP(res);    
    resultbuf = ndn_charbuf_create();
    ON_NULL_CLEANUP(resultbuf);
    name = ndn_charbuf_create();
    ON_ERROR_CLEANUP(ndn_name_init(name));
    ON_ERROR_CLEANUP(ndn_name_append_str(name, "ndnx"));
    ON_ERROR_CLEANUP(ndn_name_append(name, forwarding_entry->ndnd_id, forwarding_entry->ndnd_id_size));
    ON_ERROR_CLEANUP(ndn_name_append_str(name, forwarding_entry->action));
    ON_ERROR_CLEANUP(ndn_name_append(name, temp->buf, temp->length));
    res = ndn_get(self->ndn_handle, name, self->local_scope_template, 1000, resultbuf, &pcobuf, NULL, 0);
    ON_ERROR_CLEANUP(res);
    ON_ERROR_CLEANUP(ndn_content_get_value(resultbuf->buf, resultbuf->length, &pcobuf, &ptr, &length));
    new_forwarding_entry = ndn_forwarding_entry_parse(ptr, length);
    ON_NULL_CLEANUP(new_forwarding_entry);
    
    res = new_forwarding_entry->faceid;
    
    ndn_forwarding_entry_destroy(&new_forwarding_entry);
    ndn_charbuf_destroy(&signed_info);
    ndn_charbuf_destroy(&temp);
    ndn_charbuf_destroy(&resultbuf);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&prefixreg);
    
    return (res);
    
    /* This is where ON_ERROR_CLEANUP sends us in case of an error
     * and we must free any storage we allocated before returning.
     */
Cleanup:
    ndn_charbuf_destroy(&signed_info);
    ndn_charbuf_destroy(&temp);
    ndn_charbuf_destroy(&resultbuf);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&prefixreg);
    
    return (-1);
}
