/**
 * @file ndndc.h
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

#ifndef NDNDC_H
#define NDNDC_H

#include <ndn/charbuf.h>

struct ndndc_prefix_entry;
struct ndn_forwarding_entry;
struct ndn_face_instance;

/**
 * @brief Internal data structure for ndndc
 */
struct ndndc_data
{
    struct ndn          *ndn_handle;
    char                ndnd_id[32];       //id of local ndnd
    size_t              ndnd_id_size;
    int                 lifetime;
    struct ndn_charbuf  *local_scope_template; // scope 1 template
    struct ndn_charbuf  *no_name;   // an empty name
};

/**
 * @brief Initialize internal data structures
 * @returns "this" pointer
 */
struct ndndc_data *
ndndc_initialize_data(void);

/**
 * @brief Destroy internal data structures
 * @brief data pointer to "this"
 */
void
ndndc_destroy_data(struct ndndc_data **data);

/**
 * @brief Select a correct command based on the supplied argument
 * @param self          data pointer to "this"
 * @param check_only    flag indicating that only command checking is requested (no messages are exchanged with ndnd)
 * @param cmd           command name (e.g., add, del, or destroyface)
 * @param options       command options
 * @param num_options   number of command line options (not checked if < 0)
 * @returns 0 on success, non zero means error, -99 means command line error
 */
int
ndndc_dispatch_cmd(struct ndndc_data *self,
                   int check_only,
                   const char *cmd,
                   const char *options,
                   int num_options);


/**
 * @brief Create a new FIB entry if it doesn't exist
 *
 * The call also automatically creates a face (if it doesn't exist)
 *
 * cmd format:
 *   uri (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
 *
 * @param self          data pointer to "this"
 * @param check_only    flag indicating that only command checking is requested (nothing will be created)
 * @param cmd           add command without leading 'add' component
 * @returns 0 on success
 */
int
ndndc_add(struct ndndc_data *self,
          int check_only,
          const char *cmd);


/**
 * @brief Delete a FIB entry if it exists
 *
 * cmd format:
 *   uri (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
 *
 * @param self          data pointer to "this"
 * @param check_only    flag indicating that only command checking is requested (nothing will be removed)
 * @param cmd           del command without leading 'del' component
 * @returns 0 on success
 */
int
ndndc_del(struct ndndc_data *self,
          int check_only,
          const char *cmd);

/**
 * @brief Delete a face and recreate it with the specified parameters and prefix
 *
 * cmd format:
 *   uri (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
 *
 * @param self          data pointer to "this"
 * @param check_only    flag indicating that only command checking is requested (nothing will be created)
 * @param cmd           add command without leading 'renew' component
 * @returns 0 on success
 */
int
ndndc_renew(struct ndndc_data *self,
          int check_only,
          const char *cmd);

/**
 * @brief Create a new face without adding any prefix to it
 *
 * cmd format:
 *   (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
 *
 * @param self          data pointer to "this"
 * @param check_only    flag indicating that only command checking is requested (nothing will be created)
 * @param cmd           create command without leading 'create' component
 * @returns 0 on success
 */
int
ndndc_create(struct ndndc_data *self,
          int check_only,
          const char *cmd);


/**
 * @brief Destroy a face
 *
 * cmd format:
 *   (udp|tcp) host [port [flags [mcastttl [mcastif [destroyface]]]]])
 *
 * @param self          data pointer to "this"
 * @param check_only    flag indicating that only command checking is requested (nothing will be removed)
 * @param cmd           destroy command without leading 'destroy' component
 * @returns 0 on success
 */
int
ndndc_destroy(struct ndndc_data *self,
          int check_only,
          const char *cmd);

/**
 * brief Add (and if exists recreated) FIB entry based on guess from SRV records for a specified domain
 * @param self          data pointer to "this"
 * @param domain        domain name
 * @param domain_size   size of the "domain" variable
 *
 * @returns 0 on success
 */
int
ndndc_srv(struct ndndc_data *self,
          const unsigned char *domain,
          size_t domain_size);

/**
 * @brief Destroy face if it exists
 *
 * cmd format:
 *   faceid
 *
 * @param self          data pointer to "this"
 * @param check_only    flag indicating that only command checking is requested (nothing will be destroyed)
 * @param cmd           destroyface command without leading 'destroyface' component
 * @returns 0 on success
 */
int
ndndc_destroyface(struct ndndc_data *self,
                  int check_only,
                  const char *cmd);

/**
 * @brief Get ID of the local NDND
 *
 * NDND ID is recorded in supplied ndndc_data data structure
 *
 * @param self          data pointer to "this"
 */
int
ndndc_get_ndnd_id(struct ndndc_data *self);

/**
 * @brief Perform action using face management protocol
 * @param self          data pointer to "this"
 * @param action        action string
 * @param face_instance filled ndn_face_instance structure
 * @returns on success returns a new struct ndn_face_instance, describing created/destroyed face
 *         the structure needs to be manually destroyed
 */
struct ndn_face_instance *
ndndc_do_face_action(struct ndndc_data *self,
                     const char *action,
                     struct ndn_face_instance *face_instance);

/**
 * @brief Perform action using prefix management protocol
 * @param self          data pointer to "this"
 * @param action        action string
 * @param forwarding_entry filled ndn_forwarding_entry structure
 * @returns 0 on success
 */
int
ndndc_do_prefix_action(struct ndndc_data *self,
                       const char *action,
                       struct ndn_forwarding_entry *forwarding_entry);



//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

struct ndn_forwarding_entry *
parse_ndn_forwarding_entry(struct ndndc_data *self,
                           const char *cmd_uri,
                           const char *cmd_flags,
                           int freshness);

struct ndn_face_instance *
parse_ndn_face_instance(struct ndndc_data *self,
                        const char *cmd_proto,
                        const char *cmd_host,     const char *cmd_port,
                        const char *cmd_mcastttl, const char *cmd_mcastif,
                        int freshness);

struct ndn_face_instance *
parse_ndn_face_instance_from_face(struct ndndc_data *self,
                                  const char *cmd_faceid);

#endif
