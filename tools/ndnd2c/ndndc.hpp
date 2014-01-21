/**
 * @file ndndc.hpp
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

#ifndef NDNDC_HPP
#define NDNDC_HPP

#include <ndn-cpp-dev/face.hpp>

#include <ndn-cpp-dev/forwarding-entry.hpp>
#include <ndn-cpp-dev/status-response.hpp>
#include <ndn-cpp-dev/face-instance.hpp>

namespace ndn {

/**
 * @brief Class implementing functions to create/destroy faces/prefixes of the local forwarding daemon
 */
class Controller // aka Ndnc
{
public:
  struct Error : public std::runtime_error { Error(const std::string &what) : std::runtime_error(what) {} };

  typedef func_lib::function<void(void)> OnReady;
  typedef func_lib::function<void(void)> OnFailure;
  
  Controller(OnReady onReady, OnFailure onFailure, int lifetime = -1);
  ~Controller();
 
  /**
   * @brief Select a correct command based on the supplied argument
   * @param check_only    flag indicating that only command checking is requested (no messages are exchanged with ndnd)
   * @param cmd           command name (e.g., add, del, or destroyface)
   * @param options       command options
   * @param num_options   number of command line options (not checked if < 0)
   * @returns 0 on success, non zero means error, -99 means command line error
   */
  int
  dispatch(int check_only,
           const std::string &cmd,
           const std::string &options,
           int num_options);
  /**
   * @brief Create a new FIB entry if it doesn't exist
   *
   * The call also automatically creates a face (if it doesn't exist)
   *
   * cmd format:
   *   uri (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
   *
   * @param check_only    flag indicating that only command checking is requested (nothing will be created)
   * @param cmd           add command without leading 'add' component
   * @returns 0 on success
   */
  int
  add(int check_only,
      const std::string &cmd);

  /**
   * @brief Delete a FIB entry if it exists
   *
   * cmd format:
   *   uri (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
   *
   * @param check_only    flag indicating that only command checking is requested (nothing will be removed)
   * @param cmd           del command without leading 'del' component
   * @returns 0 on success
   */
  int
  del(int check_only,
      const std::string &cmd);

  /**
   * @brief Delete a face and recreate it with the specified parameters and prefix
   *
   * cmd format:
   *   uri (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
   *
   * @param check_only    flag indicating that only command checking is requested (nothing will be created)
   * @param cmd           add command without leading 'renew' component
   * @returns 0 on success
   */
  int
  renew(int check_only,
        const std::string &cmd);

  /**
   * @brief Create a new face without adding any prefix to it
   *
   * cmd format:
   *   (udp|tcp) host [port [flags [mcastttl [mcastif]]]])
   *
   * @param check_only    flag indicating that only command checking is requested (nothing will be created)
   * @param cmd           create command without leading 'create' component
   * @returns 0 on success
   */
  int
  create(int check_only,
         const std::string &cmd);


  /**
   * @brief Destroy a face
   *
   * cmd format:
   *   (udp|tcp) host [port [flags [mcastttl [mcastif [destroyface]]]]])
   *
   * @param check_only    flag indicating that only command checking is requested (nothing will be removed)
   * @param cmd           destroy command without leading 'destroy' component
   * @returns 0 on success
   */
  int
  destroy(int check_only,
          const std::string &cmd);

  /**
   * brief Add (and if exists recreated) FIB entry based on guess from SRV records from a search list
   *
   * @returns 0 on success
   */
  int
  srv();

  /**
   * @brief Destroy face if it exists
   *
   * cmd format:
   *   faceid
   *
   * @param check_only    flag indicating that only command checking is requested (nothing will be destroyed)
   * @param cmd           destroyface command without leading 'destroyface' component
   * @returns 0 on success
   */
  int
  destroyface(int check_only,
              const std::string &cmd);


  Face&
  getFace()
  {
    return m_face;
  }
  
private:
  void
  startFaceAction(ptr_lib::shared_ptr<FaceInstance> entry,
                  func_lib::function< void (ptr_lib::shared_ptr<FaceInstance>) > onSuccess);

  void
  startPrefixAction(ptr_lib::shared_ptr<ForwardingEntry> entry,
                    func_lib::function< void (ptr_lib::shared_ptr<ForwardingEntry>) > onSuccess);
  

  //
  void
  add_or_del_step2(ptr_lib::shared_ptr<FaceInstance> face, ptr_lib::shared_ptr<ForwardingEntry> prefix);

  //
  void
  srv_step2(ptr_lib::shared_ptr<FaceInstance> face, ptr_lib::shared_ptr<ForwardingEntry> prefix);
  
  void
  srv_step3(ptr_lib::shared_ptr<FaceInstance> face, ptr_lib::shared_ptr<ForwardingEntry> prefix);
  
  void
  srv_step4(ptr_lib::shared_ptr<FaceInstance> face, ptr_lib::shared_ptr<ForwardingEntry> prefix);
  
  // int
  // do_prefix_action(const std::string &action,
  //                  struct ndn_forwarding_entry *forwarding_entry);

  ptr_lib::shared_ptr<ForwardingEntry>
  parse_ndn_forwarding_entry(const std::string &cmd_uri,
                             const std::string &cmd_flags,
                             int freshness);
  
  ptr_lib::shared_ptr<FaceInstance>
  parse_ndn_face_instance(const std::string &cmd_proto,
                          const std::string &cmd_host,     const std::string &cmd_port,
                          const std::string &cmd_mcastttl, const std::string &cmd_mcastif,
                          int freshness);

  ptr_lib::shared_ptr<FaceInstance>
  parse_ndn_face_instance_from_face(const std::string &cmd_faceid);
  
private:
  Buffer m_ndndid;
  
  Face m_face;
  int  m_lifetime;
  // struct ndn_charbuf  *no_name;   // an empty name
};

} // namespace ndn

#endif
