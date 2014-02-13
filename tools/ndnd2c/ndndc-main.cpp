/**
 * @file ndndc-main.cpp
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

#include "ndndc.hpp"
#include "ndndc-srv.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <strings.h>
#include <errno.h>

namespace {

int
read_configfile(ndn::ndndc::Controller &ndndc, const std::string& filename);

void
usage(const char *progname)
{
  fprintf(stderr,
          "Usage:\n"
          "   %s [-h] [-d] [-v] [-t <lifetime>] (-f <configfile> | COMMAND)\n"
          "       -h print usage and exit\n"
          "       -f <configfile> add or delete FIB entries based on the content of <configfile>\n"
          "       -t use value in seconds for lifetime of prefix registration\n"
          "\n"
          "   COMMAND can be one of following:\n"
          "       (add|del) <uri> (udp|tcp) <host> [<port> [<flags> [<mcastttl> [<mcastif>]]]])\n"
          "           to add prefix to or delete prefix from face identified by parameters\n"
          "       (add|del) <uri> face <faceid>\n"
          "           to add prefix to or delete prefix from face identified by number\n"
          "       (create|destroy) (udp|tcp) <host> [<port> [<mcastttl> [<mcastif>]]])\n"
          "           create or destroy a face identified by parameters\n"
          "       destroy face <faceid>\n"
          "           destroy face identified by number\n"
          "       srv\n"
          "           add ndn:/ prefix to face created from parameters in SRV\n"
          "           record of a domain in DNS search list\n"
          ,
          progname);
}

std::string
create_command_from_command_line(int argc, char **argv)
{
  std::ostringstream os;
  if (argc >= 1)
    os << argv[0];

  for (int i = 1; i < argc; i++) {
    os << " " << argv[i];
  }
    
  return os.str();
}

} // anonymous namespace

struct Processor
{
public:
  Processor()
    : progname(NULL)
    , configfile(NULL)
    , res(1)
    , lifetime(-1)
  {
  }
  
  void
  Process()
  {
    if (optind < argc) {
      /* config file cannot be combined with command line */
      if (configfile != NULL) {
        throw ndn::ndndc::Controller::Error("Config file cannot be combined with command line");
        usage(progname);
        exit(res);
      }
        
      if (argc - optind < 0) {
        usage(progname);
        exit(res);
      }
        
      std::string cmd = create_command_from_command_line(argc-optind-1, &argv[optind+1]);
      int disp_res = controller->dispatch(0, argv[optind], cmd, argc - optind - 1);
      if (disp_res == INT_MIN) {
        usage(progname);
        exit(res);
      }
    }
    if (configfile) {
      read_configfile(*controller, configfile);
    }
  }
  
public:
  const char *progname;
  const char *configfile;
  int res;
  int lifetime;

  int argc;
  char **argv;

  ndn::ptr_lib::shared_ptr<ndn::ndndc::Controller> controller;
};

void
OnError()
{
  throw ndn::ndndc::Controller::Error("Error communicating with local NDN forwarder");
}

int
main(int argc, char **argv)
{
  Processor p;
  p.progname = argv[0];
  p.argc = argc;
  p.argv = argv;

  int opt;
  while ((opt = getopt(argc, argv, "hvt:f:")) != -1) {
    switch (opt) {
    case 'f':
      p.configfile = optarg;
      break;
    case 't':
      p.lifetime = atoi(optarg);
      if (p.lifetime <= 0) {
        usage(p.progname);
        return 1;
      }
      break;
    case 'h':
    default:
      usage(p.progname);
      return 1;
    }
  }
    
  if (p.configfile == NULL && optind == argc) {
    usage(p.progname);
    return 1;
  }

  p.controller = ndn::ptr_lib::make_shared<ndn::ndndc::Controller>(ndn::func_lib::bind(&Processor::Process, &p),
                                                                   OnError,
                                                                   p.lifetime);

  try {
    p.controller->getFace().processEvents();
  }
  catch(const std::exception &e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 2;
  }

  return 0;
}

namespace {

/**
 * @brief Process configuration file
 * @param ndndc a pointer to the structure holding internal ndndc data, from ndndc_initialize_data()
 * @param filename
 *
 * Processing configuration file in two rounds. First round performs a dry run
 * to check for errors.  If no erors found, commands are executing if normal mode.
 */
int
read_configfile(ndn::ndndc::Controller &ndndc, const std::string& filename)
{
  int configerrors;
  int lineno;
    
  FILE *cfg;
  char buf[1024];
  char *cp = NULL;
  char *cmd, *rest_of_the_command;
  int res;
  int phase;
  int retcode;
  int len;
    
  for (phase = 1; phase >= 0; --phase) {
    configerrors = 0;
    retcode = 0;
    lineno = 0;
    if (filename != "-")
      cfg = fopen(filename.c_str(), "r");
    else {
      cfg = stdin;
      phase = 0; // cannot read stdin twice...
    }
    
    if (cfg == NULL) {
      throw ndn::ndndc::Controller::Error(std::string(strerror(errno)) + "(" + filename + ")");
    }
        
    while (fgets((char *)buf, sizeof(buf), cfg)) {
      lineno++;
      len = strlen(buf);
      if (buf[0] == '#' || len == 0)
        continue;
      if (buf[len - 1] == '\n')
        buf[len - 1] = '\0';
      cp = index(buf, '#');
      if (cp != 0)
        *cp = '\0';
      if (strlen(buf) == 0)
        continue;

      rest_of_the_command = buf;
      do {
        cmd = strsep(&rest_of_the_command, " \t");
      } while (cmd != 0 && cmd[0] == 0);

      if (cmd == 0) /* blank line */
        continue;

      if ((phase == 1 || cfg == stdin) && rest_of_the_command == 0)
        {
          std::cerr << "WARN: " << "Error: near line " << lineno << std::endl;
          configerrors++;
          continue;
        }

      res = ndndc.dispatch(phase, cmd, rest_of_the_command, -1);
      retcode += res;
      if ((phase == 1 || cfg == stdin) && res < 0) {
        std::cerr << "WARN: " << "Error: near line " << lineno << std::endl;
        configerrors++;
      }
    }
    if (filename != "-")
      fclose(cfg);
    if (configerrors != 0)
      return (-configerrors);
  } 
  return (retcode);
}

} // anonymous namespace
