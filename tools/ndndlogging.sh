#!@SH@
# Source file: util/ndndlogging.sh
# 
# Part of the NDNx distribution.
#
# Portions Copyright (C) 2013 Regents of the University of California.
# 
# Based on the CCNx C Library by PARC.
# Copyright (C) 2010 Palo Alto Research Center, Inc.
#
# This work is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2 as published by the
# Free Software Foundation.
# This work is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.
#

Usage () {
  echo $0 '[ -T host ] ( none | low | co | med | high ) - adjust logging level of running ndnd' >&2
  exit 1
}


# Adjust path for consistency.
D=`dirname "$0"`
export PATH="$D:$PATH"

# Process and check the arguments
case ":$1" in
    :-T) HOSTARG="$1 $2"; shift 2;;
esac
case ":$1" in
    :none) ;;
    :low)  ;;
    :co)   ;;
    :med)  ;;
    :high) ;;
    :*)    Usage;;
esac

echo "GET /?l=$1 " | \
  ndndsmoketest `echo $HOSTARG` -b send - recv |
  sed -n -e '/NDND_DEBUG/s/[<][/a-z]*[>]/ /gp'
