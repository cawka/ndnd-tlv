#!@SH@
# Source file: util/ndnd-autoconfig.sh
# 
# Script to publish information about local ndnd gateway in local repo (should be run only on ndnd gateway nodes)
#
# Part of the NDNx distribution.
#
# Portions Copyright (C) 2013 Regents of the University of California.
# 
# Based on the CCNx C Library by PARC.
# Copyright (C) 2012 Palo Alto Research Center, Inc.
#
# This work is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2 as published by the
# Free Software Foundation.
# This work is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.

# This script should be installed in the same place as ndnd, ndndc, ndndsmoketest, ...
# adjust the path to get consistency.
D=`dirname "$0"`
export PATH="$D:$PATH"

#

udp_face_info=$1
local_prefix=$2

if [ "x$udp_face_info" = "x" -o "x$local_prefix" = "x" ]; then
   echo "Usage: "
   echo "      " $0 " <udp_face_info> <routable_prefix>"
   exit 1
fi

echo $udp_face_info | ndnseqwriter -s 1 -r -x 5 "/local/ndn/udp"
echo $local_prefix  | ndnseqwriter -s 1 -r -x 5 "/local/ndn/prefix"

