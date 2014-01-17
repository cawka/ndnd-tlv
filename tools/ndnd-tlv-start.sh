#!@SH@
# Source file: util/ndndstart.sh
# Start ndnd in the background and set up forwarding according to configuration
# 
# Part of the NDNx distribution.
#
# Portions Copyright (C) 2013 Regents of the University of California.
# 
# Based on the CCNx C Library by PARC.
# Copyright (C) 2009-2013 Palo Alto Research Center, Inc.
#
# This work is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License version 2 as published by the
# Free Software Foundation.
# This work is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.
#

# This script should be installed in the same place as ndnd-tlv, ndnd2c, ndndsmoketest, ...
# adjust the path to get consistency.
D=`dirname "$0"`
export PATH="$D:$PATH"

# Source a file containing settings, if present.
# To learn about things that you can set, use this command: ndnd -h
test -f $HOME/.ndnx/ndndrc && . $HOME/.ndnx/ndndrc

StuffPreload () {
    # Stuff preloaded content objects into ndnd
    # To use this feature, set NDND_PRELOAD in ~/.ndnx/ndndrc
    # Also has side effect of waiting until ndnd is up, even if no preload
    # First a brief delay to give forked ndnd a chance to start
    ndndsmoketest -u localhost -t 50 recv >/dev/null
    ndndsmoketest -b `for i in $NDND_PRELOAD; do echo send $i; done` >/dev/null
}

# Provide defaults
: ${NDND_CAP:=50000}
: ${NDND_DEBUG:=''}
export NDN_LOCAL_PORT NDND_CAP NDND_DEBUG NDND_AUTOREG NDND_LISTEN_ON NDND_MTU
# The following are rarely used, but include them for completeness
export NDN_LOCAL_SOCKNAME NDND_DATA_PAUSE_MICROSEC NDND_KEYSTORE_DIRECTORY
export NDND_DEFAULT_TIME_TO_STALE NDND_MAX_TIME_TO_STALE NDND_PREFIX
export NDND_MAX_RTE_MICROSEC

# If a ndnd is already running, try to shut it down cleanly.
ndndsmoketest kill 2>/dev/null

# Fork ndnd, with a log file if requested.
if [ "$NDND_LOG" = "" ]
then
	ndnd-tlv &
        StuffPreload
else
	: >"$NDND_LOG" || exit 1
	ndnd-tlv 2>"$NDND_LOG" &
        StuffPreload 2> /dev/null
fi

# Run ndnd2c if a static config file is present.
test -f $HOME/.ndnx/ndnd.conf && ndnd2c -f $HOME/.ndnx/ndnd.conf

# Start a repository as well, if a global prefix has been configured.
if [ "$NDNR_GLOBAL_PREFIX" != "" ]
then
mkdir -p $HOME/.ndnx/repository
export NDNR_DIRECTORY=$HOME/.ndnx/repository
export NDNR_GLOBAL_PREFIX
ndnr 2>>$NDNR_DIRECTORY/log &
fi

