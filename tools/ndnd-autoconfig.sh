#!/usr/bin/env bash
# Source file: util/ndnd-autoconfig.sh
#
# Script that tries to (automatically) discover of a local ndnd gateway
#
# Part of the NDNx distribution.
#
# Portions Copyright (C) 2013 Regents of the University of California.
# 
# Based on the CCNx C Library by PARC.
# Copyright (C) 2012 Palo Alto Research Center, Inc.
#           (c) 2013 University of California, Los Angeles
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

DIG=${DIR:-"/usr/bin/dig"}

function do-need-to-reconfig {
    face=`ndndstatus | grep "ndn:/autoconf-route face" | awk '{print $3}'`
    if [ "x$face" == "x" ]; then
        return 0
    else
        return 1
    fi
}

function run-autoconfig {
    ndndstatus | grep 224.0.23.170:56363 > /dev/null
    MCAST_EXISTED=$?

    # Removing any previously created (either by this script or ndndc srv command) default route
    for i in `ndndstatus | grep "ndn:/autoconf-route face" | awk '{print $3}'`; do
       ndndc del / face $i
       ndndc del /autoconf-route face $i
    done

    # Set temporary multicast face
    ndndc -t 10 add "/local/ndn" udp  224.0.23.170 56363

    ###########################################################
    # Part one. Auto-discovery of ndnd in the same subnetwork #
    ###########################################################

    # Get info from local hub, if available
    info=`ndnpeek -w 1 -vs 2 -c /local/ndn/udp 2>/dev/null` # wait at most 1 second
    if [ "x$info" = "x" ]; then
       echo "Part one failed: local hub is not availble, trying to use DNS to get local configuration"

       ##############################################
       # Part two. Fallback configuration using DNS #
       ##############################################

       # Don't use "ndndc srv", because we need to remember the created automatic route
       info=`$DIG +search +short +cmd +tries=2 +ndots=10 _ndnx._udp srv | head -1 | awk '{print $4,$3}'`
       if [ "x$info" = "x" ]; then
           echo "Part two failed: DNS query for _ndnx._udp srv returned nothing, trying part three"

           PUBKEY_NAME=`ndn-pubkey-name`

           if [ -z "$PUBKEY_NAME" ]; then
               echo "ERROR: Part three failed: public key name is not configured"
               echo "Refer to ``man ndnd-autconfig''  for more information about how to set up public key name"
               return 1
           fi

           DNS_QUERY="_ndnx._udp.`ndn-name-dnsifier.py -r 1 -l 2 "$PUBKEY_NAME"`._homehub._autoconf.named-data.net"

           info=`$DIG +search +short +cmd +tries=2 +ndots=10 "$DNS_QUERY" srv | head -1 | awk '{print $4,$3}'`
           if [ "x$info" = "x" ]; then
               echo "ERROR: Part three failed: DNS query for "$DNS_QUERY" srv returned nothing"
               return 1
           else
               echo "OK: part three succeeded: $info"
           fi
       else
           echo "OK: part two succeeded: $info"
       fi
    else
        echo "OK: part one succeded: $info"
    fi

    echo Setting default route to a local hub: "$info"
    echo "$info" | xargs ndndc add / udp
    echo "$info" | xargs ndndc add /autoconf-route udp

    if [ $MCAST_EXISTED -eq 1 ]; then
       # destroying multicast face
       ndndstatus | grep 224.0.23.170:56363 | awk '{print $2}' | xargs ndndc destroy face
    fi
}

if [ "x$1" == "x-d" ]; then
    run-autoconfig

    PID=${2:-"/var/run/ndnd-autoconfig.pid"}
    if test -f $PID &&  ps -p `cat $PID` >&-; then
        # No need to run daemon, as it is already running
        exit 0
    fi

    echo $$ > $PID

    # Infinite loop with reconfig every 5 minutes
    while true; do
        if do-need-to-reconfig; then
            echo "Trying to reconfigure automatic route..."
            run-autoconfig
        fi
        sleep 10
    done
else
    run-autoconfig
    exit $?
fi

