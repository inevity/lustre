#!/bin/sh
# Script to remove the loopback device and temp file created in newtest.sh
#
# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
OBDDIR="`dirname $0`/.."
. $OBDDIR/demos/config.sh


mount | grep "$MNTOBD " > /dev/null 2>&1
if [ x$? = x0 ]; then
    echo "Stuff still mounted on $MNTOBD"
    exit 1
fi

mount | grep "$MNTSNAP " > /dev/null 2>&1
if [ x$? = x0 ]; then
    echo "Stuff still mounted on $MNTSNAP"
    exit 2
fi

mount | grep "$MNTSNAP2 " > /dev/null 2>&1
if [ x$? = x0 ]; then
    echo "Stuff still mounted on $MNTSNAP2"
    exit 3
fi


if [ "$LOOPDEV" ]; then
    losetup -d $LOOPDEV
    rmmod loop > /dev/null 2>&1
fi

if [ "$LOOPDEV" -a "$TMPFILE" -a -f "$TMPFILE" ]; then
    rm -i $TMPFILE
fi

