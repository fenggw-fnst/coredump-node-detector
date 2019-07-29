#!/bin/sh
#
# Copyright (c) 2019 FUJITSU LIMITED. All rights reserved.
# Author: Guangwen Feng <fenggw-fnst@cn.fujitsu.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
#

INSTALL_PID=`cat /kcdt/install.pid`
CORE_PATTERN_RST=`cat /kcdt/core_pattern`
CORE_PIPE_LIMIT_RST=`cat /kcdt/core_pipe_limit`
INSTALL_DST="/kcdt/host/kcdt"

kill -9 $INSTALL_PID >/dev/null

sleep 1

sysctl -q kernel.core_pattern="$CORE_PATTERN_RST"
sysctl -q kernel.core_pipe_limit="$CORE_PIPE_LIMIT_RST"

if [ -x "$INSTALL_DST" ]; then
	rm -rf $INSTALL_DST
fi
