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

if [ -f "/kcdt/install.pid" ]; then
	INSTALL_PID=`cat /kcdt/install.pid`
else
	echo "install.pid does not exist"
fi

if [ -f "/kcdt/core_pattern.rst" ]; then
	CORE_PATTERN_RST=`cat /kcdt/core_pattern.rst`
else
	echo "core_pattern.rst does not exist"
fi

if [ -f "/kcdt/core_pipe_limit.rst" ]; then
	CORE_PIPE_LIMIT_RST=`cat /kcdt/core_pipe_limit.rst`
else
	echo "core_pipe_limit.rst does not exist"
fi

INSTALL_DST="/kcdt/host/kcdt"

kill -9 $INSTALL_PID >/dev/null
if [ $? -ne 0 ]; then
	echo "Failed to kill the installation process"
fi

sleep 1

sysctl -q kernel.core_pattern="$CORE_PATTERN_RST"
if [ $? -ne 0 ]; then
	echo "Failed to restore core_pattern"
fi

sysctl -q kernel.core_pipe_limit="$CORE_PIPE_LIMIT_RST"
if [ $? -ne 0 ]; then
	echo "Failed to restore core_pipe_limit"
fi

umount /kcdt/host/core
if [ $? -eq 0 ]; then
	rmdir /kcdt/host/core
	if [ $? -ne 0 ]; then
		echo "Failed to remove /kcdt/host/core"
	fi
else
	echo "Failed to umount /kcdt/host/core"
fi

if [ -x "$INSTALL_DST" ]; then
	rm -rf $INSTALL_DST
fi
