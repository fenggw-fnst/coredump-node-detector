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

install_pid=/kcdt/install.pid
install_dst=/kcdt/host/kcdt
core_pattern_rst=/kcdt/core_pattern.rst
core_pipe_limit_rst=/kcdt/core_pipe_limit.rst
coredump_mp=/kcdt/host/core

if [ -f $install_pid ]; then
	kill `cat $install_pid`
	if [ $? -ne 0 ]; then
		echo "Failed to kill installation process"
	fi
else
	echo "$install_pid does not exist"
fi

if [ -x $install_dst ]; then
	rm -f $install_dst
else
	echo "$install_dst does not exist or not executable"
fi

if [ -f $core_pattern_rst ]; then
	sysctl -q kernel.core_pattern="`cat $core_pattern_rst`"
	if [ $? -ne 0 ]; then
		echo "Failed to restore core_pattern"
	fi
else
	echo "$core_pattern_rst does not exist"
fi

if [ -f $core_pipe_limit_rst ]; then
	sysctl -q kernel.core_pipe_limit=`cat $core_pipe_limit_rst`
	if [ $? -ne 0 ]; then
		echo "Failed to restore core_pipe_limit"
	fi
else
	echo "$core_pipe_limit_rst does not exist"
fi

umount $coredump_mp
if [ $? -eq 0 ]; then
	rmdir $coredump_mp
	if [ $? -ne 0 ]; then
		echo "Failed to remove $coredump_mp"
	fi
else
	echo "Failed to umount $coredump_mp"
fi
