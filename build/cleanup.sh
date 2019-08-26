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

run_pid=/kcdt/run.pid
kcdt_pipe=/kcdt/host/kcdt.pipe
install_dst=/kcdt/host/kcdt
core_pattern_rst=/kcdt/core_pattern.rst
core_pipe_limit_rst=/kcdt/core_pipe_limit.rst
coredump_mp=/kcdt/host/core

. /kcdt/helper.sh

if [ -f $run_pid ]; then
	kill `cat $run_pid`
else
	loggerf WARN "$run_pid does not exist"
fi

sleep 1

if [ -p $kcdt_pipe ]; then
	rm -f $kcdt_pipe
else
	loggerf WARN "$kcdt_pipe does not exist or not a pipe"
fi

if [ -x $install_dst ]; then
	rm -f $install_dst
else
	loggerf WARN "$install_dst does not exist or not executable"
fi

if [ -f $core_pattern_rst ]; then
	for i in $(seq 1 10); do
		sysctl kernel.core_pattern="`cat $core_pattern_rst`" >/dev/null
		if [ $? -eq 0 ]; then
			loggerf INFO "core_pattern was restored successfully"
			break
		else
			loggerf WARN "Failed to restore core_pattern"
		fi
	done
else
	loggerf WARN "$core_pattern_rst does not exist"
fi

if [ -f $core_pipe_limit_rst ]; then
	for i in $(seq 1 10); do
		sysctl kernel.core_pipe_limit=`cat $core_pipe_limit_rst` >/dev/null
		if [ $? -eq 0 ]; then
			loggerf INFO "core_pipe_limit was restored successfully"
			break
		else
			loggerf WARN "Failed to restore core_pipe_limit"
		fi
	done
else
	loggerf WARN "$core_pipe_limit_rst does not exist"
fi

umount $coredump_mp
if [ $? -eq 0 ]; then
	rmdir $coredump_mp
fi
