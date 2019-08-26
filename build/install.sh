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

install_src=/kcdt/kcdt
install_dst=/kcdt/host/kcdt
kcdt_pipe=/kcdt/host/kcdt.pipe

. /kcdt/helper.sh

if [ -z $HOSTVOL ]; then
	hostvol=/root
else
	hostvol=$HOSTVOL
fi

if [ -z "$NS_DISK_QUOTA" ]; then
	ns_disk_quota="1GB"
else
	ns_disk_quota=`echo $NS_DISK_QUOTA | tr -d ' \t'`
fi

core_pattern="|$hostvol/kcdt $ns_disk_quota %c %d %e %E %g %h %i %I %p %P %s %t %u"
core_pipe_limit=64

install()
{
	if [ ! -x $install_dst ]; then
		cp $install_src $install_dst
		if [ $? -eq 0 ]; then
			loggerf INFO "kcdt was installed successfully"
		else
			loggerf WARN "Failed to install kcdt"
		fi
	fi

	if [ ! -p $kcdt_pipe ]; then
		mkfifo $kcdt_pipe
		if [ $? -eq 0 ]; then
			loggerf INFO "pipe was created successfully"
		else
			loggerf WARN "Failed to create pipe"
		fi
	fi
}

core_config()
{
	local core_pattern_cur=`sysctl -n kernel.core_pattern`
	local core_pipe_limit_cur=`sysctl -n kernel.core_pipe_limit`

	if [ "$core_pattern_cur" != "$core_pattern" ]; then
		sysctl kernel.core_pattern="$core_pattern" >/dev/null
		if [ $? -eq 0 ]; then
			loggerf INFO "core_pattern was updated successfully"
		else
			loggerf WARN "Failed to update core_pattern"
		fi
	fi

	if [ $core_pipe_limit_cur -ne $core_pipe_limit ]; then
		sysctl kernel.core_pipe_limit=$core_pipe_limit >/dev/null
		if [ $? -eq 0 ]; then
			loggerf INFO "core_pipe_limit was updated successfully"
		else
			loggerf WARN "Failed to update core_pipe_limit"
		fi
	fi
}

while true; do
	install

	core_config

	sleep 1
done
