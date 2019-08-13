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

install_src="/kcdt/kcdt"
install_dst="/kcdt/host/kcdt"

if [ -z $HOSTVOL ]; then
	core_pattern="|/root/kcdt -c %c %d %e %E %g %h %i %I %p %P %s %t %u"
else
	core_pattern="|$HOSTVOL/kcdt -c %c %d %e %E %g %h %i %I %p %P %s %t %u"
fi

core_pipe_limit="64"

install()
{
	if [ ! -x "$install_dst" ]; then
		cp $install_src $install_dst
		if [ $? -eq 0 ]; then
			echo "kcdt was installed successfully"
		else
			echo "Failed to install kcdt"
		fi
	fi
}

core_config()
{
	local core_pattern_cur=`sysctl -n kernel.core_pattern`
	local core_pipe_limit_cur=`sysctl -n kernel.core_pipe_limit`

	if [ "$core_pattern_cur" != "$core_pattern" ]; then
		sysctl -q kernel.core_pattern="$core_pattern"
		if [ $? -eq 0 ]; then
			echo "core_pattern was updated successfully"
		else
			echo "Failed to update core_pattern"
		fi
	fi

	if [ "$core_pipe_limit_cur" != "$core_pipe_limit" ]; then
		sysctl -q kernel.core_pipe_limit="$core_pipe_limit"
		if [ $? -eq 0 ]; then
			echo "core_pipe_limit was updated successfully"
		else
			echo "Failed to update core_pipe_limit"
		fi
	fi
}

echo $$ >/kcdt/install.pid
if [ $? -ne 0 ]; then
	echo "Failed to create install.pid"
fi

while true; do
	install

	core_config

	sleep 1
done
