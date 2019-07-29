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

INSTALL_SRC="/kcdt/kcdt"
INSTALL_DST="/kcdt/host/kcdt"
CORE_PATTERN_RST=`sysctl -n kernel.core_pattern`
CORE_PIPE_LIMIT_RST=`sysctl -n kernel.core_pipe_limit`

if [ -z $HOSTVOL ]; then
	CORE_PATTERN="|/root/kcdt -c %c %d %e %E %g %h %i %I %p %P %s %t %u"
else
	CORE_PATTERN="|$HOSTVOL/kcdt -c %c %d %e %E %g %h %i %I %p %P %s %t %u"
fi

CORE_PIPE_LIMIT="64"

fail()
{
	echo $@
	exit 1
}

install()
{
	if [ ! -x "$INSTALL_DST" ]; then
		cp $INSTALL_SRC $INSTALL_DST
		if [ $? -ne 0 ]; then
			fail "Failed to install kcdt"
		fi
	fi
}

core_config()
{
	local cur_pattern=`sysctl -n kernel.core_pattern`
	local cur_pipe_limit=`sysctl -n kernel.core_pipe_limit`

	if [ "$cur_pattern" != "$CORE_PATTERN" ]; then
		sysctl -q kernel.core_pattern="$CORE_PATTERN"
		if [ $? -ne 0 ]; then
			fail "Failed to set core_pattern"
		fi
	fi

	if [ "$cur_pipe_limit" != "$CORE_PIPE_LIMIT" ]; then
		sysctl -q kernel.core_pipe_limit="$CORE_PIPE_LIMIT"
		if [ $? -ne 0 ]; then
			fail "Failed to set core_pipe_limit"
		fi
	fi
}

echo $CORE_PATTERN_RST >/kcdt/core_pattern
echo $CORE_PIPE_LIMIT_RST >/kcdt/core_pipe_limit
echo $$ >/kcdt/install.pid

while true; do
	install

	core_config

	sleep 1
done
