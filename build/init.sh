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

echo `sysctl -n kernel.core_pattern` >/kcdt/core_pattern.rst
if [ $? -ne 0 ]; then
	echo "Failed to create core_pattern.rst"
fi

echo `sysctl -n kernel.core_pipe_limit` >/kcdt/core_pipe_limit.rst
if [ $? -ne 0 ]; then
	echo "Failed to create core_pipe_limit.rst"
fi

sleep 1

/kcdt/install.sh &

while true; do
	sleep 30
done
