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

trap "cleanup; exit" 1 2 3 15

cleanup()
{
	kill `pgrep -x install.sh`
	kill `pgrep -x log.sh`
}

while true; do
	pgrep -x install.sh >/dev/null
	if [ $? -ne 0 ]; then
		/kcdt/install.sh &
	fi

	pgrep -x log.sh >/dev/null
	if [ $? -ne 0 ]; then
		/kcdt/log.sh &
	fi

	sleep 1
done
