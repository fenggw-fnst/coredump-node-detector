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

loggerf()
{
	local level=$1
	shift
	local msg="$(date '+%Y-%m-%d %H:%M:%S') $@"
	case "$level" in
		INFO)
			echo "$level $msg"
			;;
		WARN)
			echo "$level $msg"
			;;
		ERR)
			echo "$level  $msg"
			exit 1
			;;
		*)
			echo "Invalid log level type $level"
			exit 1
			;;
	esac
}
