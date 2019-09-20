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

kcdt_pipe=/kcdt/host/kcdt.pipe

. /kcdt/helper.sh

post_low_disk_event()
{
	local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	local namespace=$1

	if [ -z $namespace ]; then
		return 1
	fi

	curl -d \
	'{
		"apiVersion": "v1",
		"firstTimestamp": "'"$timestamp"'",
		"involvedObject": {
			"apiVersion": "v1",
			"kind": "Pod",
			"namespace": "'"$namespace"'"
		},
		"kind": "Event",
		"lastTimestamp": "'"$timestamp"'",
		"message": "Low disk space for current namespace to save core files",
		"metadata": {
			"name": "coredump low disk warning",
			"namespace": "'"$namespace"'"
		},
		"reason": "Coredumped",
		"source": {
			"component": "coredump-collector"
		},
		"type": "Warning"
	}' \
	--cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
	-H "Authorization: Bearer `cat /var/run/secrets/kubernetes.io/serviceaccount/token`" \
	-H "Content-Type: application/json" \
	-X POST \
	https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_PORT_443_TCP_PORT/api/v1/namespaces/$namespace/events \
	>/dev/null 2>&1
}

check_low_disk_space()
{
	shift 3

	echo $@ | grep -q "Low disk space"
	if [ $? -eq 0 ]; then
		post_low_disk_event $2
	fi
}

while true; do
	if [ ! -p $kcdt_pipe ]; then
    		sleep 1
		continue
	fi

	if read line <$kcdt_pipe; then
		echo $line

		check_low_disk_space $line
		if [ $? -ne 0 ]; then
			loggerf WARN "Failed to report low disk space warning"
		fi
	fi
done
