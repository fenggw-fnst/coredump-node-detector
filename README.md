kcdt
====

A core dump handler program for kubernetes cluster.

It works on the host machine of every k8s node by the way of
"Piping core dumps to a program" (See man 5 core for details).

The installation and configuration to the host machine are
managed by a privileged pod deployed via k8s daemonset.

When a core dump occurred, it will collect the k8s related
information such as k8s namespace, pod uid and container name
as a label to store the coredump files. The other part of this
project provides the authorized user download according it.
(See github.com/WanLinghao/coredump-detector)

Currently the container runtimes it supports are docker and cri-o.


## Install

1. Make sure the host machine of every k8s node has installed the libcurl package.

2. Complete the k8s daemonset configuration file refer to sample.yaml.

3. $ kubectl apply -f sample.yaml


## Build

1. Prerequisites:
  * libcurl
  * cJSON (static compilation)
  * procps (static compilation)

2. Compile:
  $ gcc kcdt.c -o build/kcdt -lcurl -l:libcjson.a -l:libprocps.a

3. Build docker image:
  $ cd buildImage
  $ docker build -t name:tag .


## Open source licenses
  * cURL: MIT/X derivate license
  * cJSON: MIT
  * procps: GNU GPLv2

## License

  Copyright (c) 2019 FUJITSU LIMITED. All rights reserved.
  Author: Guangwen Feng <fenggw-fnst@cn.fujitsu.com>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>.

