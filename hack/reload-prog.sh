#!/usr/bin/env bash

# Copyright © 2022 Merbridge Authors

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

usage() {
	echo "Usage: ./reload-prog.sh OPTIONS { [-m MODE] [-n NODE] [-p EBPFPROG] | -h }
		
			OPTIONS := {-v}
				-v : Enable verbose mode. It prints more information for debugging the failure of loading

			MODE := {istio | kuma | osm}
			NODE := {all | <node where ebpf programs needs reload>}
			EBPFPROG := {all | bind | connect | sockops | getsock | redir | sendmsg | recvmsg | xdp}

			Description: This script is just a utility script to help developers to load locally hacked
			eBPF programs in the existing Merbridge pods, so they don't have to redeploy the Merbridge 
			daemonset or can skip the manual steps and save time. 
			
			Some examples of using the script are:

			Load all the eBPF programs on all the nodes
	 		./reload-prog.sh -n all -p all
	
			Load connect eBPF program on worker-3 node
			./reload-prog.sh -n worker-3 -p connect
	
			Load all eBPF programs on worker-4 node
			./reload-prog.sh -n worker-4 -p all
	
			Load bind eBPF program on all worker node
			./reload-prog.sh -n all -p bind

			Load bind eBPF program on all worker nodes for kuma service mesh
			./reload-prog.sh -m kuma -n all -p bind

      Load bind eBPF program on all worker nodes for osm/osm-edge service mesh
      ./reload-prog.sh -m osm -n all -p bind

			Enable verbose mode of the script
			./reload-prog.sh -v -n worker-3 -p xdp		"
	exit 1
}

if [ $# -lt 1 ] ; then
    usage
fi

unset mode workernode ebpfprog
verbose=false

set_variable()
{
  local varname=$1
  shift
  if [ -z "${!varname}" ]; then
    eval "$varname=\"$@\""
  else
    echo "Error: \"-${opt}\" option is already set once, multiple inputs are not supported."
    usage
  fi
}

while getopts "hvn:m:p:" opt; do
	case ${opt} in
		v ) verbose=true;;
		n ) set_variable workernode $OPTARG;;
		p ) set_variable ebpfprog $OPTARG;;
		m ) set_variable mode $OPTARG;;
		h ) usage;;
		: ) echo "Please provide the required arguments"
			usage;;
		? ) echo "\"-$OPTARG\" is not a valid argument"
			usage;;
	esac
done

if [ -z "$mode" ]; then
  mode="istio"
fi

case $mode in
  istio ) mesh_number=1; namespace="istio-system";;
  kuma )  mesh_number=3; namespace="kuma-system";;
  osm )  mesh_number=3; namespace="osm-system";;
esac

if ! command -v kubectl &> /dev/null && command -v clang &> /dev/null && command -v bpftool &> /dev/null
then
	echo "Please ensure that kubectl/clang/bpftool are installed and in the path."
	exit
fi

declare -a podlist

get_pod_list() {
        if [ "$1" = "all" ] ;then
                podlist=( `kubectl get pods -n "$namespace" -l app=merbridge | awk '{print $1}'` )
        else
                podlist=( `kubectl get pods -n "$namespace" -o wide -l app=merbridge --field-selector spec.nodeName=$1 | awk '{print $1}'` )
        fi

	podlist=("${podlist[@]:1}")
        if [ ${#podlist[@]} -eq 0 ]; then
               echo "\"$1\" node/nodes is/are not running merbridge pod. Please provide connected worker node name or \"all\""
               exit 1
        fi
}

reload_all() {
	pod=$1
        reload_prog $pod "bind"
        reload_prog $pod "connect"
        reload_prog $pod "sockops"
        reload_prog $pod "getsock"
        reload_prog $pod "redir"
        reload_prog $pod "sendmsg"
        reload_prog $pod "recvmsg"
        reload_prog $pod "xdp"
}

reload_prog() {
	echo "*** Reloading eBPF prog \"$2\" on pod \"$1\" ***"
        pod=$1
	prog=$2
	if [ "$prog" = "getsock" ]; then
		clang -O2 -g  -Wall -target bpf -I/usr/include/x86_64-linux-gnu -DMESH="$mesh_number" -DUSE_RECONNECT -c mb_get_sockopts.c -o mb_get_sockopts.o
		kubectl cp ./mb_get_sockopts.o $pod:bpf/ -c merbridge -n "$namespace"
	else
		clang -O2 -g  -Wall -target bpf -I/usr/include/x86_64-linux-gnu -DMESH="$mesh_number" -DUSE_RECONNECT -c mb_$prog.c -o mb_$prog.o
		kubectl cp ./mb_$prog.o $pod:bpf/ -c merbridge -n "$namespace"
	fi

        kubectl exec -it $pod -c merbridge -n "$namespace" -- make -C bpf clean-$prog
        kubectl exec -it $pod -c merbridge -n "$namespace" -- make -C bpf load-$prog
	if [ "$prog" != "xdp" ]; then
        	kubectl exec -it $pod -c merbridge -n "$namespace" -- make -C bpf attach-$prog
	fi
}

show_bpfprog() {
	echo "*** Merbridge loaded eBPF Programs on pod $1 ***"
        pod=$1
        kubectl exec -it $pod -c merbridge -n "$namespace" -- /usr/local/sbin/bpftool prog show
}

show_progobj() {
	echo "*** Merbridge eBPF Object Files on pod $1***"
        pod=$1
        kubectl exec -it $pod -c merbridge -n "$namespace" -- ls -lrt ./bpf
}

get_pod_list $workernode
pushd ../bpf/

for pod in "${podlist[@]}"
do
	if [ "$verbose" = true ]; then show_bpfprog $pod; fi
	
	case $ebpfprog in
		"all") reload_all $pod;;
		"bind") reload_prog $pod $ebpfprog;;
		"connect") reload_prog $pod $ebpfprog;;
		"sockops") reload_prog $pod $ebpfprog;;
		"getsock") reload_prog $pod $ebpfprog;;
		"redir") reload_prog $pod $ebpfprog;;
		"sendmsg") reload_prog $pod $ebpfprog;;
		"recvmsg") reload_prog $pod $ebpfprog;;
		"xdp") reload_prog $pod $ebpfprog;;
		*) echo "\"$ebpfprog\" eBPF program is not supported.\n" 
		popd
		usage;;
	esac
	
	if [ "$verbose" = true ]; then show_progobj $pod; fi

	if [ "$verbose" = true ]; then show_bpfprog $pod; fi
done
popd
