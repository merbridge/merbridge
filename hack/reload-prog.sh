#/bin/sh

usage() {
	echo "Usage: ./reload-prog.sh OPTIONS { [-n NODE] [-p EBPFPROG] | -h }
		
			OPTIONS := {-v}
				-v : Enable verbose mode. It prints more information for debugging the failure of loading
                
			NODE := {all | <node where ebpf programs needs reload>}
			EBPFPROG := {all | bind | connect | sockops | getsock | redir | sendmsg | recvmsg | xdp}
		
			Description: This script is just a utility script to help developers to load locally hecked 
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
	
			Enable verbose mode of the script
			./reload-prog.sh -v -n worker-3 -p xdp		"
	exit 1
}

if [ $# -lt 1 ] ; then
    usage
fi

unset workernode ebpfprog 
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

while getopts "hvn:p:" opt; do
	case ${opt} in
		v ) verbose=true;;
		n ) set_variable workernode $OPTARG;;
		p ) set_variable ebpfprog $OPTARG;;
		h ) usage;;
		: ) echo "Please provide the required arguments"
			usage;;
		? ) echo "\"-$OPTARG\" is not a valid argument"
			usage;;
	esac
done

if ! command -v kubectl &> /dev/null && command -v clang &> /dev/null && command -v bpftool &> /dev/null
then
	echo "Please ensure that kubectl/clang/bpftool are installed and in the path."
	exit
fi

declare -a podlist

get_pod_list() {
        if [ "$1" = "all" ] ;then
                podlist=( `kubectl get pods -n istio-system | grep merbridge | awk '{print $1}'` )
        else
                podlist=( `kubectl get pods -n istio-system -o wide | grep $1 | grep merbridge | awk '{print $1}'` )
        fi

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
		clang -O2 -g  -Wall -target bpf -I/usr/include/x86_64-linux-gnu  -DMESH=1 -DUSE_RECONNECT -c mb_get_sockopts.c -o mb_get_sockopts.o
		kubectl cp ./mb_get_sockopts.o $pod:bpf/ -c merbridge -n istio-system
	else
		clang -O2 -g  -Wall -target bpf -I/usr/include/x86_64-linux-gnu  -DMESH=1 -DUSE_RECONNECT -c mb_$prog.c -o mb_$prog.o
		kubectl cp ./mb_$prog.o $pod:bpf/ -c merbridge -n istio-system
	fi

        kubectl exec -it $pod -c merbridge -n istio-system -- make -C bpf clean-$prog
        kubectl exec -it $pod -c merbridge -n istio-system -- make -C bpf load-$prog
	if [ "$prog" != "xdp" ]; then
        	kubectl exec -it $pod -c merbridge -n istio-system -- make -C bpf attach-$prog
	fi
}

show_bpfprog() {
	echo "*** Merbridge loaded eBPF Programs on pod $1 ***"
        pod=$1
        kubectl exec -it $pod -c merbridge -n istio-system -- /usr/local/sbin/bpftool prog show
}

show_progobj() {
	echo "*** Merbridge eBPF Object Files on pod $1***"
        pod=$1
        kubectl exec -it $pod -c merbridge -n istio-system -- ls -lrt ./bpf
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
