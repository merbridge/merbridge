/*
Copyright © 2022 Merbridge Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cniserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"
	"time"

	passfd "github.com/ftrvxmtrx/fd"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/config/constants"
)

var (
	TransferFdSockName    = "/tmp/bpf-transfer-fd.sock"
	BpfBackServer         = "/host/var/run/bpf-back-server.sock"
	FdServerTransferFdURL = "/v1/transfer-fds"
	FdServerStandbyURL    = "/v1/standby"
)

type Server interface {
	Start() error
	Stop()
}

type server struct {
	sync.Mutex
	serviceMeshMode string
	unixSockPath    string
	bpfMountPath    string
	// qdiscs is for cleaning up all tc programs when merbridge exits
	// key: netns(inode), value: qdisc info
	qdiscs map[uint64]qdisc
	// listeners are the dummy sockets created for eBPF programs to fetch the current pod ip
	// key: netns(inode), value: net.Listener
	listeners      map[uint64]net.Listener
	stop           chan struct{}
	hotUpgradeFlag bool
	wg             sync.WaitGroup
}

// NewServer returns a new CNI Server.
// the path this the unix path to listen.

func NewServer(serviceMeshMode string, unixSockPath string, bpfMountPath string, stop chan struct{}) Server {
	if unixSockPath == "" {
		unixSockPath = path.Join(config.HostVarRun, "merbridge-cni.sock")
	}
	if bpfMountPath == "" {
		bpfMountPath = "/sys/fs/bpf"
	}
	return &server{
		serviceMeshMode: serviceMeshMode,
		unixSockPath:    unixSockPath,
		bpfMountPath:    bpfMountPath,
		qdiscs:          make(map[uint64]qdisc),
		listeners:       make(map[uint64]net.Listener),
		stop:            stop,
		hotUpgradeFlag:  false,
	}
}

func (s *server) Start() error {
	if err := os.RemoveAll(s.unixSockPath); err != nil {
		log.Fatal(err)
	}
	l, err := net.Listen("unix", s.unixSockPath)
	if err != nil {
		log.Fatal("listen error:", err)
	}

	if config.EnableHotRestart {
		s.transferFdBack()
	}

	if err = s.checkAndRepairPodPrograms(); err != nil {
		log.Errorf("Failed to check existing pods: %v", err)
	}

	r := mux.NewRouter()
	r.Path(constants.CNICreatePodURL).
		Methods("POST").
		HandlerFunc(s.PodCreated)

	r.Path(constants.CNIDeletePodURL).
		Methods("POST").
		HandlerFunc(s.PodDeleted)

	r.Path(constants.CNITransferFdStartURL).
		Methods("POST").
		HandlerFunc(s.TransferFd)

	ss := http.Server{
		Handler:      r,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	go func() {
		go ss.Serve(l) // nolint: errcheck
		// TODO: unify all clean-up functions
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGABRT)
		select {
		case <-ch:
			s.Stop()
		case <-s.stop:
			s.Stop()
		}
		_ = ss.Shutdown(context.Background())
	}()
	return nil
}

func (s *server) PutFd(ld net.Listener, unixconn net.Conn) {
	tcpln := ld.(*net.TCPListener)
	f, err := tcpln.File()
	if err != nil {
		log.Errorf("get tcp listen file err: %v", err)
		return
	}
	inode, err := getInoFromFd(f)
	if err != nil {
		log.Errorf("get inode err: %v", err)
		return
	}
	if err != nil {
		log.Errorf("parse listen err: %v", err)
	}
	err = passfd.Put(unixconn.(*net.UnixConn), f)
	if err != nil {
		log.Errorf("passfd put fd err: %v", err)
	}
	f.Close()
	s.Lock()
	delete(s.listeners, inode)
	s.Unlock()
}

func getUnixSock(sockName string) (unixSock net.Listener, err error) {
	os.Remove(sockName)
	unix, err := net.Listen("unix", sockName)
	if err != nil {
		return unix, err
	}
	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", BpfBackServer)
			},
		},
	}
	bs, _ := json.Marshal("")
	body := bytes.NewReader(bs)

	_, err = httpc.Post("http://bpf-back-server"+FdServerTransferFdURL, "application/json", body)
	if err != nil {
		log.Errorf("transfer fd err: %v", err)
		return unix, err
	}
	return unix, nil
}

func (s *server) transferFds() {
	log.Debugf("start transferring %d fds...", len(s.listeners))
	if len(s.listeners) > 0 {
		unixSock, err := getUnixSock(TransferFdSockName)
		if err != nil {
			log.Error(err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			unixconn, err := unixSock.Accept()
			if err != nil {
				log.Errorf("unix get conn err: %v", err)
				return
			}
			defer s.Unlock()
			s.Lock()

			for _, ld := range s.listeners {
				s.PutFd(ld, unixconn)
			}
			s.hotUpgradeFlag = true

			log.Debugf("complete %d fds transfers", len(s.listeners))
		}()
		s.wg.Wait()
	}
}

func (s *server) transferFd(ln net.Listener) {
	log.Debugf("start transferring fd(%v) ...", ln)
	if ln != nil {
		unixSock, err := getUnixSock(TransferFdSockName)
		if err != nil {
			log.Error(err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			unixconn, err := unixSock.Accept()
			if err != nil {
				log.Errorf("unix get conn err: %v", err)
				return
			}
			defer s.Unlock()
			s.Lock()
			s.PutFd(ln, unixconn)
			log.Debugf("complete fd(%v) transfers", ln)
		}()
		s.wg.Wait()
	}
}

func (s *server) transferFdBack() {
	// send reset request to fd backup server
	log.Debug("start reset backup server fd")
	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", BpfBackServer)
			},
		},
	}
	bs, _ := json.Marshal("")
	body := bytes.NewReader(bs)
	req, err := http.NewRequest("POST", "http://bpf-back-server"+FdServerStandbyURL, body)
	if err != nil {
		log.Errorf("make req err: %v", err)
		return
	}
	resp, err := httpc.Do(req)
	if err != nil {
		log.Errorf("post request back fd err: %v", err)
		return
	}
	if resp.StatusCode == 200 {
		unixconn, err := net.Dial("unix", TransferFdSockName)
		if err != nil {
			log.Errorf("dial unix err: %v", err)
			return
		}

		for {
			files, err := passfd.Get(unixconn.(*net.UnixConn), 1, nil)
			if err != nil {
				log.Errorf("passfd get err: %v", err)
				break
			}
			f := files[0]
			tcpln, err := net.FileListener(f)
			if err != nil {
				log.Errorf("listening fd(%v) err: %v", f, err)
				continue
			}
			_inode, err := getInoFromFd(f)
			if err != nil {
				log.Errorf("get inode err: %v", err)
				continue
			}
			if s.listeners == nil {
				s.listeners = make(map[uint64]net.Listener)
			}
			s.listeners[_inode] = tcpln

			go func() {
				for {
					_, err := tcpln.Accept()
					if err != nil {
						break
					}
				}
			}()
			f.Close()
		}
		unixconn.Close()

	}
}

func getInoFromFd(f *os.File) (uint64, error) {
	fileinfo, _ := f.Stat()
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("not a syscall.Stat_t")
	}
	return stat.Ino, nil
}

func (s *server) Stop() {
	log.Infof("cni-server stop ...")
	if config.EnableHotRestart {
		s.wg.Wait()
		s.transferFds()
	}
	s.cleanUpTC()
	close(s.stop)
}
