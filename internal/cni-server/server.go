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
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/config/constants"
)

type Server interface {
	Start() error
	Stop()
}

type server struct {
	sync.Mutex
	unixSockPath string
	bpfMountPath string
	// qdiscs is for cleaning up all tc programs when merbridge exits
	// key: netns(inode), value: qdisc info
	qdiscs map[uint64]qdisc
	// listeners are the dummy sockets created for eBPF programs to fetch the current pod ip
	// key: netns(inode), value: net.Listener
	listeners map[uint64]net.Listener
	stop      chan struct{}
}

// NewServer returns a new CNI Server.
// the path this the unix path to listen.
func NewServer(unixSockPath string, bpfMountPath string) Server {
	if unixSockPath == "" {
		unixSockPath = path.Join(config.HostVarRun, "merbridge-cni.sock")
	}
	if bpfMountPath == "" {
		bpfMountPath = "/sys/fs/bpf"
	}
	return &server{
		unixSockPath: unixSockPath,
		bpfMountPath: bpfMountPath,
		qdiscs:       make(map[uint64]qdisc),
		listeners:    make(map[uint64]net.Listener),
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

	if err := s.checkAndRepairPodPrograms(); err != nil {
		log.Errorf("Failed to check existing pods: %v", err)
	}

	r := mux.NewRouter()
	r.Path(constants.CNICreatePodURL).
		Methods("POST").
		HandlerFunc(s.PodCreated)

	r.Path(constants.CNIDeletePodURL).
		Methods("POST").
		HandlerFunc(s.PodDeleted)

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

func (s *server) Stop() {
	s.cleanUpTC()
	close(s.stop)
}
