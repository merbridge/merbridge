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

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	passfd "github.com/ftrvxmtrx/fd"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const (
	TransferFdSockName = "/tmp/bpf-transfer-fd.sock"
	BpfBackServer      = "/host/var/run/bpf-back-server.sock"
	CNITransferFdURL   = "/v1/transferFd"
	CNIStandbyURL      = "/v1/standby"
)

var listener net.Listener

type Server struct {
	sync.Mutex
	stop         chan struct{}
	unixSockPath string
	listeners    []net.Listener
}

func NewServer(unixSockPath string) *Server {
	if unixSockPath == "" {
		unixSockPath = BpfBackServer
	}
	return &Server{
		unixSockPath: unixSockPath,
	}
}

func (s *Server) Start() (err error) {
	if err := os.RemoveAll(s.unixSockPath); err != nil {
		log.Fatal(err)
	}
	listener, err = net.Listen("unix", s.unixSockPath)

	if err != nil {
		log.Fatal("listen error:", err)
	}
	r := mux.NewRouter()
	r.Path(CNITransferFdURL).
		Methods("POST").
		HandlerFunc(s.TransferFd)

	r.Path(CNIStandbyURL).
		Methods("POST").
		HandlerFunc(s.TransferFdBack)

	ss := http.Server{
		Handler:      r,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	go func() {
		err = ss.Serve(listener)
		if err != nil {
			panic(fmt.Sprintf("http server start fail:%v", err))
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGABRT)
	for {
		select {
		case <-ch:
			s.Stop()
			_ = ss.Shutdown(context.Background())
			return
		case <-s.stop:
			s.Stop()
			_ = ss.Shutdown(context.Background())
		}
	}
}

func (s *Server) TransferFd(w http.ResponseWriter, req *http.Request) {
	unixconn, err := net.Dial("unix", TransferFdSockName)
	if err != nil {
		log.Errorf("dial unix %s error", err)
		w.WriteHeader(500)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	go func() {
		defer unixconn.Close()
		for {
			files, err := passfd.Get(unixconn.(*net.UnixConn), 1, nil)
			if err != nil {
				log.Errorf("passfd get err:%v", err)
				w.WriteHeader(500)
				_, _ = w.Write([]byte(err.Error()))
				return
			}
			f := files[0]
			tcpln, err := net.FileListener(f)
			tcpln.Addr()
			if err != nil {
				log.Errorf("listening fd(%v) err:%v", f, err)
				continue
			}
			s.listeners = append(s.listeners, tcpln)
			go func() {
				for {
					_, err := tcpln.Accept()
					if err != nil {
						// only break loop if error.
						break
					}
				}
			}()
			f.Close()
		}
	}()
	w.WriteHeader(200)
	_, _ = w.Write([]byte(""))
}

func (s *Server) TransferFdBack(w http.ResponseWriter, req *http.Request) {
	log.Debugf("tranfer fd len(%v) start.........", len(s.listeners))
	if len(s.listeners) > 0 {
		os.Remove(TransferFdSockName)
		unix, err := net.Listen("unix", TransferFdSockName)
		if err != nil {
			panic(err)
		}

		go func() {
			unixconn, err := unix.Accept()
			if err != nil {
				log.Infof("unix get conn err:%v", err)
			}
			for _, l := range s.listeners {
				tcpln := l.(*net.TCPListener)
				f, err := tcpln.File()
				if err != nil {
					log.Infof("parse listen err:%v", err)
				}
				err = passfd.Put(unixconn.(*net.UnixConn), f)
				if err != nil {
					log.Errorf("passfd put fd err:%v", err)
				}
				l.Close()
				f.Close()
			}
			s.listeners = make([]net.Listener, 0)
			unixconn.Close()
		}()
		log.Debugf("tranfer fd len(%v) ending.........", len(s.listeners))
		w.WriteHeader(200)
		_, _ = w.Write([]byte(""))
	} else {
		w.WriteHeader(204)
		_, _ = w.Write([]byte(""))
	}
}

func (s *Server) Stop() {
	log.Debugf("server stop ...")
	if s.stop != nil {
		close(s.stop)
	}
}

func main() {
	flag.Parse()
	s := NewServer("")
	var err error
	log.Print("Listening on a new file descriptor...")
	err = s.Start()
	if err != nil {
		log.Fatalf("listener error: %v", err)
	}
	log.Printf("server stop")
}
