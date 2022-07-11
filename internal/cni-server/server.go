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
	"github.com/merbridge/merbridge/pkg/file"
)

var (
	TransferFdSockName = "/tmp/bpf-transfer-fd.sock"
	BpfBackServer      = "/host/var/run/bpf-back-server.sock"
	CNITransferFdURL   = "/v1/transferFd"
	CNIStandbyURL      = "/v1/standby"
)

type ListenerData struct {
	l     net.Listener
	netns string
}

type Server interface {
	Start() error
	Stop()
}

type server struct {
	sync.Mutex
	unixSockPath string
	bpfMountPath string
	// qdiscs is for cleaning up all tc programs when merbridge exits
	// key: netns, value: qdisc info
	qdiscs map[string]qdisc
	stop   chan struct{}

	listeners     map[string]ListenerData
	backListeners []net.Listener
}

// NewServer returns a new CNI Server.
// the path this the unix path to listen.
func NewServer(unixSockPath string, bpfMountPath string, stop chan struct{}) Server {
	if unixSockPath == "" {
		unixSockPath = path.Join(config.HostVarRun, "merbridge-cni.sock")
	}
	if bpfMountPath == "" {
		bpfMountPath = "/sys/fs/bpf"
	}
	return &server{
		unixSockPath: unixSockPath,
		bpfMountPath: bpfMountPath,
		qdiscs:       make(map[string]qdisc),
		stop:         stop,
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
	s.transferFdBack()

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

func (s *server) transferFd() {
	log.Debugf("tranfer fd len(%v) start.........", len(s.listeners))
	if len(s.listeners) > 0 {
		os.Remove(TransferFdSockName)
		unix, err := net.Listen("unix", TransferFdSockName)
		if err != nil {
			panic(err)
		}
		httpc := http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return net.Dial("unix", BpfBackServer)
				},
			},
		}
		http.DefaultClient = &httpc
		bs, _ := json.Marshal("")
		body := bytes.NewReader(bs)

		_, err = httpc.Post("http://bpf-back-server"+CNITransferFdURL, "application/json", body)
		if err != nil {
			log.Errorf("transfer fd err:%v", err)
			return
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			unixconn, err := unix.Accept()
			if err != nil {
				log.Infof("unix get conn err:%v", err)
			}
			for _, ld := range s.listeners {
				tcpln := ld.l.(*net.TCPListener)
				f, err := tcpln.File()
				if err != nil {
					log.Errorf("parse listen err:%v", err)
				}
				err = passfd.Put(unixconn.(*net.UnixConn), f)
				if err != nil {
					log.Errorf("passfd put fd err:%v", err)
				}
				inode, err := getInoFromFd(f)
				if err != nil {
					log.Errorf("get inode err:%v", err)
				}
				err = file.OptInodeByNetns("add", ld.netns, inode)
				if err != nil {
					log.Errorf("add deploy rule err %v", err)
				}
				f.Close()
			}
		}()
		wg.Wait()
		log.Debugf("tranfer fd len(%v) ending.........", len(s.listeners))
	}
}

func (s *server) transferFdBack() {
	// ----- send reset request to fd backup server
	log.Debug("start reset backup server fd")
	httpc := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", BpfBackServer)
			},
		},
	}
	http.DefaultClient = &httpc
	bs, _ := json.Marshal("")
	body := bytes.NewReader(bs)

	resp, err := httpc.Post("http://bpf-back-server"+CNIStandbyURL, "application/json", body)
	if err != nil {
		log.Errorf("post request back fd err:%v", err)
	} else {
		log.Info("post request back fd success")
	}
	if err == nil && resp.StatusCode == 200 {
		unixconn, err := net.Dial("unix", TransferFdSockName)
		if err != nil {
			log.Errorf("dial unix err:%v", err)
		} else {

			for {
				files, err := passfd.Get(unixconn.(*net.UnixConn), 1, nil)
				if err != nil {
					log.Errorf("passfd get err:%v", err)
					break
				}
				f := files[0]
				tcpln, err := net.FileListener(f)
				if err != nil {
					log.Errorf("listening fd(%v) err:%v", f, err)
					continue
				}
				s.backListeners = append(s.backListeners, tcpln)
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
}

func getInoFromFd(f *os.File) (string, error) {
	fileinfo, _ := f.Stat()
	stat, ok := fileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("not a syscall.Stat_t")
	}
	return fmt.Sprint(stat.Ino), nil
}

func (s *server) Stop() {
	s.transferFd()
	s.cleanUpTC()
	s.stop <- struct{}{}
	close(s.stop)
}
