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
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/containernetworking/cni/pkg/skel"
	log "github.com/sirupsen/logrus"
)

func (s *server) PodCreated(w http.ResponseWriter, req *http.Request) {
	bs, err := ioutil.ReadAll(req.Body)
	if err != nil {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(err.Error()))
	}
	args := skel.CmdArgs{}
	err = json.Unmarshal(bs, &args)
	log.Infof("cni called create with args: %+v", args)
	if err != nil {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(err.Error()))
	}
	err = s.CmdAdd(&args)
	if err != nil {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(err.Error()))
	}
	w.WriteHeader(200)
	_, _ = w.Write([]byte("ok"))
}

func (s *server) PodDeleted(w http.ResponseWriter, req *http.Request) {
	bs, err := ioutil.ReadAll(req.Body)
	if err != nil {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(err.Error()))
	}
	args := skel.CmdArgs{}
	err = json.Unmarshal(bs, &args)
	log.Infof("cni called delete with args: %+v", args)
	if err != nil {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(err.Error()))
	}
	err = s.CmdDelete(&args)
	if err != nil {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(err.Error()))
	}
	w.WriteHeader(200)
	_, _ = w.Write([]byte("ok"))
}
