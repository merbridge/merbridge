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

package file

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/merbridge/merbridge/config"
)

// TODO use atom to rewrite
func NotExistAndCreate() (inode *os.File, err error) {
	dir := filepath.Dir(config.FdMapPath)
	_, err = os.Stat(dir)
	if err != nil && os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			log.Errorf("deployment rule bpf mkdir err:%v", err)
			return nil, err
		}
	}
	inode, err = os.Open(config.FdMapPath)

	if err != nil && os.IsNotExist(err) {
		inode, err = os.Create(config.FdMapPath)
		log.Infof("create deployment rule err:%v", err)
		return inode, err
	}
	return inode, nil
}

func GetInodeBynetns(netns string) (inode string, err error) {
	file, err := NotExistAndCreate()
	if err != nil {
		return "", err
	}
	defer file.Close()

	// 阻塞模式，加共享锁
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH); err != nil {
		log.Errorf("add share lock in no block failed %v", err)
		return "", err
	}
	defer func() {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
			log.Errorf("unlock share lock failed %v", err)
		}
	}()
	buf := bufio.NewScanner(file)
	for {
		if !buf.Scan() {
			break
		}
		line := buf.Text()
		data := strings.Split(line, " ")
		if data[0] == netns {
			return data[1], nil
		}
	}
	return "", nil
}

func OptInodeByNetns(opt string, netns string, inode string) error {
	f, err := os.OpenFile(config.FdMapPath, os.O_RDWR|os.O_APPEND, 0o777)
	if err != nil {
		return err
	}
	defer f.Close()
	// 阻塞模式，加排他锁
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		log.Errorf("add exclusive lock in no block failed:%v", err)
		return err
	}
	defer func() {
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
			log.Errorf("unlock exclusive lock failed:%v", err)
		}
	}()

	var lines []string
	r := bufio.NewReader(f)
	for {
		line, _ := r.ReadString('\n')
		if line == "" {
			break
		}
		lines = append(lines, strings.Trim(line, "\r\n"))
	}
	err = f.Truncate(0)
	if err != nil {
		log.Errorf("truncate file err:%v", err)
		return err
	}
	addFlag := false
	for _, line := range lines {
		if opt == "del" {
			if !strings.Contains(line, netns) {
				fmt.Fprintf(f, "%s\n", line)
			}
		} else {
			if strings.Contains(line, netns) {
				fmt.Fprintf(f, "%s %s\n", netns, inode)
				addFlag = true
			} else {
				fmt.Fprintf(f, "%s\n", line)
			}
		}
	}
	if opt != "del" && !addFlag {
		log.Debugf("add line: %s %s", netns, inode)
		fmt.Fprintf(f, "%s %s\n", netns, inode)
	}
	return nil
}
