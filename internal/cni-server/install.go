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
	"html/template"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/containernetworking/cni/libcni"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"istio.io/istio/cni/pkg/util"
	"istio.io/istio/pkg/file"

	"github.com/merbridge/merbridge/config"
)

const (
	kubeConfigFileName = "ZZZ-merbridge-cni-kubeconfig"
	tokenPath          = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	kubeConfigTemplate = `# Kubeconfig file for Merbridge CNI plugin.
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: {{.KubernetesServiceProtocol}}://[{{.KubernetesServiceHost}}]:{{.KubernetesServicePort}}
    {{.TLSConfig}}
users:
- name: merbridge-cni
  user:
    token: "{{.ServiceAccountToken}}"
contexts:
- name: merbridge-cni-context
  context:
    cluster: local
    user: merbridge-cni
current-context: merbridge-cni-context
`
)

type Installer struct {
	kubeConfigFilepath string
	cniConfigFilepath  string
}

type kubeconfigFields struct {
	KubernetesServiceProtocol string
	KubernetesServiceHost     string
	KubernetesServicePort     string
	ServiceAccountToken       string
	TLSConfig                 string
}

// NewInstaller returns an instance of Installer with the given config
func NewInstaller() *Installer {
	return &Installer{}
}

// Run starts the installation process, verifies the configuration, then sleeps.
// If an invalid configuration is detected, the installation process will restart to restore a valid state.
func (in *Installer) Run(ctx context.Context) error {
	for {
		if err := copyBinaries(); err != nil {
			return err
		}

		saToken, err := readServiceAccountToken()
		if err != nil {
			return err
		}

		if in.kubeConfigFilepath, err = createKubeconfigFile(saToken); err != nil {
			return err
		}

		if in.cniConfigFilepath, err = createCNIConfigFile(ctx); err != nil {
			return err
		}

		if err = sleepCheckInstall(ctx, in.cniConfigFilepath); err != nil {
			return err
		}
		log.Info("Restarting Merbridge CNI installer...")
	}
}

// Cleanup remove Merbridge CNI's config, kubeconfig file, and binaries.
func (in *Installer) Cleanup() error {
	log.Info("Cleaning up.")
	if len(in.cniConfigFilepath) > 0 && file.Exists(in.cniConfigFilepath) {
		log.Infof("Removing Merbridge CNI config from CNI config file: %s", in.cniConfigFilepath)

		// Read JSON from CNI config file
		cniConfigMap, err := readCNIConfigMap(in.cniConfigFilepath)
		if err != nil {
			return err
		}
		// Find Merbridge CNI and remove from plugin list
		plugins, err := util.GetPlugins(cniConfigMap)
		if err != nil {
			return errors.Wrap(err, in.cniConfigFilepath)
		}
		for i, rawPlugin := range plugins {
			plugin, err := util.GetPlugin(rawPlugin)
			if err != nil {
				return errors.Wrap(err, in.cniConfigFilepath)
			}
			if plugin["type"] == "merbridge-cni" {
				cniConfigMap["plugins"] = append(plugins[:i], plugins[i+1:]...)
				break
			}
		}

		cniConfig, err := util.MarshalCNIConfig(cniConfigMap)
		if err != nil {
			return err
		}
		if err = file.AtomicWrite(in.cniConfigFilepath, cniConfig, os.FileMode(0644)); err != nil {
			return err
		}
	}

	if len(in.kubeConfigFilepath) > 0 && file.Exists(in.kubeConfigFilepath) {
		log.Infof("Removing Merbridge CNI kubeconfig file: %s", in.kubeConfigFilepath)
		if err := os.Remove(in.kubeConfigFilepath); err != nil {
			return err
		}
	}

	log.Info("Removing existing binaries")
	cniBinPath := path.Join(config.CNIBinDir, "merbridge-cni")
	if file.Exists(cniBinPath) {
		if err := os.Remove(cniBinPath); err != nil {
			return err
		}
	}
	return nil
}

func createCNIConfigFile(ctx context.Context) (string, error) {
	// TODO(dddddai): support ExcludeNamespaces?
	mbCNIConfig := fmt.Sprintf(`
	{
		"type": "merbridge-cni",
		"kubernetes": {
			"kubeconfig": "/etc/cni/net.d/%s"
		}
	}`, kubeConfigFileName)

	return writeCNIConfig(ctx, []byte(mbCNIConfig))
}

func insertCNIConfig(mbCNIConfig, existingCNIConfig []byte) ([]byte, error) {
	var mbMap map[string]interface{}
	if err := json.Unmarshal(mbCNIConfig, &mbMap); err != nil {
		return nil, fmt.Errorf("error loading Merbridge CNI config (JSON error): %v", err)
	}

	var existingMap map[string]interface{}
	if err := json.Unmarshal(existingCNIConfig, &existingMap); err != nil {
		return nil, fmt.Errorf("error loading existing CNI config (JSON error): %v", err)
	}

	var newMap map[string]interface{}

	if _, ok := existingMap["type"]; ok {
		// Assume it is a regular network conf file
		delete(existingMap, "cniVersion")

		plugins := make([]map[string]interface{}, 2)
		plugins[0] = existingMap
		plugins[1] = mbMap

		newMap = map[string]interface{}{
			"name":       "k8s-pod-network",
			"cniVersion": "0.3.1",
			"plugins":    plugins,
		}
	} else {
		// Assume it is a network list file
		newMap = existingMap
		plugins, err := util.GetPlugins(newMap)
		if err != nil {
			return nil, fmt.Errorf("existing CNI config: %v", err)
		}

		for _, rawPlugin := range plugins {
			plugin, err := util.GetPlugin(rawPlugin)
			if err != nil {
				return nil, fmt.Errorf("existing CNI plugin: %v", err)
			}
			if plugin["type"] == "merbridge-cni" {
				// it already contains merbridge-cni
				return util.MarshalCNIConfig(newMap)
			}
		}

		newMap["plugins"] = append(plugins, mbMap)
	}

	return util.MarshalCNIConfig(newMap)
}

func writeCNIConfig(ctx context.Context, mbCNIConfig []byte) (string, error) {
	cniConfigFilepath, err := getCNIConfigFilepath(ctx)
	if err != nil {
		return "", err
	}

	// This section overwrites an existing plugins list entry for merbridge-cni
	existingCNIConfig, err := ioutil.ReadFile(cniConfigFilepath)
	if err != nil {
		return "", err
	}
	cniConfig, err := insertCNIConfig(mbCNIConfig, existingCNIConfig)
	if err != nil {
		return "", err
	}

	if err = file.AtomicWrite(cniConfigFilepath, cniConfig, os.FileMode(0644)); err != nil {
		return "", err
	}

	if strings.HasSuffix(cniConfigFilepath, ".conf") {
		// If the old CNI config filename ends with .conf, rename it to .conflist, because it has to be changed to a list
		log.Infof("Renaming %s extension to .conflist", cniConfigFilepath)
		err = os.Rename(cniConfigFilepath, cniConfigFilepath+"list")
		if err != nil {
			return "", err
		}
		cniConfigFilepath += "list"
	}

	log.Infof("Created CNI config %s", cniConfigFilepath)
	return cniConfigFilepath, nil
}

// If configured as chained CNI plugin, waits indefinitely for a main CNI config file to exist before returning
// Or until cancelled by parent context
func getCNIConfigFilepath(ctx context.Context) (string, error) {
	watcher, fileModified, errChan, err := util.CreateFileWatcher(config.CNIConfigDir)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = watcher.Close()
	}()

	filename, err := getDefaultCNINetwork(config.CNIConfigDir)
	for len(filename) == 0 {
		filename, err = getDefaultCNINetwork(config.CNIConfigDir)
		if err == nil {
			break
		}
		if err = util.WaitForFileMod(ctx, fileModified, errChan); err != nil {
			return "", err
		}
	}

	cniConfigFilepath := filepath.Join(config.CNIConfigDir, filename)

	for !file.Exists(cniConfigFilepath) {
		if strings.HasSuffix(cniConfigFilepath, ".conf") && file.Exists(cniConfigFilepath+"list") {
			log.Infof("%s doesn't exist, but %[1]slist does; Using it as the CNI config file instead.", cniConfigFilepath)
			cniConfigFilepath += "list"
		} else if strings.HasSuffix(cniConfigFilepath, ".conflist") && file.Exists(cniConfigFilepath[:len(cniConfigFilepath)-4]) {
			log.Infof("%s doesn't exist, but %s does; Using it as the CNI config file instead.", cniConfigFilepath, cniConfigFilepath[:len(cniConfigFilepath)-4])
			cniConfigFilepath = cniConfigFilepath[:len(cniConfigFilepath)-4]
		} else {
			log.Infof("CNI config file %s does not exist. Waiting for file to be written...", cniConfigFilepath)
			if err = util.WaitForFileMod(ctx, fileModified, errChan); err != nil {
				return "", err
			}
		}
	}

	log.Infof("CNI config file %s exists. Proceeding.", cniConfigFilepath)

	return cniConfigFilepath, err
}

// sleepCheckInstall verifies the configuration then blocks until an invalid configuration is detected, and return nil.
// If an error occurs or context is canceled, the function will return the error.
// Returning from this function will set the pod to "NotReady".
func sleepCheckInstall(ctx context.Context, cniConfigFilepath string) error {
	// Create file watcher before checking for installation
	// so that no file modifications are missed while and after checking
	watcher, fileModified, errChan, err := util.CreateFileWatcher(config.CNIConfigDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = watcher.Close()
	}()

	for {
		if checkErr := checkInstall(cniConfigFilepath); checkErr != nil {
			// Pod set to "NotReady" due to invalid configuration
			log.Infof("Invalid configuration. %v", checkErr)
			return nil
		}
		// Check if file has been modified or if an error has occurred during checkInstall before setting isReady to true
		select {
		case <-fileModified:
			return nil
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Valid configuration; set isReady to true and wait for modifications before checking again
			if err = util.WaitForFileMod(ctx, fileModified, errChan); err != nil {
				// Pod set to "NotReady" before termination
				return err
			}
		}
	}
}

func copyBinaries() error {
	srcFile := "/app/merbridge-cni"

	if file.IsDirWriteable(config.CNIBinDir) != nil {
		return fmt.Errorf("directory %s is not writable", config.CNIBinDir)
	}
	err := file.AtomicCopy(srcFile, config.CNIBinDir, "merbridge-cni")
	if err != nil {
		return err
	}
	log.Infof("Copied %s to %s.", srcFile, config.CNIBinDir)
	return nil
}

// checkInstall returns an error if an invalid CNI configuration is detected
func checkInstall(cniConfigFilepath string) error {
	defaultCNIConfigFilename, err := getDefaultCNINetwork(config.CNIConfigDir)
	if err != nil {
		return err
	}
	defaultCNIConfigFilepath := filepath.Join(config.CNIConfigDir, defaultCNIConfigFilename)
	if defaultCNIConfigFilepath != cniConfigFilepath {
		return fmt.Errorf("cni config file %s preempted by %s", cniConfigFilepath, defaultCNIConfigFilepath)
	}

	if !file.Exists(cniConfigFilepath) {
		return fmt.Errorf("cni config file removed: %s", cniConfigFilepath)
	}

	// Verify that Merbridge CNI config exists in the CNI config plugin list
	cniConfigMap, err := readCNIConfigMap(cniConfigFilepath)
	if err != nil {
		return err
	}
	plugins, err := util.GetPlugins(cniConfigMap)
	if err != nil {
		return errors.Wrap(err, cniConfigFilepath)
	}
	for _, rawPlugin := range plugins {
		plugin, err := util.GetPlugin(rawPlugin)
		if err != nil {
			return errors.Wrap(err, cniConfigFilepath)
		}
		if plugin["type"] == "merbridge-cni" {
			return nil
		}
	}

	return fmt.Errorf("merbridge CNI config removed from CNI config file: %s", cniConfigFilepath)
}

// Read CNI config from file and return the unmarshalled JSON as a map
func readCNIConfigMap(path string) (map[string]interface{}, error) {
	cniConfig, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cniConfigMap map[string]interface{}
	if err = json.Unmarshal(cniConfig, &cniConfigMap); err != nil {
		return nil, errors.Wrap(err, path)
	}

	return cniConfigMap, nil
}

func createKubeconfigFile(saToken string) (kubeconfigFilepath string, err error) {
	tpl, err := template.New("kubeconfig").Parse(kubeConfigTemplate)
	if err != nil {
		return
	}

	protocol := os.Getenv("KUBERNETES_SERVICE_PROTOCOL")
	if protocol == "" {
		protocol = "https"
	}

	// TODO: support tls
	tlsConfig := "insecure-skip-tls-verify: true"

	fields := kubeconfigFields{
		KubernetesServiceProtocol: protocol,
		KubernetesServiceHost:     os.Getenv("KUBERNETES_SERVICE_HOST"),
		KubernetesServicePort:     os.Getenv("KUBERNETES_SERVICE_PORT"),
		ServiceAccountToken:       saToken,
		TLSConfig:                 tlsConfig,
	}

	var kcbb bytes.Buffer
	if err := tpl.Execute(&kcbb, fields); err != nil {
		return "", err
	}

	var kcbbToPrint bytes.Buffer
	fields.ServiceAccountToken = "<redacted>"
	if err := tpl.Execute(&kcbbToPrint, fields); err != nil {
		return "", err
	}

	kubeconfigFilepath = filepath.Join(config.CNIConfigDir, kubeConfigFileName)
	log.Infof("write kubeconfig file %s with: \n%+v", kubeconfigFilepath, kcbbToPrint.String())
	if err = file.AtomicWrite(kubeconfigFilepath, kcbb.Bytes(), os.FileMode(0600)); err != nil {
		return "", err
	}

	return
}

func readServiceAccountToken() (string, error) {
	if !file.Exists(tokenPath) {
		return "", fmt.Errorf("service account token file %s does not exist. Is this not running within a pod?", tokenPath)
	}

	token, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

// Follows the same semantics as kubelet
// https://github.com/kubernetes/kubernetes/blob/954996e231074dc7429f7be1256a579bedd8344c/pkg/kubelet/dockershim/network/cni/cni.go#L144-L184
func getDefaultCNINetwork(confDir string) (string, error) {
	files, err := libcni.ConfFiles(confDir, []string{".conf", ".conflist"})
	switch {
	case err != nil:
		return "", err
	case len(files) == 0:
		return "", fmt.Errorf("no networks found in %s", confDir)
	}

	sort.Strings(files)
	for _, confFile := range files {
		var confList *libcni.NetworkConfigList
		if strings.HasSuffix(confFile, ".conflist") {
			confList, err = libcni.ConfListFromFile(confFile)
			if err != nil {
				log.Warnf("Error loading CNI config list file %s: %v", confFile, err)
				continue
			}
		} else {
			conf, err := libcni.ConfFromFile(confFile)
			if err != nil {
				log.Warnf("Error loading CNI config file %s: %v", confFile, err)
				continue
			}
			// Ensure the config has a "type" so we know what plugin to run.
			// Also catches the case where somebody put a conflist into a conf file.
			if conf.Network.Type == "" {
				log.Warnf("Error loading CNI config file %s: no 'type'; perhaps this is a .conflist?", confFile)
				continue
			}

			confList, err = libcni.ConfListFromConf(conf)
			if err != nil {
				log.Warnf("Error converting CNI config file %s to list: %v", confFile, err)
				continue
			}
		}
		if len(confList.Plugins) == 0 {
			log.Warnf("CNI config list %s has no networks, skipping", confList.Name)
			continue
		}

		return filepath.Base(confFile), nil
	}

	return "", fmt.Errorf("no valid networks found in %s", confDir)
}
