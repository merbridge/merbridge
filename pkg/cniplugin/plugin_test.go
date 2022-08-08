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

package cniplugin

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	kubeserverfake "github.com/DaoCloud/ckube/pkg/client/fake"
	"istio.io/istio/cni/pkg/plugin"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func TestIgnorePod(t *testing.T) {
	type args struct {
		namespace string
		name      string
		pod       *plugin.PodInfo
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "non-injected pod",
			args: args{
				pod: &plugin.PodInfo{
					Containers: []string{"foo", "bar"},
				},
			},
			want: true,
		},
		{
			name: "injected pod with inject-disabled annotation",
			args: args{
				pod: &plugin.PodInfo{
					Containers: []string{"foo", "bar"},
					Annotations: map[string]string{
						injectAnnotationKey: "false",
					},
				},
			},
			want: true,
		},
		{
			name: "injected pod without sidecar status",
			args: args{
				pod: &plugin.PodInfo{
					Containers: []string{"foo", "istio-proxy"},
				},
			},
			want: true,
		},
		{
			name: "injected pod",
			args: args{
				pod: &plugin.PodInfo{
					Containers: []string{"foo", "istio-proxy"},
					Annotations: map[string]string{
						sidecarStatusKey: "whatever",
					},
				},
			},
			want: false,
		},
		{
			name: "injected pod with envoy disabled",
			args: args{
				pod: &plugin.PodInfo{
					Containers: []string{"foo", "istio-proxy"},
					Annotations: map[string]string{
						sidecarStatusKey: "whatever",
					},
					ProxyEnvironments: map[string]string{
						"DISABLE_ENVOY": "true",
					},
				},
			},
			want: true,
		},
		{
			name: "injected pod with envoy enabled",
			args: args{
				pod: &plugin.PodInfo{
					Containers: []string{"foo", "istio-proxy"},
					Annotations: map[string]string{
						sidecarStatusKey: "whatever",
					},
					ProxyEnvironments: map[string]string{
						"DISABLE_ENVOY": "false",
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ignorePod(tt.args.namespace, tt.args.name, tt.args.pod); got != tt.want {
				t.Errorf("ignorePod() = %v, want %v", got, tt.want)
			}
		})
	}
}

func applyResources(cfb *rest.Config, objs ...runtime.Object) (*kubernetes.Clientset, error) {
	cli, err := kubernetes.NewForConfig(cfb)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	for _, obj := range objs {
		if m, ok := obj.(*corev1.Pod); ok {
			cli.CoreV1().Pods(m.Namespace).Create(context.Background(), m, metav1.CreateOptions{})
		}
	}

	return cli, nil
}

func getAvailablePort() (int, error) {
	address, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:0", "0.0.0.0"))
	if err != nil {
		return 0, err
	}

	listener, err := net.ListenTCP("tcp", address)
	if err != nil {
		return 0, err
	}

	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func generateKubeConfig(rc *rest.Config) (string, error) {
	genConfigStringFromRestConfigTemplate := func(c *rest.Config) (string, error) {
		ns := "test"
		clusters := make(map[string]*api.Cluster)
		clusters["default-cluster"] = &api.Cluster{
			Server:                   c.Host,
			CertificateAuthorityData: c.CAData,
		}

		contexts := make(map[string]*api.Context)
		contexts["default-context"] = &api.Context{
			Cluster:   "default-cluster",
			Namespace: ns,
			AuthInfo:  ns,
		}
		authInfos := make(map[string]*api.AuthInfo)
		authInfos[ns] = &api.AuthInfo{
			Token: c.BearerToken,
		}

		clientConfig := api.Config{
			Kind:           "Config",
			APIVersion:     "v1",
			Clusters:       clusters,
			Contexts:       contexts,
			CurrentContext: "default-context",
			AuthInfos:      authInfos,
		}
		bt, err := clientcmd.Write(clientConfig)

		res := string(bt)
		return res, err
	}

	config, err := genConfigStringFromRestConfigTemplate(rc)
	if err != nil {
		return "", err
	}

	tempDir, err := os.MkdirTemp("/tmp/", ".kube")
	if err != nil {
		return "", err
	}
	filePath := filepath.Join(tempDir, "config")
	err = os.WriteFile(filePath, []byte(config), 0o644)
	if err != nil {
		return "", err
	}
	return filePath, nil
}

func Test_ignore(t *testing.T) {
	// init fake kube server
	port, err := getAvailablePort()
	if err != nil {
		t.Fatal(err)
	}
	s, err := kubeserverfake.NewFakeCKubeServerWithConfigPath(fmt.Sprintf(":%d", port), "./testdata/fake-ckube-config.json")
	if err != nil {
		t.Fatal(err)
	}

	// gen configPath by restConfig
	config, err := generateKubeConfig(s.GetKubeConfig())
	if err != nil {
		t.Fatalf("Failed to create a sample kubernetes config file. Err: %v", err)
	}
	defer os.RemoveAll(filepath.Dir(config))

	type args struct {
		conf    *plugin.Config
		k8sArgs *plugin.K8sArgs
	}
	tests := []struct {
		name     string
		fakeObjs []runtime.Object
		args     args
		want     bool
	}{
		{
			name: "not a kubernetes pod",
			args: args{
				k8sArgs: &plugin.K8sArgs{},
			},
			want: true,
		},
		{
			name: "pod namespace within exclude namespaces",
			args: args{
				conf: &plugin.Config{
					Kubernetes: plugin.Kubernetes{
						ExcludeNamespaces: []string{"ns1", "ns2"},
					},
				},
				k8sArgs: &plugin.K8sArgs{
					K8S_POD_NAME:      "test-pod",
					K8S_POD_NAMESPACE: "ns1",
				},
			},
			want: true,
		},
		{
			name: "pod not found",
			args: args{
				conf: &plugin.Config{
					Kubernetes: plugin.Kubernetes{
						Kubeconfig: config,
					},
				},
				k8sArgs: &plugin.K8sArgs{
					K8S_POD_NAME:      "p1",
					K8S_POD_NAMESPACE: "ns1",
				},
			},
			want: true,
		},
		{
			name: "not ignore",
			fakeObjs: []runtime.Object{
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ns1",
						Name:      "p1",
						Annotations: map[string]string{
							sidecarStatusKey: "whatever",
						},
					},
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{
								Name: "istio-proxy",
							},
							{
								Name: "foo",
							},
						},
					},
				},
			},
			args: args{
				conf: &plugin.Config{
					Kubernetes: plugin.Kubernetes{
						Kubeconfig: config,
					},
				},
				k8sArgs: &plugin.K8sArgs{
					K8S_POD_NAME:      "p1",
					K8S_POD_NAMESPACE: "ns1",
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer s.Clean()

			if _, err := applyResources(s.GetKubeConfig(), tt.fakeObjs...); err != nil {
				t.Fatalf("apply kubernetes resources: %v", err)
			}

			if got := ignore(tt.args.conf, tt.args.k8sArgs); got != tt.want {
				t.Errorf("ignore() = %v, want %v", got, tt.want)
			}
		})
	}
}
