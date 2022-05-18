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
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/merbridge/merbridge/config"
	"github.com/merbridge/merbridge/controller"
	cniserver "github.com/merbridge/merbridge/internal/cni-server"
	"github.com/merbridge/merbridge/internal/ebpfs"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "mbctl",
	Short: "Use eBPF to speed up your Service Mesh like crossing an Einstein-Rosen Bridge.",
	Long:  `Use eBPF to speed up your Service Mesh like crossing an Einstein-Rosen Bridge.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := ebpfs.LoadMBProgs(config.Mode, config.UseReconnect, config.Debug, config.DNSRedirection); err != nil {
			return fmt.Errorf("failed to load ebpf programs: %v", err)
		}

		cniReady := make(chan struct{}, 1)
		if config.EnableCNI {
			s := cniserver.NewServer(path.Join(config.HostVarRun, "merbridge-cni.sock"), "/sys/fs/bpf", config.HardwareCheckSum)
			if err := s.Start(); err != nil {
				log.Fatal(err)
				return err
			}
			installCNI(cmd.Context(), cniReady)
		}

		// todo wait for stop
		if err := controller.Run(cniReady); err != nil {
			log.Fatal(err)
			return err
		}
		return nil
	},
}

// Execute excute root command and its child commands
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Setup log format
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp:       false,
		FullTimestamp:          true,
		DisableLevelTruncation: true,
		DisableColors:          true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			fs := strings.Split(f.File, "/")
			filename := fs[len(fs)-1]
			ff := strings.Split(f.Function, "/")
			_f := ff[len(ff)-1]
			return fmt.Sprintf("%s()", _f), fmt.Sprintf("%s:%d", filename, f.Line)
		},
	})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(true)

	// Get some flags from commands
	rootCmd.PersistentFlags().StringVarP(&config.Mode, "mode", "m", config.ModeIstio, "Service mesh mode, current support istio and linkerd")
	rootCmd.PersistentFlags().BoolVarP(&config.UseReconnect, "use-reconnect", "r", true, "Use re-connect mode as same-node acceleration")
	rootCmd.PersistentFlags().BoolVarP(&config.Debug, "debug", "d", false, "Debug mode")
	rootCmd.PersistentFlags().BoolVarP(&config.IsKind, "kind", "k", false, "Kubernetes in Kind mode")
	rootCmd.PersistentFlags().StringVarP(&config.IpsFile, "ips-file", "f", "", "Current node ips file name")
	rootCmd.PersistentFlags().BoolVar(&config.EnableCNI, "cni-mode", false, "Enable Merbridge CNI plugin")
	rootCmd.PersistentFlags().BoolVar(&config.DNSRedirection, "dns-redir", false, "Enable DNS message redirection for Istio service mesh")
	// If hardware checksum not enabled, we should disable tx checksum, otherwise,
	// this can cause problems with Pods communication across hosts (Kubernetes Service logic) when CNI mode enabled.
	// Turning this off may make network performance worse.
	// You can check your node with run `ethtool -k eth0 | grep tx-checksum-ipv4`, (eth0 is your NIC interface name).
	// If it shows like `tx-checksum-ipv4: off [fixed]`, that means you NIC doesn't support hardware checksum,
	// you should disable hardwareCheckSum.
	// We are considering the option of using tc instead of xdp and may not need this feature in the future.
	rootCmd.PersistentFlags().BoolVar(&config.HardwareCheckSum, "hardware-checksum", false, "Enable hardware checksum")
	rootCmd.PersistentFlags().StringVar(&config.HostProc, "host-proc", "/host/proc", "/proc mount path")
	rootCmd.PersistentFlags().StringVar(&config.CNIBinDir, "cni-bin-dir", "/host/opt/cni/bin", "/opt/cni/bin mount path")
	rootCmd.PersistentFlags().StringVar(&config.CNIConfigDir, "cni-config-dir", "/host/etc/cni/net.d", "/etc/cni/net.d mount path")
	rootCmd.PersistentFlags().StringVar(&config.HostVarRun, "host-var-run", "/host/var/run", "/var/run mount path")
}

func installCNI(ctx context.Context, cniReady chan struct{}) {
	installer := cniserver.NewInstaller()
	go func() {
		if err := installer.Run(ctx, cniReady); err != nil {
			log.Error(err)
		}
		if err := installer.Cleanup(); err != nil {
			log.Errorf("Failed to clean up Merbridge CNI: %v", err)
		}
	}()

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGABRT)
		<-ch
		if err := installer.Cleanup(); err != nil {
			log.Errorf("Failed to clean up Merbridge CNI: %v", err)
		}
	}()
}
