package ebpfs

import (
	"fmt"
	"os"
	"os/exec"
)

func LoadMBProgs() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("root user in required for this process or container")
	}
	cmd := exec.Command("/usr/bin/make", "load")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		return fmt.Errorf("unexpected exit code: %d", code)
	}
	return nil
}

func UnLoadMBProgs() error {
	cmd := exec.Command("/usr/bin/make", "clean")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		return fmt.Errorf("unexpected exit code: %d", code)
	}
	return nil
}
