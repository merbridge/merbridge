package ebpfs

import (
	"fmt"
	"os"
	"os/exec"
)

func LoadMBProgs(meshMode string, debug bool) error {
	if os.Getuid() != 0 {
		return fmt.Errorf("root user in required for this process or container")
	}
	cmd := exec.Command("make", "load")
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "MESH_MODE="+meshMode)
	if debug {
		cmd.Env = append(cmd.Env, "DEBUG=1")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
		return fmt.Errorf("unexpected exit code: %d, err: %v", code, err)
	}
	return nil
}

func UnLoadMBProgs() error {
	cmd := exec.Command("make", "clean")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 || err != nil {
		return fmt.Errorf("unload unexpected exit code: %d, err: %v", code, err)
	}
	return nil
}
