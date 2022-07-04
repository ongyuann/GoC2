package scheduledtasks

import (
	"errors"
	"os/exec"
)

func ExecuteScheduledTask(args []string) (string, error) {
	taskArgs := make([]string, 0)
	machineStr := "/s"
	machine := args[0]
	delStr := "/run"
	tnStr := "/tn"
	taskName := args[1]
	fStr := "/I"
	taskArgs = append(taskArgs, machineStr)
	taskArgs = append(taskArgs, machine)
	taskArgs = append(taskArgs, delStr)
	taskArgs = append(taskArgs, tnStr)
	taskArgs = append(taskArgs, taskName)
	taskArgs = append(taskArgs, fStr)
	cmd := exec.Command("schtasks.exe", taskArgs...)
	result, cmdError := cmd.CombinedOutput()
	if cmdError != nil {
		return "", cmdError
	}
	return string(result), nil
}

func CreateScheduledTask(args []string) (string, error) {
	if len(args) < 5 {
		return "", errors.New("Not Enough Args.")
	}
	taskArgs := make([]string, 0)
	machineStr := "/s"
	machine := args[0]
	createStr := "/Create"
	tnStr := "/tn"
	taskName := args[1]
	// task name
	scStri := "/sc"
	taskSchedule := args[2]
	// schedule frequency
	stStr := "/st"
	taskStartTime := args[3]
	// start time
	trStr := "/tr"
	taskRun := args[4]
	// actual task binary etc
	taskArgs = append(taskArgs, machineStr)
	taskArgs = append(taskArgs, machine)
	taskArgs = append(taskArgs, createStr)
	taskArgs = append(taskArgs, tnStr)
	taskArgs = append(taskArgs, taskName)
	taskArgs = append(taskArgs, scStri)
	taskArgs = append(taskArgs, taskSchedule)
	taskArgs = append(taskArgs, stStr)
	taskArgs = append(taskArgs, taskStartTime)
	taskArgs = append(taskArgs, trStr)
	taskArgs = append(taskArgs, taskRun)
	cmd := exec.Command("schtasks.exe", taskArgs...)
	result, cmdError := cmd.CombinedOutput()
	if cmdError != nil {
		return "", cmdError
	}
	return string(result), nil
}

func DeleteScheduledTask(args []string) (string, error) {
	taskArgs := make([]string, 0)
	machineStr := "/s"
	machine := args[0]
	delStr := "/delete"
	tnStr := "/tn"
	taskName := args[1]
	fStr := "/f"
	taskArgs = append(taskArgs, machineStr)
	taskArgs = append(taskArgs, machine)
	taskArgs = append(taskArgs, delStr)
	taskArgs = append(taskArgs, tnStr)
	taskArgs = append(taskArgs, taskName)
	taskArgs = append(taskArgs, fStr)
	cmd := exec.Command("schtasks.exe", taskArgs...)
	result, cmdError := cmd.CombinedOutput()
	if cmdError != nil {
		return "", cmdError
	}
	return string(result), nil
}
