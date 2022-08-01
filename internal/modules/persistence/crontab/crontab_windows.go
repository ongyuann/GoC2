//go:build windows
// +build windows

package crontab

//TODO
func AppendCronJob(command string) (string, error) {
	return "Not Available On This Platform", nil
	// must be root unless using crontab setuid binary.
}
