package basic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func RemoteDownload(args []string) (string, error) {
	// https://flashpaper.chime.com/ -> ???
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	url := args[0]
	outputPath := args[1]
	transport := http.Transport{}
	tlsConf := &tls.Config{}
	tlsConf.InsecureSkipVerify = true
	client := &http.Client{}
	client.Transport = &transport
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(request)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", errors.New(fmt.Sprintf("Failed Got %d status code", resp.StatusCode))
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	filePtr, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	nWrote, err := filePtr.Write(data)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Wrote %d Bytes To %s", nWrote, outputPath), nil
}
