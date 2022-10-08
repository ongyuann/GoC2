package basic

import (
	"bufio"
	"bytes"
	"compress/gzip"
	b64 "encoding/base64"
	"errors"
	"io/ioutil"
	"os"
)

func DownloadFile(filePath string) (string, error) {
	if filePath == "" {
		return "", errors.New("Not Enough Args")
	}
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	read := bufio.NewReader(f)
	data, err := ioutil.ReadAll(read)
	if err != nil {
		return "", err
	}
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tempDir)
	file, err := ioutil.TempFile(tempDir, "")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", err
	}
	w.Write(data)
	w.Close()
	sEnc := b64.StdEncoding.EncodeToString(buf.Bytes())
	return sEnc, nil
}
