package basic

import (
	"bufio"
	"bytes"
	"compress/gzip"
	b64 "encoding/base64"
	"io/ioutil"
	"log"
	"os"
)

func DownloadFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	read := bufio.NewReader(f)
	data, err := ioutil.ReadAll(read)
	if err != nil {
		return "", err
	}
	tempDir, err := ioutil.TempDir("", "")
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	defer os.RemoveAll(tempDir)
	file, err := ioutil.TempFile(tempDir, "")
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	defer os.Remove(file.Name())
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		log.Fatal(err)
		return "", err
	}
	w.Write(data)
	w.Close()
	sEnc := b64.StdEncoding.EncodeToString(buf.Bytes())
	return sEnc, nil
}
