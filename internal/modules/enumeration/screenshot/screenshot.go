package screenshot

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"

	"github.com/kbinani/screenshot"
)

func Screenshot() (string, error) {
	n := screenshot.NumActiveDisplays()
	// above func has issues
	if n == 0 {
		n = 1
	}
	// create zip file in memory
	fileBuffers := make(map[string]bytes.Buffer)
	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)
		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			return "", err
		}
		fileBuffer := new(bytes.Buffer)
		fileBufferWriter := bufio.NewWriter(fileBuffer)
		fileName := fmt.Sprintf("%d_%dx%d.png", i, bounds.Dx(), bounds.Dy())
		png.Encode(fileBufferWriter, img)
		fileBuffers[fileName] = *fileBuffer
	}
	zipBuffer := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuffer)
	for key, value := range fileBuffers {
		zipFile, err := zipWriter.Create(key)
		if err != nil {
			return "", err
		}
		_, err = zipFile.Write(value.Bytes())
		if err != nil {
			return "", err
		}
	}
	err := zipWriter.Close()
	if err != nil {
		return "", err
	}
	zipResult := base64.StdEncoding.EncodeToString(zipBuffer.Bytes())
	return zipResult, nil
}
