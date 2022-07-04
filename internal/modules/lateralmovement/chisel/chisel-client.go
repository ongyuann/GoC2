package chisel

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	not "github.com/jpillora/chisel/client"
	notcos "github.com/jpillora/chisel/share/cos"
	"github.com/mattn/go-shellwords"
)

type multiFlag struct {
	values *[]string
}

func (flag multiFlag) String() string {
	return strings.Join(*flag.values, ", ")
}

func (flag multiFlag) Set(arg string) error {
	*flag.values = append(*flag.values, arg)
	return nil
}

type headerFlags struct {
	http.Header
}

func (flag *headerFlags) String() string {
	out := ""
	for k, v := range flag.Header {
		out += fmt.Sprintf("%s: %s\n", k, v)
	}
	return out
}

func (flag *headerFlags) Set(arg string) error {
	index := strings.Index(arg, ":")
	if index < 0 {
		return fmt.Errorf(`Invalid header (%s). Should be in the format "HeaderName: HeaderContent"`, arg)
	}
	if flag.Header == nil {
		flag.Header = http.Header{}
	}
	key := arg[0:index]
	value := arg[index+1:]
	flag.Header.Set(key, strings.TrimSpace(value))
	return nil
}

func generatePidFile() {
	pid := []byte(strconv.Itoa(os.Getpid()))
	if err := ioutil.WriteFile("chisel.pid", pid, 0644); err != nil {
		log.Fatal(err)
	}
}

func ChiselClient(args []string) (string, error) {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	config := not.Config{Headers: http.Header{}}
	flags.StringVar(&config.Fingerprint, "fingerprint", "", "")
	flags.StringVar(&config.Auth, "auth", "", "")
	flags.DurationVar(&config.KeepAlive, "keepalive", 25*time.Second, "")
	flags.IntVar(&config.MaxRetryCount, "max-retry-count", -1, "")
	flags.DurationVar(&config.MaxRetryInterval, "max-retry-interval", 0, "")
	flags.StringVar(&config.Proxy, "proxy", "", "")
	flags.StringVar(&config.TLS.CA, "tls-ca", "", "")
	flags.BoolVar(&config.TLS.SkipVerify, "tls-skip-verify", false, "")
	flags.StringVar(&config.TLS.Cert, "tls-cert", "", "")
	flags.StringVar(&config.TLS.Key, "tls-key", "", "")
	flags.Var(&headerFlags{config.Headers}, "header", "")
	hostname := flags.String("hostname", "", "")
	pid := flags.Bool("pid", false, "")
	verbose := flags.Bool("v", false, "")
	flags.Usage = func() {
		//fmt.Print(clientHelp)
		os.Exit(0)
	}
	fixedArgs, err := shellwords.Parse(strings.Join(args, " "))
	if err != nil {
		return "", err
	}
	flags.Parse(fixedArgs)
	log.Println(fixedArgs)
	//pull out options, put back remaining args
	args = flags.Args()
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	config.Server = args[0]
	config.Remotes = args[1:]
	//default auth
	if config.Auth == "" {
		config.Auth = os.Getenv("AUTH")
	}
	//move hostname onto headers
	if *hostname != "" {
		config.Headers.Set("Host", *hostname)
	}
	//ready
	c, err := not.NewClient(&config)
	if err != nil {
		return "", err
	}
	c.Debug = *verbose
	if *pid {
		generatePidFile()
	}
	go notcos.GoStats()
	ctx := notcos.InterruptContext()
	if err := c.Start(ctx); err != nil {
		return "", err
	}
	/* dont block
	if err := c.Wait(); err != nil {
		return "", err
	}
	*/
	return "Should Have Worked", nil
}
