package data

type ListenerType int

const (
	WebsocketListener = iota
	HTTPSListener
	// Future Protocol Support
)

type Listener struct {
	Port            string       `json:"port"`
	Listener        ListenerType `json:"listener_type"`
	Label           string       `json:"label"`
	ShutdownChannel chan int     `json:"-"`
}
