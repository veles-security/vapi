package sig

import "github.com/veles-security/vapi"

type Message []byte

func (d Message) Kind() string {
	return "bytes"
}

var _ vapi.Artifact = &Message{}
