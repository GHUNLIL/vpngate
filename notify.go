package main

// Notifications for events downstream systems care about: the exit IP changed, or no node is
// available / service recovered. Sent to a webhook (JSON POST) and/or a Telegram chat by a single
// background worker: in order, best effort, never blocking switching.

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Notifier struct {
	WebhookURL string
	TGToken    string
	TGChatID   string

	once  sync.Once
	queue chan Event
}

var notifyClient = &http.Client{Timeout: 10 * time.Second}

// Event is the webhook payload.
type Event struct {
	Event  string `json:"event"` // exit_ip_changed | no_node | recovered
	Text   string `json:"text"`
	OldIP  string `json:"old_ip,omitempty"`
	NewIP  string `json:"new_ip,omitempty"`
	Reason string `json:"reason,omitempty"`
	Node   string `json:"node,omitempty"`
	Time   int64  `json:"time"`
}

func (n *Notifier) Enabled() bool {
	return n != nil && (n.WebhookURL != "" || n.TGToken != "" && n.TGChatID != "")
}

// Send queues e for delivery; it never blocks (events are dropped if 64 are already pending).
func (n *Notifier) Send(e Event) {
	if !n.Enabled() {
		return
	}
	n.once.Do(func() {
		n.queue = make(chan Event, 64)
		go n.worker()
	})
	e.Time = time.Now().Unix()
	select {
	case n.queue <- e:
	default:
		log.Printf("通知队列已满，丢弃: %s", e.Text)
	}
}

func (n *Notifier) worker() {
	for e := range n.queue {
		if n.WebhookURL != "" {
			body, _ := json.Marshal(e)
			n.post(n.WebhookURL, "application/json", body)
		}
		if n.TGToken != "" && n.TGChatID != "" {
			form := url.Values{"chat_id": {n.TGChatID}, "text": {"[VPNGATE] " + e.Text}}
			n.post("https://api.telegram.org/bot"+n.TGToken+"/sendMessage", "application/x-www-form-urlencoded",
				[]byte(form.Encode()))
		}
	}
}

func (n *Notifier) post(target, ctype string, body []byte) {
	resp, err := notifyClient.Post(target, ctype, bytes.NewReader(body))
	if err != nil {
		log.Printf("通知发送失败: %v", redact(err.Error(), n.TGToken))
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("通知发送失败: HTTP %d", resp.StatusCode)
	}
}

// redact keeps the Telegram token out of the log (it appears in request URLs inside errors).
func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	return string(bytes.ReplaceAll([]byte(s), []byte(secret), []byte("***")))
}
