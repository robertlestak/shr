package shr

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

var (
	socketClients     = make(map[string]*websocket.Conn)
	clientShrs        = make(map[string]string)
	clientLastMessage = make(map[string]int64)
	socketResponses   map[string]socketResponse
)

type SocketMessage struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

func cleanupSocket(id string) {
	l := log.WithFields(log.Fields{
		"action": "cleanupSocket",
	})
	l.Debug("start")
	if id == "" {
		l.Error("id is empty")
		return
	}
	delete(socketClients, id)
	RemoveRelay(clientShrs[id])
	delete(clientShrs, id)
	delete(clientLastMessage, id)
}

func setClientShr(id string, shr string) {
	l := log.WithFields(log.Fields{
		"action": "setClientShr",
		"id":     id,
		"shr":    shr,
	})
	l.Debug("start")
	if id == "" {
		l.Error("id is empty")
		return
	}
	if shr == "" {
		l.Error("shr is empty")
		return
	}
	l.Debug("set")
	clientShrs[id] = shr
}

func (s *Shr) handleRegisterShr(id string, data *any) {
	l := log.WithFields(log.Fields{
		"action": "handleRegisterShr",
		"shrID":  *s.ID,
		"id":     id,
	})
	l.Debug("start")
	if id == "" {
		l.Error("id is empty")
		return
	}
	if data == nil {
		l.Error("data is empty")
		return
	}
	ns := &Shr{}
	bd, err := json.Marshal(data)
	if err != nil {
		l.Error("marshal:", err)
		return
	}
	err = json.Unmarshal(bd, &ns)
	if err != nil {
		l.Error("unmarshal:", err)
		return
	}
	if s.Relay.AuthKey != nil &&
		*s.Relay.AuthKey != "" &&
		ns.Relay.AuthKey != nil &&
		*ns.Relay.AuthKey != *s.Relay.AuthKey {
		l.Error("auth key mismatch")
		if err := ns.writeSocketMessage("register_shr:failure", nil); err != nil {
			l.Error("write:", err)
		}
		return
	}
	setClientShr(id, *ns.ID)
	if err := ns.writeSocketMessage("register_shr:success", nil); err != nil {
		l.Error("write:", err)
	}
}

func (s *Shr) writeSocketMessage(t string, m any) error {
	l := log.WithFields(log.Fields{
		"action": "writeSocketMessage",
		"t":      t,
		"shr":    *s.ID,
	})
	l.Debug("start")
	if *s.ID == "" {
		l.Error("shr is empty")
		return errors.New("shr is empty")
	}
	var conn *websocket.Conn
	if s.socketClient != nil {
		l.Debug("use socketClient")
		conn = s.socketClient
	} else {
		l.Debug("clientShrs:", clientShrs)
		var socketId string
		for k, v := range clientShrs {
			if v == *s.ID {
				socketId = k
				break
			}
		}
		var ok bool
		if conn, ok = socketClients[socketId]; !ok {
			l.Error("socket not found")
			return errors.New("socket not found")
		}
	}
	err := conn.WriteJSON(&SocketMessage{
		Type: t,
		Data: m,
	})
	if err != nil {
		l.Error("write:", err)
		return err
	}
	return nil
}

func (s *Shr) handleSocketResponse(data any) error {
	l := log.WithFields(log.Fields{
		"action": "handleSocketResponse",
	})
	l.Debug("start")
	if data == nil {
		l.Error("data is empty")
		return errors.New("data is empty")
	}
	sr := &socketResponse{}
	bd, err := json.Marshal(data)
	if err != nil {
		l.Error("marshal:", err)
		return err
	}
	err = json.Unmarshal(bd, &sr)
	if err != nil {
		l.Error("unmarshal:", err)
		return err
	}
	if sr.ID == "" {
		l.Error("id is empty")
		return errors.New("id is empty")
	}
	if socketResponses == nil {
		socketResponses = make(map[string]socketResponse)
	}
	l.WithField("id", sr.ID).Debug("set socket response")
	socketResponses[sr.ID] = *sr
	return nil
}

func (s *Shr) handleSocketMessage(id string) error {
	l := log.WithFields(log.Fields{
		"action": "handleSocketMessage",
	})
	l.Debug("start")
	if id == "" {
		l.Error("id is empty")
		return errors.New("id is empty")
	}
	var ok bool
	var conn *websocket.Conn
	if conn, ok = socketClients[id]; !ok {
		l.Error("socket not found")
		return errors.New("socket not found")
	}
	message := &SocketMessage{}
	err := conn.ReadJSON(&message)
	if err != nil {
		l.Error("read:", err)
		return err
	}
	l.Debug("handle message")
	clientLastMessage[id] = time.Now().Unix()
	switch message.Type {
	case "ping":
		l.Debug("handle ping")
		conn.WriteJSON(&SocketMessage{
			Type: "pong",
			Data: &map[string]interface{}{
				"message": "pong",
			}})
	case "pong":
		l.Debug("handle pong")
	case "register_shr":
		l.Debug("handle register_shr")
		s.handleRegisterShr(id, &message.Data)
	case "response":
		l.Debug("handle response")
		if err := s.handleSocketResponse(message.Data); err != nil {
			l.Error("handle response:", err)
		}
	default:
		l.Error("unknown message type", message.Type)
	}
	return nil
}

func (s *Shr) relaySocketHandler(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"action": "wsHandler",
	})
	l.Debug("start")
	var upgrader = websocket.Upgrader{}
	upgrader.CheckOrigin = func(r *http.Request) bool {
		if os.Getenv("CORS_ALLOWED_ORIGINS") == "*" {
			return true
		}
		for _, h := range strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ",") {
			origin := r.Header["Origin"]
			if len(origin) == 0 {
				return true
			}
			if origin[0] == h {
				return true
			}
		}
		return false
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		l.WithError(err).Error("Failed to upgrade websocket")
		http.Error(w, "Could not open websocket connection", http.StatusBadRequest)
		return
	}
	l.Debug("handle socket")
	cid := uuid.New().String()
	l.Debug("new connection id:", cid)
	socketClients[cid] = conn
	clientLastMessage[cid] = time.Now().Unix()
	defer func() {
		l.Debug("remove connection id:", cid)
		cleanupSocket(cid)
		conn.Close()
	}()
	for {
		if err := s.handleSocketMessage(cid); err != nil {
			l.WithError(err).Error("Failed to handle websocket")
			cleanupSocket(cid)
			break
		}
	}
}

func parseWSMessage(d []byte) (*SocketMessage, error) {
	var msg SocketMessage
	err := json.Unmarshal(d, &msg)
	if err != nil {
		return nil, err
	}
	return &msg, nil
}
