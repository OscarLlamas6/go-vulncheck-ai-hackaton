package main

import (
	"encoding/json"
	"github.com/panjf2000/gnet/v2"
	"github.com/sirupsen/logrus"
)

type NotificationServer struct {
	*gnet.BuiltinEventEngine
	eng       gnet.Engine
	addr      string
	connected []gnet.Conn
}

type BookNotification struct {
	Event string `json:"event"`
	Book  Book   `json:"book"`
}

func NewNotificationServer(addr string) *NotificationServer {
	return &NotificationServer{
		addr:      addr,
		connected: make([]gnet.Conn, 0),
	}
}

func (s *NotificationServer) OnBoot(eng gnet.Engine) gnet.Action {
	s.eng = eng
	logrus.WithField("addr", s.addr).Info("notification server is listening")
	return gnet.None
}

func (s *NotificationServer) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	logrus.WithField("client", c.RemoteAddr().String()).Info("new client connected")
	s.connected = append(s.connected, c)
	return nil, gnet.None
}

func (s *NotificationServer) OnClose(c gnet.Conn, err error) (action gnet.Action) {
	logrus.WithField("client", c.RemoteAddr().String()).Info("client disconnected")
	for i, conn := range s.connected {
		if conn == c {
			s.connected = append(s.connected[:i], s.connected[i+1:]...)
			break
		}
	}
	return gnet.None
}

func (s *NotificationServer) OnTraffic(c gnet.Conn) (action gnet.Action) {
	// We don't handle incoming traffic, this is notification-only
	return gnet.None
}

func (s *NotificationServer) NotifyBookEvent(event string, book Book) {
	notification := BookNotification{
		Event: event,
		Book:  book,
	}

	data, err := json.Marshal(notification)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal notification")
		return
	}

	// Add newline for better client reading
	data = append(data, '\n')

	for _, conn := range s.connected {
		err := conn.AsyncWrite(data, nil)
		if err != nil {
			logrus.WithError(err).Error("failed to send notification")
		}
	}
}

func (s *NotificationServer) Start() error {
	return gnet.Run(s, s.addr,
		gnet.WithMulticore(true),
		gnet.WithReusePort(true),
	)
}
