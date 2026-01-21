package models

import "time"

type EventType string

const (
	EventTypeFileWrite       EventType = "file_write"
	EventTypeFileRead        EventType = "file_read"
	EventTypeFileOpen        EventType = "file_open"
	EventTypeNetworkConnect  EventType = "network_connect"
	EventTypeNetworkAccept   EventType = "network_accept"
	EventTypeNetworkSend     EventType = "network_send"
	EventTypeNetworkRecv     EventType = "network_recv"
)

type MonitorEvent struct {
	TaskID      string                 `json:"task_id"`
	ContainerID string                 `json:"container_id"`
	EventType   EventType              `json:"event_type"`
	Timestamp   time.Time              `json:"timestamp"`
	Process     ProcessInfo            `json:"process"`
	Details     map[string]interface{} `json:"details"`
}

type ProcessInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Comm    string `json:"comm"`
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	ExePath string `json:"exe_path"`
}
