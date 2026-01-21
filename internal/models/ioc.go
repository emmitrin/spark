package models

import "time"

type IoCDocument struct {
	TaskID      string                 `json:"task_id"`
	ContainerID string                 `json:"container_id"`
	Timestamp   time.Time              `json:"timestamp"`
	IoC         map[string]interface{} `json:"ioc"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
