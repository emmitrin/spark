package models

import "time"

type TaskStatus string

const (
	TaskStatusUnknown    TaskStatus = "unknown"
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusRunning    TaskStatus = "running"
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusFailed     TaskStatus = "failed"
	TaskStatusTerminated TaskStatus = "terminated"
)

type WorkerStatus string

const (
	WorkerStatusUnknown   WorkerStatus = "unknown"
	WorkerStatusHealthy   WorkerStatus = "healthy"
	WorkerStatusDegraded  WorkerStatus = "degraded"
	WorkerStatusUnhealthy WorkerStatus = "unhealthy"
)

type Task struct {
	ID          string
	ContainerID string
	Status      TaskStatus
	CreatedAt   time.Time
	Limits      ResourceLimits
	StopChan    chan struct{}
}

type ContainerInfo struct {
	ID        string
	Name      string
	Status    string
	CreatedAt time.Time
	Networks  []string
}

type ResourceLimits struct {
	CPULimit    float64
	MemoryLimit int64
	DiskLimit   int64
	NetworkBW   int32
}

type ResourceUsage struct {
	CPUUsagePercent  float64
	MemoryUsedBytes  int64
	MemoryLimitBytes int64
	NetworkRxBytes   int64
	NetworkTxBytes   int64
}

type TaskInfo struct {
	TaskID      string
	Status      TaskStatus
	ContainerID string
	CreatedAt   int64
	Resources   *ResourceUsage
	Networks    []string
}

type WorkerState struct {
	Status    WorkerStatus
	Tasks     []*TaskInfo
	Resources *ResourceUsage
}

type EnqueueTaskInput struct {
	Image          string // Docker image to run (e.g. "alpine:latest"); empty means default
	ResourceLimits ResourceLimits
	TimeoutSeconds int32
}

type EnqueueTaskResult struct {
	Success     bool
	TaskID      string
	Message     string
	ContainerID string
}

type TerminateTaskResult struct {
	Success bool
	Message string
}
