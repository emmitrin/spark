package task

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/emmitrin/spark/internal/clients/docker"
	"github.com/emmitrin/spark/internal/clients/opensearch"
	"github.com/emmitrin/spark/internal/models"
	"github.com/emmitrin/spark/internal/monitor"
)

type Manager struct {
	tasks      map[string]*models.Task
	tasksMutex sync.RWMutex

	dockerClient     *docker.Client
	monitor          monitor.Monitor
	opensearchClient *opensearch.Client
	echoMode         bool
	logger           *logrus.Logger
}

func NewManager(
	dockerClient *docker.Client,
	monitor monitor.Monitor,
	opensearchClient *opensearch.Client,
	echoMode bool,
	logger *logrus.Logger,
) *Manager {
	return &Manager{
		tasks:            make(map[string]*models.Task),
		dockerClient:     dockerClient,
		monitor:          monitor,
		opensearchClient: opensearchClient,
		echoMode:         echoMode,
		logger:           logger,
	}
}

func (m *Manager) EnqueueTask(ctx context.Context, input *models.EnqueueTaskInput) (*models.EnqueueTaskResult, error) {
	taskID := uuid.New().String()

	limits := m.defaultLimits(input.ResourceLimits)

	image := m.taskImage(input.Image)
	containerName := fmt.Sprintf("spark-task-%s", taskID)

	containerInfo, err := m.dockerClient.StartContainer(ctx, image, containerName, limits, nil)
	if err != nil {
		return &models.EnqueueTaskResult{
			Success: false,
			TaskID:  taskID,
			Message: fmt.Sprintf("Failed to start container: %v", err),
		}, nil
	}

	task := &models.Task{
		ID:          taskID,
		ContainerID: containerInfo.ID,
		Status:      models.TaskStatusRunning,
		CreatedAt:   time.Now(),
		Limits:      limits,
		StopChan:    make(chan struct{}),
	}

	m.tasksMutex.Lock()
	m.tasks[taskID] = task
	m.tasksMutex.Unlock()

	if err := m.monitor.Start(ctx, containerInfo.ID, taskID); err != nil {
		m.logger.Warnf("Failed to start monitoring for task %s: %v", taskID, err)
	}

	go m.collectMetrics(ctx, task)

	if input.TimeoutSeconds > 0 {
		go m.scheduleTermination(ctx, taskID, input.TimeoutSeconds)
	}

	return &models.EnqueueTaskResult{
		Success:     true,
		TaskID:      taskID,
		Message:     "Task enqueued successfully",
		ContainerID: containerInfo.ID,
	}, nil
}

func (m *Manager) scheduleTermination(ctx context.Context, taskID string, timeoutSeconds int32) {
	time.Sleep(time.Duration(timeoutSeconds) * time.Second)

	_, _ = m.TerminateTask(ctx, taskID, false)
}

func (m *Manager) taskImage(image string) string {
	if image == "" {
		return "alpine:latest"
	}

	return image
}

func (m *Manager) defaultLimits(limits models.ResourceLimits) models.ResourceLimits {
	if limits.CPULimit == 0 {
		limits.CPULimit = 0.5
	}

	if limits.MemoryLimit == 0 {
		limits.MemoryLimit = 512 * 1024 * 1024
	}

	return limits
}

func (m *Manager) TerminateTask(ctx context.Context, taskID string, force bool) (*models.TerminateTaskResult, error) {
	m.tasksMutex.Lock()
	task, exists := m.tasks[taskID]

	if !exists {
		m.tasksMutex.Unlock()

		return &models.TerminateTaskResult{
			Success: false,
			Message: fmt.Sprintf("Task %s not found", taskID),
		}, nil
	}

	delete(m.tasks, taskID)
	m.tasksMutex.Unlock()

	if err := m.monitor.Stop(task.ContainerID); err != nil {
		m.logger.Warnf("Failed to stop monitoring: %v", err)
	}

	if err := m.dockerClient.StopContainer(ctx, task.ContainerID, force); err != nil {
		return &models.TerminateTaskResult{
			Success: false,
			Message: fmt.Sprintf("Failed to stop container: %v", err),
		}, nil
	}

	close(task.StopChan)

	return &models.TerminateTaskResult{
		Success: true,
		Message: "Task terminated successfully",
	}, nil
}

func (m *Manager) GetCurrentState(ctx context.Context) (*models.WorkerState, error) {
	m.tasksMutex.RLock()
	defer m.tasksMutex.RUnlock()

	tasks := make([]*models.TaskInfo, 0, len(m.tasks))
	for _, task := range m.tasks {
		containerInfo, err := m.dockerClient.GetContainerInfo(ctx, task.ContainerID)
		if err != nil {
			m.logger.Warnf("Failed to get container info for %s: %v", task.ContainerID, err)
			continue
		}

		stats, err := m.dockerClient.GetContainerStats(ctx, task.ContainerID)
		if err != nil {
			m.logger.Warnf("Failed to get container stats for %s: %v", task.ContainerID, err)
		}

		resourceUsage := &models.ResourceUsage{}
		if stats != nil {
			resourceUsage = stats
		}

		status := m.containerStatusToTaskStatus(containerInfo.Status)

		taskInfo := &models.TaskInfo{
			TaskID:      task.ID,
			Status:      status,
			ContainerID: task.ContainerID,
			CreatedAt:   task.CreatedAt.Unix(),
			Resources:   resourceUsage,
			Networks:    containerInfo.Networks,
		}

		tasks = append(tasks, taskInfo)
	}

	workerStatus := models.WorkerStatusHealthy
	if len(tasks) > 10 {
		workerStatus = models.WorkerStatusDegraded
	}

	return &models.WorkerState{
		Status:    workerStatus,
		Tasks:     tasks,
		Resources: &models.ResourceUsage{},
	}, nil
}

func (m *Manager) containerStatusToTaskStatus(containerStatus string) models.TaskStatus {
	switch containerStatus {
	case "running":
		return models.TaskStatusRunning
	case "exited":
		return models.TaskStatusCompleted
	default:
		return models.TaskStatusUnknown
	}
}

func (m *Manager) collectMetrics(ctx context.Context, task *models.Task) {
	metricsTicker := time.NewTicker(5 * time.Second)
	eventTicker := time.NewTicker(1 * time.Second)

	defer metricsTicker.Stop()
	defer eventTicker.Stop()

	events := make([]models.MonitorEvent, 0)

	drainEvents := func() {
		eventChan := m.monitor.GetEvents(task.ContainerID)
		if eventChan == nil {
			return
		}

		for {
			select {
			case event, ok := <-eventChan:
				if !ok {
					return
				}

				events = append(events, event)
			default:
				return
			}
		}
	}

	for {
		select {
		case <-task.StopChan:
			drainEvents()

			if len(events) > 0 {
				m.sendIoC(ctx, task, events)
			}

			return
		case <-eventTicker.C:
			drainEvents()

			if len(events) > 0 {
				m.sendIoC(ctx, task, events)
				events = events[:0]
			}
		case <-metricsTicker.C:
			drainEvents()

			if len(events) > 0 {
				m.sendIoC(ctx, task, events)
				events = events[:0]
			}
		}
	}
}

func (m *Manager) sendIoC(ctx context.Context, task *models.Task, events []models.MonitorEvent) {
	if len(events) == 0 {
		return
	}

	if m.echoMode {
		m.logEvents(task, events)
		return
	}

	if m.opensearchClient == nil {
		return
	}

	ioc := m.convertToIoC(events)

	doc := &models.IoCDocument{
		TaskID:      task.ID,
		ContainerID: task.ContainerID,
		Timestamp:   time.Now(),
		IoC:         ioc,
		Metadata: map[string]interface{}{
			"container_name": task.ContainerID,
			"status":         task.Status,
			"created_at":     task.CreatedAt,
		},
	}

	if err := m.opensearchClient.IndexIoC(ctx, doc); err != nil {
		m.logger.Errorf("Failed to index IoC for task %s: %v", task.ID, err)
	} else {
		m.logger.Debugf("Indexed IoC for task %s with %d events", task.ID, len(events))
	}
}

func (m *Manager) logEvents(task *models.Task, events []models.MonitorEvent) {
	m.logger.Infof("[echo] task=%s container=%s events=%d", task.ID, task.ContainerID, len(events))

	for i, e := range events {
		m.logger.Infof("[echo] #%d type=%s pid=%d comm=%s details=%v",
			i+1, e.EventType, e.Process.PID, e.Process.Comm, e.Details)
	}
}

func (m *Manager) convertToIoC(events []models.MonitorEvent) map[string]interface{} {
	ioc := make(map[string]interface{})

	fileOps := make([]map[string]interface{}, 0)
	networkOps := make([]map[string]interface{}, 0)

	for _, event := range events {
		switch event.EventType {
		case models.EventTypeFileWrite, models.EventTypeFileRead, models.EventTypeFileOpen:
			fileOps = append(fileOps, map[string]interface{}{
				"type":      event.EventType,
				"timestamp": event.Timestamp,
				"process":   event.Process,
				"details":   event.Details,
			})
		case models.EventTypeNetworkConnect, models.EventTypeNetworkAccept, models.EventTypeNetworkSend, models.EventTypeNetworkRecv:
			networkOps = append(networkOps, map[string]interface{}{
				"type":      event.EventType,
				"timestamp": event.Timestamp,
				"process":   event.Process,
				"details":   event.Details,
			})
		}
	}

	if len(fileOps) > 0 {
		ioc["file_operations"] = fileOps
	}

	if len(networkOps) > 0 {
		ioc["network_operations"] = networkOps
	}

	ioc["metadata"] = map[string]interface{}{
		"total_events":   len(events),
		"file_events":    len(fileOps),
		"network_events": len(networkOps),
		"generated_at":   time.Now(),
	}

	return ioc
}
