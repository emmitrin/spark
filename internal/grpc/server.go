package grpc

import (
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/emmitrin/spark/internal/managers/task"
	"github.com/emmitrin/spark/internal/models"
	pb "github.com/emmitrin/spark/pkg/proto"
)

type Server struct {
	pb.UnimplementedWorkerServiceServer

	taskManager *task.Manager
	logger      *logrus.Logger
}

func NewServer(taskManager *task.Manager, logger *logrus.Logger) *Server {
	return &Server{
		taskManager: taskManager,
		logger:      logger,
	}
}

func (s *Server) GetCurrentState(ctx context.Context, req *pb.GetCurrentStateRequest) (*pb.GetCurrentStateResponse, error) {
	state, err := s.taskManager.GetCurrentState(ctx)
	if err != nil {
		return nil, err
	}

	return s.workerStateToProto(state), nil
}

func (s *Server) EnqueueTask(ctx context.Context, req *pb.EnqueueTaskRequest) (*pb.EnqueueTaskResponse, error) {
	input := s.enqueueRequestToInput(req)
	result, err := s.taskManager.EnqueueTask(ctx, input)

	if err != nil {
		return nil, err
	}

	return s.enqueueResultToProto(result), nil
}

func (s *Server) TerminateTask(ctx context.Context, req *pb.TerminateTaskRequest) (*pb.TerminateTaskResponse, error) {
	result, err := s.taskManager.TerminateTask(ctx, req.TaskId, req.Force)
	if err != nil {
		return nil, err
	}

	return s.terminateResultToProto(result), nil
}

func (s *Server) Register(grpcServer *grpc.Server) {
	pb.RegisterWorkerServiceServer(grpcServer, s)
}

func (s *Server) workerStateToProto(state *models.WorkerState) *pb.GetCurrentStateResponse {
	tasks := make([]*pb.TaskInfo, 0, len(state.Tasks))

	for _, t := range state.Tasks {
		tasks = append(tasks, s.taskInfoToProto(t))
	}

	var resources *pb.ResourceUsage

	if state.Resources != nil {
		resources = s.resourceUsageToProto(state.Resources)
	} else {
		resources = &pb.ResourceUsage{}
	}

	return &pb.GetCurrentStateResponse{
		Status:    s.workerStatusToProto(state.Status),
		Tasks:     tasks,
		Resources: resources,
	}
}

func (s *Server) taskInfoToProto(t *models.TaskInfo) *pb.TaskInfo {
	var resources *pb.ResourceUsage

	if t.Resources != nil {
		resources = s.resourceUsageToProto(t.Resources)
	}

	return &pb.TaskInfo{
		TaskId:      t.TaskID,
		Status:      s.taskStatusToProto(t.Status),
		ContainerId: t.ContainerID,
		CreatedAt:   t.CreatedAt,
		Resources:   resources,
		Networks:    t.Networks,
	}
}

func (s *Server) resourceUsageToProto(r *models.ResourceUsage) *pb.ResourceUsage {
	if r == nil {
		return &pb.ResourceUsage{}
	}

	return &pb.ResourceUsage{
		CpuUsagePercent:  r.CPUUsagePercent,
		MemoryUsedBytes:  r.MemoryUsedBytes,
		MemoryLimitBytes: r.MemoryLimitBytes,
		NetworkRxBytes:   r.NetworkRxBytes,
		NetworkTxBytes:   r.NetworkTxBytes,
	}
}

func (s *Server) workerStatusToProto(status models.WorkerStatus) pb.WorkerStatus {
	switch status {
	case models.WorkerStatusHealthy:
		return pb.WorkerStatus_WORKER_STATUS_HEALTHY
	case models.WorkerStatusDegraded:
		return pb.WorkerStatus_WORKER_STATUS_DEGRADED
	case models.WorkerStatusUnhealthy:
		return pb.WorkerStatus_WORKER_STATUS_UNHEALTHY
	default:
		return pb.WorkerStatus_WORKER_STATUS_UNKNOWN
	}
}

func (s *Server) taskStatusToProto(status models.TaskStatus) pb.TaskStatus {
	switch status {
	case models.TaskStatusPending:
		return pb.TaskStatus_TASK_STATUS_PENDING
	case models.TaskStatusRunning:
		return pb.TaskStatus_TASK_STATUS_RUNNING
	case models.TaskStatusCompleted:
		return pb.TaskStatus_TASK_STATUS_COMPLETED
	case models.TaskStatusFailed:
		return pb.TaskStatus_TASK_STATUS_FAILED
	case models.TaskStatusTerminated:
		return pb.TaskStatus_TASK_STATUS_TERMINATED
	default:
		return pb.TaskStatus_TASK_STATUS_UNKNOWN
	}
}

func (s *Server) enqueueRequestToInput(req *pb.EnqueueTaskRequest) *models.EnqueueTaskInput {
	limits := models.ResourceLimits{}

	if req.ResourceLimits != nil {
		limits = models.ResourceLimits{
			CPULimit:    req.ResourceLimits.CpuLimit,
			MemoryLimit: req.ResourceLimits.MemoryLimitBytes,
			DiskLimit:   req.ResourceLimits.DiskLimitBytes,
			NetworkBW:   req.ResourceLimits.NetworkBandwidthMbps,
		}
	}

	return &models.EnqueueTaskInput{
		Image:          req.GetImage(),
		ResourceLimits: limits,
		TimeoutSeconds: req.TimeoutSeconds,
	}
}

func (s *Server) enqueueResultToProto(result *models.EnqueueTaskResult) *pb.EnqueueTaskResponse {
	return &pb.EnqueueTaskResponse{
		Success:     result.Success,
		TaskId:      result.TaskID,
		Message:     result.Message,
		ContainerId: result.ContainerID,
	}
}

func (s *Server) terminateResultToProto(result *models.TerminateTaskResult) *pb.TerminateTaskResponse {
	return &pb.TerminateTaskResponse{
		Success: result.Success,
		Message: result.Message,
	}
}
