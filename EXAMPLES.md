# Примеры использования Spark Worker Node API

## gRPC API

Worker Node предоставляет gRPC API для управления контейнерами. Ниже приведены примеры использования.

## Установка клиентских инструментов

```bash
# Установка grpcurl для тестирования
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Или через brew (macOS)
brew install grpcurl
```

## Примеры вызовов

### 1. Получение текущего состояния воркера

```bash
grpcurl -plaintext localhost:50051 worker.WorkerService/GetCurrentState
```

Ответ:
```json
{
  "status": "WORKER_STATUS_HEALTHY",
  "tasks": [],
  "resources": {
    "cpuUsagePercent": 0.0,
    "memoryUsedBytes": 0,
    "memoryLimitBytes": 0,
    "networkRxBytes": 0,
    "networkTxBytes": 0
  }
}
```

### 2. Запуск новой задачи (контейнера)

```bash
grpcurl -plaintext -d '{
  "task_id": "test-task-1",
  "docker_compose": "",
  "resource_limits": {
    "cpu_limit": 0.5,
    "memory_limit_bytes": 536870912,
    "disk_limit_bytes": 1073741824,
    "network_bandwidth_mbps": 100
  },
  "timeout_seconds": 300
}' localhost:50051 worker.WorkerService/EnqueueTask
```

Ответ:
```json
{
  "success": true,
  "task_id": "test-task-1",
  "message": "Task enqueued successfully",
  "container_id": "abc123def456..."
}
```

### 3. Завершение задачи

```bash
grpcurl -plaintext -d '{
  "task_id": "test-task-1",
  "force": false
}' localhost:50051 worker.WorkerService/TerminateTask
```

Ответ:
```json
{
  "success": true,
  "message": "Task terminated successfully"
}
```

## Использование из Go кода

```go
package main

import (
    "context"
    "log"
    
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    pb "github.com/emmitrin/spark/pkg/proto"
)

func main() {
    conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()
    
    client := pb.NewWorkerServiceClient(conn)
    
    // Получаем состояние
    state, err := client.GetCurrentState(context.Background(), &pb.GetCurrentStateRequest{})
    if err != nil {
        log.Fatalf("Failed to get state: %v", err)
    }
    log.Printf("Worker status: %v", state.Status)
    
    // Запускаем задачу
    resp, err := client.EnqueueTask(context.Background(), &pb.EnqueueTaskRequest{
        TaskId: "my-task",
        ResourceLimits: &pb.ResourceLimits{
            CpuLimit: 0.5,
            MemoryLimitBytes: 512 * 1024 * 1024,
        },
        TimeoutSeconds: 300,
    })
    if err != nil {
        log.Fatalf("Failed to enqueue task: %v", err)
    }
    log.Printf("Task enqueued: %v", resp)
}
```

## Просмотр данных в OpenSearch

После запуска задач, метрики и IoC отправляются в OpenSearch. Вы можете просмотреть их:

```bash
# Через curl
curl -u admin:admin "http://localhost:9200/spark-ioc/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match_all": {}
  },
  "size": 10
}'

# Или через OpenSearch Dashboards
# Откройте http://localhost:5601 в браузере
```

## Структура IoC документа в OpenSearch

```json
{
  "task_id": "test-task-1",
  "container_id": "abc123...",
  "timestamp": "2024-01-15T12:34:56Z",
  "ioc": {
    "file_operations": [
      {
        "type": "file_write",
        "timestamp": "2024-01-15T12:34:57Z",
        "process": {
          "pid": 1234,
          "comm": "test-process",
          "exe_path": "/usr/bin/test"
        },
        "details": {
          "path": "/tmp/test_file.txt",
          "flags": 577,
          "result": 0
        }
      }
    ],
    "network_operations": [
      {
        "type": "network_connect",
        "timestamp": "2024-01-15T12:34:58Z",
        "process": {
          "pid": 1235,
          "comm": "curl"
        },
        "details": {
          "protocol": "tcp",
          "remote_ip": "8.8.8.8",
          "remote_port": 53
        }
      }
    ],
    "metadata": {
      "total_events": 2,
      "file_events": 1,
      "network_events": 1
    }
  },
  "metadata": {
    "container_name": "abc123...",
    "status": 2,
    "created_at": "2024-01-15T12:34:56Z"
  }
}
```
