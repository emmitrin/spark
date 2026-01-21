package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/emmitrin/spark/internal/clients/docker"
	"github.com/emmitrin/spark/internal/clients/opensearch"
	"github.com/emmitrin/spark/internal/config"
	grpcserver "github.com/emmitrin/spark/internal/grpc"
	"github.com/emmitrin/spark/internal/managers/task"
	"github.com/emmitrin/spark/internal/monitor"
)

func main() {
	var configPath string

	flag.StringVar(&configPath, "config", "", "Path to YAML config file (optional; env vars override file)")
	flag.Parse()

	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Fatalf("Load config: %v", err)
	}

	if cfg.Log.Level == "debug" {
		logger.SetLevel(logrus.DebugLevel)
	}

	logger.Info("Starting spark")

	dockerClient, err := docker.NewClient(
		cfg.Docker.Endpoint,
		cfg.Docker.UseGVisor,
		cfg.Docker.GVisorRuntime,
		logger,
	)
	if err != nil {
		logger.Fatalf("Failed to initialize Docker client: %v", err)
	}
	defer dockerClient.Close()

	if cfg.Docker.UseGVisor {
		logger.Infof("Using gVisor runtime: %s", cfg.Docker.GVisorRuntime)
		logger.Info("Make sure gVisor (runsc) is installed and configured in Docker")
	}

	mon := monitor.NewEBPFMonitor(
		logger,
		cfg.Monitor.Enabled,
		cfg.Monitor.FileOpsEnabled,
		cfg.Monitor.NetworkOpsEnabled,
		cfg.Monitor.BPFObjectPath,
		cfg.Monitor.PidsFromCgroup,
	)
	defer mon.Close()

	var osClient *opensearch.Client

	enableOpenSearch := !cfg.Monitor.EchoMode

	if cfg.Monitor.EchoMode {
		logger.Info("Echo mode, no opensearch integration")
	}

	if enableOpenSearch {
		osClient, err = opensearch.NewClient(opensearch.Config{
			Addresses:  cfg.OpenSearch.Addresses,
			Username:   cfg.OpenSearch.Username,
			Password:   cfg.OpenSearch.Password,
			IndexName:  cfg.OpenSearch.IndexName,
			UseTLS:     cfg.OpenSearch.UseTLS,
			SkipVerify: cfg.OpenSearch.SkipVerify,
		}, logger)
		if err != nil {
			logger.Fatalf("Failed to initialize OpenSearch client: %v", err)
		}
		defer osClient.Close()
		logger.Info("OpenSearch client initialized")
	} else if !cfg.Monitor.EchoMode {
		logger.Info("OpenSearch integration disabled")
	}

	taskManager := task.NewManager(dockerClient, mon, osClient, cfg.Monitor.EchoMode, logger)

	grpcServer := grpc.NewServer()
	workerServer := grpcserver.NewServer(taskManager, logger)
	workerServer.Register(grpcServer)

	reflection.Register(grpcServer)
	logger.Info("gRPC reflection enabled")

	addr := fmt.Sprintf("%s:%d", cfg.GRPC.Address, cfg.GRPC.Port)
	listener, err := net.Listen("tcp", addr)

	if err != nil {
		logger.Fatalf("Failed to listen on %s: %v", addr, err)
	}

	logger.Infof("gRPC server listening on %s", addr)

	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			logger.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down...")
	grpcServer.GracefulStop()
	cancel()
	logger.Info("Shutdown complete")
}
