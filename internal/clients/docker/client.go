package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"

	"github.com/emmitrin/spark/internal/models"
)

type Client struct {
	client    *client.Client
	useGVisor bool
	runtime   string
	logger    *logrus.Logger
}

func NewClient(endpoint string, useGVisor bool, runtime string, logger *logrus.Logger) (*Client, error) {
	cli, err := client.NewClientWithOpts(
		client.WithHost(endpoint),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	return &Client{
		client:    cli,
		useGVisor: useGVisor,
		runtime:   runtime,
		logger:    logger,
	}, nil
}

func (c *Client) StartContainer(ctx context.Context, image string, name string, limits models.ResourceLimits, env []string) (*models.ContainerInfo, error) {
	config := &container.Config{
		Image: image,
		Env:   env,
	}

	oomKillDisable := false
	pidsLimit := int64(100)
	readonlyRootfs := false

	hostConfig := &container.HostConfig{
		Privileged:  false,
		CapDrop:     []string{"ALL"},
		CapAdd:      []string{"NET_BIND_SERVICE", "CHOWN", "SETGID", "SETUID"},
		SecurityOpt: []string{"no-new-privileges:true"},
		ReadonlyRootfs:  readonlyRootfs,
		Resources: container.Resources{
			CPUQuota:          int64(limits.CPULimit * 100000),
			CPUPeriod:         100000,
			Memory:            limits.MemoryLimit,
			MemorySwap:        limits.MemoryLimit,
			OomKillDisable:    &oomKillDisable,
			PidsLimit:         &pidsLimit,
			DeviceCgroupRules: []string{"c *:* m", "b *:* m"},
		},
		RestartPolicy: container.RestartPolicy{
			Name: "no",
		},
		NetworkMode: "bridge",
	}

	if c.useGVisor {
		hostConfig.Runtime = c.runtime
		c.logger.Infof("Using gVisor runtime: %s", c.runtime)
	}

	resp, err := c.client.ContainerCreate(ctx, config, hostConfig, nil, nil, name)
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	if err := c.client.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		_ = c.client.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	return c.GetContainerInfo(ctx, resp.ID)
}

func (c *Client) StopContainer(ctx context.Context, containerID string, force bool) error {
	timeoutDuration := 10 * time.Second

	var timeout *int

	if !force {
		timeoutSeconds := int(timeoutDuration.Seconds())
		timeout = &timeoutSeconds
	}

	if err := c.client.ContainerStop(ctx, containerID, container.StopOptions{Timeout: timeout}); err != nil {
		if !force {
			return fmt.Errorf("failed to stop container: %w", err)
		}

		c.logger.Warnf("Failed to stop container gracefully, forcing removal: %v", err)
	}

	removeOpts := container.RemoveOptions{
		Force:         force,
		RemoveVolumes: true,
	}

	if err := c.client.ContainerRemove(ctx, containerID, removeOpts); err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	return nil
}

func (c *Client) GetContainerStats(ctx context.Context, containerID string) (*models.ResourceUsage, error) {
	stats, err := c.client.ContainerStats(ctx, containerID, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get container stats: %w", err)
	}
	defer stats.Body.Close()

	var statsJSON types.StatsJSON
	if err := json.NewDecoder(stats.Body).Decode(&statsJSON); err != nil {
		return nil, fmt.Errorf("failed to decode stats: %w", err)
	}

	return c.statsToResourceUsage(&statsJSON), nil
}

func (c *Client) statsToResourceUsage(stats *types.StatsJSON) *models.ResourceUsage {
	ru := &models.ResourceUsage{
		MemoryUsedBytes:  int64(stats.MemoryStats.Usage),
		MemoryLimitBytes: int64(stats.MemoryStats.Limit),
	}

	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)

	if systemDelta > 0 {
		ru.CPUUsagePercent = (cpuDelta / systemDelta) * 100.0
	}

	for _, netStats := range stats.Networks {
		ru.NetworkRxBytes += int64(netStats.RxBytes)
		ru.NetworkTxBytes += int64(netStats.TxBytes)
	}

	return ru
}

func (c *Client) GetContainerInfo(ctx context.Context, containerID string) (*models.ContainerInfo, error) {
	info, err := c.client.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	networks := make([]string, 0, len(info.NetworkSettings.Networks))
	for netName := range info.NetworkSettings.Networks {
		networks = append(networks, netName)
	}

	createdAt, err := time.Parse(time.RFC3339Nano, info.Created)
	if err != nil {
		createdAt = time.Now()
	}

	return &models.ContainerInfo{
		ID:        info.ID,
		Name:      info.Name,
		Status:    info.State.Status,
		CreatedAt: createdAt,
		Networks:  networks,
	}, nil
}

func (c *Client) GetContainerLogs(ctx context.Context, containerID string, tail string) (io.ReadCloser, error) {
	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       tail,
		Follow:     false,
	}

	return c.client.ContainerLogs(ctx, containerID, options)
}

func (c *Client) Close() error {
	return c.client.Close()
}
