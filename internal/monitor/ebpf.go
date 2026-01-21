package monitor

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/emmitrin/spark/internal/models"
	"github.com/emmitrin/spark/internal/monitor/ebpf"
)

type Monitor interface {
	Start(ctx context.Context, containerID string, taskID string) error
	Stop(containerID string) error
	GetEvents(containerID string) <-chan models.MonitorEvent
	Close() error
}

type eBPFMonitor struct {
	logger         *logrus.Logger
	enabled        bool
	fileOps        bool
	networkOps     bool
	pidsFromCgroup bool
	containers     map[string]*containerMonitor
	containersMu   sync.RWMutex
	events         map[string]chan models.MonitorEvent
	ebpfLoader     *ebpf.Loader
	containerPIDs  map[string][]uint32
	pidsMu         sync.RWMutex
	readLoopCtx    context.Context
	readLoopCancel context.CancelFunc
}

type containerMonitor struct {
	containerID string
	taskID      string
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewEBPFMonitor создаёт монитор. bpfObjectPath — необязательный путь к bpf_programs.o; пустой — авто-поиск и fallback на заглушки.
// pidsFromCgroup: при true PIDs берутся из cgroup контейнера (включая docker exec), иначе main + children.
func NewEBPFMonitor(logger *logrus.Logger, enabled, fileOps, networkOps bool, bpfObjectPath string, pidsFromCgroup bool) Monitor {
	m := &eBPFMonitor{
		logger:         logger,
		enabled:        enabled,
		fileOps:        fileOps,
		networkOps:     networkOps,
		pidsFromCgroup: pidsFromCgroup,
		containers:     make(map[string]*containerMonitor),
		events:         make(map[string]chan models.MonitorEvent),
		containerPIDs:  make(map[string][]uint32),
	}

	if enabled {
		loader, err := ebpf.NewLoader(logger, bpfObjectPath)
		if err != nil {
			logger.Warnf("Failed to initialize eBPF loader: %v. Monitoring will use stubs.", err)

			m.enabled = false
		} else {
			m.ebpfLoader = loader
		}
	}

	return m
}

func (m *eBPFMonitor) Start(ctx context.Context, containerID string, taskID string) error {
	if !m.enabled {
		m.logger.Debug("Monitoring is disabled")
		return nil
	}

	monCtx, cancel := context.WithCancel(ctx)
	mon := &containerMonitor{
		containerID: containerID,
		taskID:      taskID,
		ctx:         monCtx,
		cancel:      cancel,
	}

	m.containersMu.Lock()
	m.containers[containerID] = mon
	m.events[containerID] = make(chan models.MonitorEvent, 100)
	m.containersMu.Unlock()

	pids, err := m.getContainerPIDs(containerID)
	if err != nil {
		m.logger.Warnf("Failed to get container PIDs: %v", err)
	} else {
		m.pidsMu.Lock()
		m.containerPIDs[containerID] = pids
		m.pidsMu.Unlock()
		if m.ebpfLoader != nil {
			for _, pid := range pids {
				if err := m.ebpfLoader.AddMonitoredPID(pid); err != nil {
					m.logger.Warnf("Failed to add PID %d to monitoring: %v", pid, err)
				}
			}
		}
	}

	if m.ebpfLoader != nil && m.readLoopCancel == nil {
		m.readLoopCtx, m.readLoopCancel = context.WithCancel(context.Background())
		go m.runReadLoop(m.readLoopCtx)
	}

	m.logger.Infof("Started monitoring for container %s (task %s) with %d PIDs", containerID, taskID, len(pids))

	return nil
}

func (m *eBPFMonitor) Stop(containerID string) error {
	m.containersMu.Lock()
	mon, exists := m.containers[containerID]

	if !exists {
		m.containersMu.Unlock()
		return fmt.Errorf("monitor not found for container %s", containerID)
	}

	mon.cancel()
	delete(m.containers, containerID)
	ch := m.events[containerID]
	delete(m.events, containerID)
	m.containersMu.Unlock()

	m.pidsMu.Lock()
	pids := m.containerPIDs[containerID]
	delete(m.containerPIDs, containerID)
	m.pidsMu.Unlock()

	if len(pids) > 0 && m.ebpfLoader != nil {
		for _, pid := range pids {
			_ = m.ebpfLoader.RemoveMonitoredPID(pid)
		}
	}

	if ch != nil {
		close(ch)
	}

	m.logger.Infof("Stopped monitoring for container %s", containerID)

	return nil
}

func (m *eBPFMonitor) GetEvents(containerID string) <-chan models.MonitorEvent {
	m.containersMu.RLock()
	ch := m.events[containerID]
	m.containersMu.RUnlock()

	return ch
}

func (m *eBPFMonitor) Close() error {
	m.containersMu.Lock()
	ids := make([]string, 0, len(m.containers))

	for id := range m.containers {
		ids = append(ids, id)
	}
	m.containersMu.Unlock()

	for _, id := range ids {
		_ = m.Stop(id)
	}

	if m.readLoopCancel != nil {
		m.readLoopCancel()
	}

	if m.ebpfLoader != nil {
		return m.ebpfLoader.Close()
	}

	return nil
}

func (m *eBPFMonitor) runReadLoop(ctx context.Context) {
	m.logger.Info("eBPF read loop started")

	ticker := time.NewTicker(100 * time.Millisecond)

	defer ticker.Stop()

	refreshTicker := time.NewTicker(2 * time.Second)

	defer refreshTicker.Stop()

	var cycle int64

	for {
		select {
		case <-ctx.Done():
			m.logger.Debug("eBPF read loop exiting (ctx.Done)")
			return
		case <-refreshTicker.C:
			m.containersMu.RLock()
			mons := make([]*containerMonitor, 0, len(m.containers))

			for _, mon := range m.containers {
				mons = append(mons, mon)
			}
			m.containersMu.RUnlock()

			for _, mon := range mons {
				m.refreshContainerPIDs(mon)
			}
		case <-ticker.C:
			cycle++
			if cycle%500 == 0 {
				m.logger.Infof("eBPF read loop alive: %d cycles (~%ds)", cycle, cycle*100/1000)
			}

			if m.ebpfLoader == nil {
				continue
			}

			if m.fileOps {
				m.readAndDispatchFileEvents()
			}

			if m.networkOps {
				m.readAndDispatchNetworkEvents()
			}
		}
	}
}

func (m *eBPFMonitor) getContainerIDsForPID(pid uint32) []string {
	m.pidsMu.RLock()
	defer m.pidsMu.RUnlock()

	var out []string

	for containerID, pids := range m.containerPIDs {
		for _, p := range pids {
			if p == pid {
				out = append(out, containerID)
				break
			}
		}
	}

	return out
}

func (m *eBPFMonitor) readAndDispatchFileEvents() {
	events, err := m.ebpfLoader.ReadFileEvents()
	if err != nil {
		m.logger.Debugf("Failed to read file events: %v", err)
		return
	}

	if len(events) > 0 {
		pids := make([]uint32, 0, len(events))
		for i := range events {
			pids = append(pids, events[i].PID)
		}

		m.pidsMu.RLock()
		monitored := make(map[string][]uint32)

		for cid, list := range m.containerPIDs {
			monitored[cid] = append([]uint32(nil), list...)
		}
		m.pidsMu.RUnlock()
		m.logger.Infof("eBPF file: received %d events (PIDs: %v), monitored PIDs per container: %v", len(events), pids, monitored)
	}

	for _, ebpfEvent := range events {
		containerIDs := m.getContainerIDsForPID(ebpfEvent.PID)
		for _, containerID := range containerIDs {
			m.containersMu.RLock()
			mon := m.containers[containerID]
			ch := m.events[containerID]
			m.containersMu.RUnlock()

			if mon == nil || ch == nil {
				continue
			}

			origPath := strings.TrimRight(string(ebpfEvent.Path[:]), "\x00")
			pathStr := origPath

			if origPath == "[read]" || origPath == "[write]" {
				pathStr = formatReadWritePath(origPath, ebpfEvent.Flags)
			}

			details := map[string]interface{}{
				"path":   pathStr,
				"flags":  ebpfEvent.Flags,
				"result": int(ebpfEvent.Result),
			}

			if origPath == "[read]" || origPath == "[write]" {
				details["fd"] = ebpfEvent.Flags
			}

			event := models.MonitorEvent{
				TaskID:      mon.taskID,
				ContainerID: mon.containerID,
				EventType:   models.EventTypeFileOpen,
				Timestamp:   time.Unix(0, int64(ebpfEvent.Timestamp)),
				Process: models.ProcessInfo{
					PID:     int(ebpfEvent.PID),
					PPID:    int(ebpfEvent.PPID),
					Comm:    strings.TrimRight(string(ebpfEvent.Comm[:]), "\x00"),
					UID:     int(ebpfEvent.UID),
					GID:     int(ebpfEvent.GID),
					ExePath: m.getExePath(ebpfEvent.PID),
				},
				Details: details,
			}

			if ebpfEvent.Flags&0x241 == 0x241 {
				event.EventType = models.EventTypeFileWrite
			} else {
				event.EventType = models.EventTypeFileRead
			}
			select {
			case ch <- event:
			default:
				m.logger.Warnf("Event channel full for container %s", containerID)
			}
		}
	}
}

func (m *eBPFMonitor) readAndDispatchNetworkEvents() {
	events, err := m.ebpfLoader.ReadNetworkEvents()
	if err != nil {
		m.logger.Debugf("Failed to read network events: %v", err)
		return
	}

	if len(events) > 0 {
		pids := make([]uint32, 0, len(events))
		for i := range events {
			pids = append(pids, events[i].PID)
		}

		m.pidsMu.RLock()
		monitored := make(map[string][]uint32)

		for cid, list := range m.containerPIDs {
			monitored[cid] = append([]uint32(nil), list...)
		}
		m.pidsMu.RUnlock()
		m.logger.Infof("eBPF network: received %d events (PIDs: %v), monitored PIDs per container: %v", len(events), pids, monitored)
	}

	for _, ebpfEvent := range events {
		containerIDs := m.getContainerIDsForPID(ebpfEvent.PID)
		for _, containerID := range containerIDs {
			m.containersMu.RLock()
			mon := m.containers[containerID]
			ch := m.events[containerID]
			m.containersMu.RUnlock()

			if mon == nil || ch == nil {
				continue
			}

			protocol := "tcp"

			if ebpfEvent.Protocol == 1 {
				protocol = "udp"
			}

			event := models.MonitorEvent{
				TaskID:      mon.taskID,
				ContainerID: mon.containerID,
				EventType:   models.EventTypeNetworkConnect,
				Timestamp:   time.Unix(0, int64(ebpfEvent.Timestamp)),
				Process: models.ProcessInfo{
					PID:     int(ebpfEvent.PID),
					PPID:    int(ebpfEvent.PPID),
					Comm:    strings.TrimRight(string(ebpfEvent.Comm[:]), "\x00"),
					UID:     int(ebpfEvent.UID),
					GID:     int(ebpfEvent.GID),
					ExePath: m.getExePath(ebpfEvent.PID),
				},
				Details: map[string]interface{}{
					"protocol":    protocol,
					"local_ip":    m.formatIP(ebpfEvent.LocalIP),
					"local_port":  int(ebpfEvent.LocalPort),
					"remote_ip":   m.formatIP(ebpfEvent.RemoteIP),
					"remote_port": int(ebpfEvent.RemotePort),
					"result":      int(ebpfEvent.Result),
				},
			}
			select {
			case ch <- event:
			default:
				m.logger.Warnf("Event channel full for container %s", containerID)
			}
		}
	}
}

// refreshContainerPIDs подтягивает новые PIDs контейнера (например, воркеры nginx) и добавляет их в eBPF мониторинг.
func (m *eBPFMonitor) refreshContainerPIDs(mon *containerMonitor) {
	m.containersMu.RLock()
	_, exists := m.containers[mon.containerID]
	m.containersMu.RUnlock()

	if !exists {
		return
	}

	pids, err := m.getContainerPIDs(mon.containerID)

	if err != nil {
		return
	}

	m.pidsMu.Lock()
	cur, exists := m.containerPIDs[mon.containerID]

	if !exists {
		m.pidsMu.Unlock()
		return
	}

	seen := make(map[uint32]bool)

	for _, p := range cur {
		seen[p] = true
	}

	var added []uint32

	for _, p := range pids {
		if !seen[p] {
			seen[p] = true

			cur = append(cur, p)
			added = append(added, p)
		}
	}

	m.containerPIDs[mon.containerID] = cur
	m.pidsMu.Unlock()

	if m.ebpfLoader != nil && len(added) > 0 {
		for _, pid := range added {
			_ = m.ebpfLoader.AddMonitoredPID(pid)
		}

		m.logger.Infof("Discovered %d new PIDs for container %s: %v", len(added), mon.containerID, added)
	}
}

func formatReadWritePath(pathStr string, fd uint32) string {
	if pathStr == "[read]" {
		if fd <= 2 {
			return "[tty_read]"
		}

		return fmt.Sprintf("[read fd:%d]", fd)
	}

	if pathStr == "[write]" {
		if fd <= 2 {
			return "[tty_write]"
		}

		return fmt.Sprintf("[write fd:%d]", fd)
	}

	return pathStr
}

func (m *eBPFMonitor) getExePath(pid uint32) string {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(exePath)

	if err != nil {
		return ""
	}

	return target
}

func (m *eBPFMonitor) formatIP(ip uint32) string {
	return net.IP([]byte{
		byte(ip >> 24),
		byte(ip >> 16),
		byte(ip >> 8),
		byte(ip),
	}).String()
}

func (m *eBPFMonitor) getContainerPIDs(containerID string) ([]uint32, error) {
	cmd := exec.Command("docker", "inspect", "--format", "{{.State.Pid}}", containerID)
	output, err := cmd.Output()

	if err != nil {
		return nil, fmt.Errorf("failed to get container PID: %w", err)
	}

	pidStr := strings.TrimSpace(string(output))
	mainPID, err := strconv.ParseUint(pidStr, 10, 32)

	if err != nil {
		return nil, fmt.Errorf("failed to parse PID: %w", err)
	}

	if m.pidsFromCgroup {
		return m.getContainerPIDsFromCgroup(uint32(mainPID))
	}

	pids := []uint32{uint32(mainPID)}
	procDir := fmt.Sprintf("/proc/%d/task/%d/children", mainPID, mainPID)
	data, err := os.ReadFile(procDir)

	if err == nil {
		children := strings.Fields(string(data))
		for _, childStr := range children {
			if childPID, err := strconv.ParseUint(childStr, 10, 32); err == nil {
				pids = append(pids, uint32(childPID))
			}
		}
	}

	return pids, nil
}

func (m *eBPFMonitor) getContainerPIDsFromCgroup(mainPID uint32) ([]uint32, error) {
	cgroupPath, err := m.getCgroupPath(mainPID)
	if err != nil {
		return nil, err
	}

	seen := make(map[uint32]bool)
	seen[mainPID] = true
	pids := []uint32{mainPID}
	err = filepath.Walk(cgroupPath, func(path string, info os.FileInfo, errWalk error) error {
		if errWalk != nil || !info.Mode().IsDir() {
			return nil
		}
		procsFile := filepath.Join(path, "cgroup.procs")
		data, errRead := os.ReadFile(procsFile)
		if errRead != nil {
			return nil
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			pid, errParse := strconv.ParseUint(line, 10, 32)
			if errParse != nil {
				continue
			}
			if !seen[uint32(pid)] {
				seen[uint32(pid)] = true
				pids = append(pids, uint32(pid))
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return pids, nil
}

func (m *eBPFMonitor) getCgroupPath(pid uint32) (string, error) {
	cgroupContent, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("read cgroup for pid %d: %w", pid, err)
	}

	for _, line := range strings.Split(strings.TrimSpace(string(cgroupContent)), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "0::") {
			path := strings.TrimPrefix(line, "0::")
			path = strings.TrimPrefix(path, "/")

			return filepath.Join("/sys/fs/cgroup", path), nil
		}
	}

	return "", fmt.Errorf("cgroup v2 path not found for pid %d", pid)
}
