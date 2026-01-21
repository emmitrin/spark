package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
)

type FileEvent struct {
	PID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	Comm      [16]byte
	Path      [256]byte
	Flags     uint32
	Result    uint32
	Timestamp uint64
}

type NetworkEvent struct {
	PID        uint32
	PPID       uint32
	UID        uint32
	GID        uint32
	Comm       [16]byte
	Protocol   uint32 // 0 — TCP, 1 — UDP
	LocalIP    uint32
	LocalPort  uint32
	RemoteIP   uint32
	RemotePort uint32
	Result     uint32
	Timestamp  uint64
}

type Loader struct {
	logger        *logrus.Logger
	fileEventsMap *ebpf.Map
	netEventsMap  *ebpf.Map
	monitoredPids *ebpf.Map
	fileReader    *perf.Reader
	netReader     *perf.Reader
	links         []link.Link
	mu            sync.Mutex
	readMu        sync.Mutex
}

func NewLoader(logger *logrus.Logger, objectPath string) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	spec, err := loadEBPFSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	loader := &Loader{
		logger:        logger,
		fileEventsMap: coll.Maps["file_events_map"],
		netEventsMap:  coll.Maps["network_events_map"],
		monitoredPids: coll.Maps["monitored_pids"],
		links:         make([]link.Link, 0),
	}

	perCPUBufferSize := 64 * 1024
	fileReader, err := perf.NewReader(loader.fileEventsMap, perCPUBufferSize)

	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to create file events reader: %w", err)
	}

	loader.fileReader = fileReader

	netReader, err := perf.NewReader(loader.netEventsMap, perCPUBufferSize)
	if err != nil {
		fileReader.Close()
		coll.Close()

		return nil, fmt.Errorf("failed to create network events reader: %w", err)
	}

	loader.netReader = netReader

	if err := loader.attachPrograms(coll); err != nil {
		loader.Close()
		return nil, fmt.Errorf("failed to attach programs: %w", err)
	}

	return loader, nil
}

// loadEBPFSpec: objectPath → cwd → exe dir → compile .c
func loadEBPFSpec(objectPath string) (*ebpf.CollectionSpec, error) {
	tryLoad := func(path string) (*ebpf.CollectionSpec, bool) {
		f, err := os.Open(path)
		if err != nil {
			return nil, false
		}
		defer f.Close()
		spec, err := ebpf.LoadCollectionSpecFromReader(f)

		if err != nil {
			return nil, false
		}

		return spec, true
	}

	if objectPath != "" {
		if spec, ok := tryLoad(objectPath); ok {
			return spec, nil
		}
	}

	bpfDir := filepath.Join("internal", "monitor", "ebpf", "bpf")
	compiledPath := filepath.Join(bpfDir, "bpf_programs.o")

	if spec, ok := tryLoad(compiledPath); ok {
		return spec, nil
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)

		for _, rel := range []string{
			"bpf_programs.o",
			filepath.Join("internal", "monitor", "ebpf", "bpf", "bpf_programs.o"),
			filepath.Join("..", "internal", "monitor", "ebpf", "bpf", "bpf_programs.o"),
		} {
			p := filepath.Join(exeDir, rel)
			if spec, ok := tryLoad(p); ok {
				return spec, nil
			}
		}
	}

	sourcePath := filepath.Join(bpfDir, "bpf_programs.c")
	if _, err := os.Stat(sourcePath); err == nil {
		if CompileEBPFPrograms(sourcePath, compiledPath) == nil {
			if spec, ok := tryLoad(compiledPath); ok {
				return spec, nil
			}
		}
	}

	// Стабы
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"file_events_map": {
				Type:       ebpf.PerfEventArray,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 0,
			},
			"network_events_map": {
				Type:       ebpf.PerfEventArray,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 0,
			},
			"monitored_pids": {
				Type:       ebpf.Hash,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1024,
			},
		},
		Programs: map[string]*ebpf.ProgramSpec{},
	}

	return spec, nil
}

// AddMonitoredPID: в ядре eBPF ищет по pid/tgid; мы сохраняем PID процесса (tgid для главного потока).
func (l *Loader) AddMonitoredPID(pid uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	value := uint32(1)
	if err := l.monitoredPids.Put(pid, value); err != nil {
		return fmt.Errorf("failed to add monitored PID: %w", err)
	}

	l.logger.Debugf("Added PID %d (and TGID) to monitoring", pid)

	return nil
}

func (l *Loader) RemoveMonitoredPID(pid uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.monitoredPids.Delete(pid); err != nil {
		return fmt.Errorf("failed to remove monitored PID: %w", err)
	}

	l.logger.Debugf("Removed PID %d from monitoring", pid)

	return nil
}

func (l *Loader) ReadFileEvents() ([]FileEvent, error) {
	if l.fileReader == nil {
		return nil, fmt.Errorf("file reader not initialized")
	}

	l.readMu.Lock()
	defer l.readMu.Unlock()

	events := make([]FileEvent, 0)

	l.fileReader.SetDeadline(time.Now().Add(50 * time.Millisecond))

	for {
		record, err := l.fileReader.Read()
		if err != nil {
			if err == perf.ErrClosed {
				break
			}

			if errors.Is(err, os.ErrDeadlineExceeded) {
				return events, nil
			}

			return events, err
		}

		if len(record.RawSample) < int(unsafe.Sizeof(FileEvent{})) {
			continue
		}

		var event FileEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			l.logger.Warnf("Failed to parse file event: %v", err)
			continue
		}

		events = append(events, event)
		if len(events) >= 100 {
			break
		}
	}

	if len(events) > 0 {
		l.logger.Debugf("[ebpf loader] ReadFileEvents: n=%d", len(events))
	}

	return events, nil
}

func (l *Loader) ReadNetworkEvents() ([]NetworkEvent, error) {
	if l.netReader == nil {
		return nil, fmt.Errorf("network reader not initialized")
	}

	l.readMu.Lock()
	defer l.readMu.Unlock()

	events := make([]NetworkEvent, 0)

	l.netReader.SetDeadline(time.Now().Add(50 * time.Millisecond))

	for {
		record, err := l.netReader.Read()
		if err != nil {
			if err == perf.ErrClosed {
				break
			}

			if errors.Is(err, os.ErrDeadlineExceeded) {
				return events, nil
			}

			return events, err
		}

		if len(record.RawSample) < int(unsafe.Sizeof(NetworkEvent{})) {
			continue
		}

		var event NetworkEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			l.logger.Warnf("Failed to parse network event: %v", err)
			continue
		}

		events = append(events, event)
		if len(events) >= 100 {
			break
		}
	}

	if len(events) > 0 {
		l.logger.Debugf("[ebpf loader] ReadNetworkEvents: n=%d", len(events))
	}

	return events, nil
}

func (l *Loader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.fileReader != nil {
		l.fileReader.Close()
	}

	if l.netReader != nil {
		l.netReader.Close()
	}

	for _, lnk := range l.links {
		lnk.Close()
	}

	if l.fileEventsMap != nil {
		l.fileEventsMap.Close()
	}

	if l.netEventsMap != nil {
		l.netEventsMap.Close()
	}

	if l.monitoredPids != nil {
		l.monitoredPids.Close()
	}

	return nil
}

func (l *Loader) attachPrograms(coll *ebpf.Collection) error {
	attachedCount := 0

	fileTracepoints := []struct {
		group string
		name  string
		prog  string
	}{
		{"syscalls", "sys_enter_openat", "tracepoint_sys_enter_openat"},
		{"syscalls", "sys_enter_open", "tracepoint_sys_enter_open"},
		{"syscalls", "sys_enter_write", "tracepoint_sys_enter_write"},
		{"syscalls", "sys_enter_read", "tracepoint_sys_enter_read"},
	}

	netTracepoints := []struct {
		group string
		name  string
		prog  string
	}{
		{"syscalls", "sys_enter_connect", "tracepoint_sys_enter_connect"},
		{"syscalls", "sys_enter_accept4", "tracepoint_sys_enter_accept4"},
		{"syscalls", "sys_enter_sendto", "tracepoint_sys_enter_sendto"},
		{"syscalls", "sys_enter_recvfrom", "tracepoint_sys_enter_recvfrom"},
	}

	for _, tp := range fileTracepoints {
		prog := coll.Programs[tp.prog]
		if prog == nil {
			// clang может кидать tracepoint__sys_enter_* или tracepoint_sys_enter_*
			for progName, p := range coll.Programs {
				if progName == tp.prog ||
					progName == "tracepoint__sys_enter_"+tp.name ||
					progName == "tracepoint_sys_enter_"+tp.name {
					prog = p
					break
				}
			}
		}

		if prog != nil {
			lnk, err := link.Tracepoint(tp.group, tp.name, prog, nil)
			if err != nil {
				l.logger.Warnf("Failed to attach tracepoint %s/%s: %v", tp.group, tp.name, err)
				continue
			}

			l.links = append(l.links, lnk)
			attachedCount++

			l.logger.Infof("Attached eBPF program to tracepoint: %s/%s", tp.group, tp.name)
		} else {
			l.logger.Debugf("Program %s not found in collection", tp.prog)
		}
	}

	for _, tp := range netTracepoints {
		prog := coll.Programs[tp.prog]
		if prog == nil {
			for progName, p := range coll.Programs {
				if progName == tp.prog ||
					progName == "tracepoint__sys_enter_"+tp.name ||
					progName == "tracepoint_sys_enter_"+tp.name {
					prog = p
					break
				}
			}
		}

		if prog != nil {
			lnk, err := link.Tracepoint(tp.group, tp.name, prog, nil)
			if err != nil {
				l.logger.Warnf("Failed to attach tracepoint %s/%s: %v", tp.group, tp.name, err)
				continue
			}

			l.links = append(l.links, lnk)
			attachedCount++

			l.logger.Infof("Attached eBPF program to tracepoint: %s/%s", tp.group, tp.name)
		} else {
			l.logger.Debugf("Program %s not found in collection", tp.prog)
		}
	}

	if attachedCount == 0 {
		l.logger.Warn("No eBPF programs found")

		return nil
	}

	l.logger.Infof("Successfully attached %d eBPF programs to tracepoints", attachedCount)

	return nil
}

func GetContainerPIDs(containerID string) ([]uint32, error) {
	pids := make([]uint32, 0)
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)

	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		pid, err := parsePID(pidStr)

		if err != nil {
			continue
		}

		pids = append(pids, pid)
	}

	return pids, nil
}

func parsePID(s string) (uint32, error) {
	var pid uint32
	_, err := fmt.Sscanf(s, "%d", &pid)

	return pid, err
}

func CompileEBPFPrograms(sourcePath, outputPath string) error {
	if _, err := exec.LookPath("clang"); err != nil {
		return fmt.Errorf("clang not found: %w", err)
	}

	cmd := exec.Command("clang",
		"-target", "bpf",
		"-O2", "-g",
		"-c", sourcePath,
		"-o", outputPath,
		"-I/usr/include",
		"-I/usr/include/bpf",
		"-I/usr/include/x86_64-linux-gnu",
		"-D__TARGET_ARCH_x86",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to compile eBPF: %w\n%s", err, stderr.String())
	}

	return nil
}
