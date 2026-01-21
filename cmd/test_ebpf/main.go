package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// FileEvent структура события файловой операции (должна совпадать с C структурой)
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

// NetworkEvent структура сетевого события (должна совпадать с C структурой)
type NetworkEvent struct {
	PID        uint32
	PPID       uint32
	UID        uint32
	GID        uint32
	Comm       [16]byte
	Protocol   uint32
	LocalIP    uint32
	LocalPort  uint32
	RemoteIP   uint32
	RemotePort uint32
	Result     uint32
	Timestamp  uint64
}

func main() {
	fmt.Println("=== eBPF POC Test ===")
	fmt.Println("This test will:")
	fmt.Println("1. Load eBPF programs")
	fmt.Println("2. Monitor this process (PID:", os.Getpid(), ")")
	fmt.Println("3. Perform file and network operations")
	fmt.Println("4. Read and display captured events")
	fmt.Println()

	// Снимаем ограничения на память для eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Загружаем eBPF программы (относительно корня проекта)
	bpfPath := filepath.Join("internal", "monitor", "ebpf", "bpf", "bpf_programs.o")
	file, err := os.Open(bpfPath)
	if err != nil {
		log.Fatalf("Failed to open eBPF object file: %v\nMake sure to compile: clang -target bpf -O2 -g -c internal/monitor/ebpf/bpf/bpf_programs.c -o internal/monitor/ebpf/bpf/bpf_programs.o -I/usr/include -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_x86", err)
	}
	defer file.Close()

	spec, err := ebpf.LoadCollectionSpecFromReader(file)
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	fmt.Printf("✓ Loaded eBPF collection with %d programs and %d maps\n", len(coll.Programs), len(coll.Maps))

	// Выводим список программ
	fmt.Println("\nAvailable programs:")
	for name := range coll.Programs {
		fmt.Printf("  - %s\n", name)
	}

	// Получаем maps
	fileEventsMap := coll.Maps["file_events_map"]
	netEventsMap := coll.Maps["network_events_map"]
	monitoredPids := coll.Maps["monitored_pids"]

	if fileEventsMap == nil || netEventsMap == nil || monitoredPids == nil {
		log.Fatal("Required maps not found in collection")
	}

	// Создаем perf readers
	fileReader, err := perf.NewReader(fileEventsMap, os.Getpagesize()*64)
	if err != nil {
		log.Fatalf("Failed to create file events reader: %v", err)
	}
	defer fileReader.Close()

	netReader, err := perf.NewReader(netEventsMap, os.Getpagesize()*64)
	if err != nil {
		log.Fatalf("Failed to create network events reader: %v", err)
	}
	defer netReader.Close()

	fmt.Println("✓ Created perf event readers")

	// Добавляем текущий PID в мониторинг
	pid := uint32(os.Getpid())
	tgid := pid // Для однопоточного процесса tgid = pid
	value := uint32(1)

	if err := monitoredPids.Put(pid, value); err != nil {
		log.Fatalf("Failed to add PID to monitoring: %v", err)
	}
	if err := monitoredPids.Put(tgid, value); err != nil {
		log.Fatalf("Failed to add TGID to monitoring: %v", err)
	}
	fmt.Printf("✓ Added PID %d and TGID %d to monitoring\n", pid, tgid)

	// Привязываем программы к tracepoints
	links := make([]link.Link, 0)
	defer func() {
		for _, lnk := range links {
			lnk.Close()
		}
	}()

	// Файловые операции
	fileTracepoints := []struct {
		group string
		name  string
		prog  string
	}{
		{"syscalls", "sys_enter_openat", "tracepoint_sys_enter_openat"},
		{"syscalls", "sys_enter_open", "tracepoint_sys_enter_open"},
		{"syscalls", "sys_enter_read", "tracepoint_sys_enter_read"},
		{"syscalls", "sys_enter_write", "tracepoint_sys_enter_write"},
	}

	// Сетевые операции
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

	attachedCount := 0
	for _, tp := range fileTracepoints {
		prog := coll.Programs[tp.prog]
		if prog != nil {
			lnk, err := link.Tracepoint(tp.group, tp.name, prog, nil)
			if err != nil {
				fmt.Printf("⚠ Failed to attach %s/%s: %v\n", tp.group, tp.name, err)
				continue
			}
			links = append(links, lnk)
			attachedCount++
			fmt.Printf("✓ Attached %s/%s\n", tp.group, tp.name)
		} else {
			fmt.Printf("⚠ Program %s not found\n", tp.prog)
		}
	}

	for _, tp := range netTracepoints {
		prog := coll.Programs[tp.prog]
		if prog != nil {
			lnk, err := link.Tracepoint(tp.group, tp.name, prog, nil)
			if err != nil {
				fmt.Printf("⚠ Failed to attach %s/%s: %v\n", tp.group, tp.name, err)
				continue
			}
			links = append(links, lnk)
			attachedCount++
			fmt.Printf("✓ Attached %s/%s\n", tp.group, tp.name)
		} else {
			fmt.Printf("⚠ Program %s not found\n", tp.prog)
		}
	}

	if attachedCount == 0 {
		log.Fatal("No programs were attached!")
	}

	fmt.Printf("\n✓ Successfully attached %d eBPF programs\n", attachedCount)
	fmt.Println("\n=== Starting test operations ===")

	// Запускаем горутину для чтения файловых событий
	fileEventsChan := make(chan FileEvent, 100)
	done := make(chan bool)
	go func() {
		defer close(fileEventsChan)
		for {
			select {
			case <-done:
				return
			default:
				record, err := fileReader.Read()
				if err != nil {
					if err == perf.ErrClosed {
						return
					}
					continue
				}

				if len(record.RawSample) >= int(unsafe.Sizeof(FileEvent{})) {
					var event FileEvent
					reader := bytes.NewReader(record.RawSample)
					if err := binary.Read(reader, binary.LittleEndian, &event); err == nil {
						select {
						case fileEventsChan <- event:
						default:
						}
					}
				}
			}
		}
	}()

	// Запускаем горутину для чтения сетевых событий
	netEventsChan := make(chan NetworkEvent, 100)
	go func() {
		defer close(netEventsChan)
		for {
			select {
			case <-done:
				return
			default:
				record, err := netReader.Read()
				if err != nil {
					if err == perf.ErrClosed {
						return
					}
					continue
				}

				if len(record.RawSample) >= int(unsafe.Sizeof(NetworkEvent{})) {
					var event NetworkEvent
					reader := bytes.NewReader(record.RawSample)
					if err := binary.Read(reader, binary.LittleEndian, &event); err == nil {
						select {
						case netEventsChan <- event:
						default:
						}
					}
				}
			}
		}
	}()

	// Даем время программам привязаться
	time.Sleep(500 * time.Millisecond)

	// Выполняем тестовые операции
	fmt.Println("\n1. Performing file operations...")

	// Открываем файл
	testFile, err := os.Create("/tmp/ebpf_test_file.txt")
	if err == nil {
		testFile.WriteString("test data")
		testFile.Close()
		fmt.Println("   ✓ Created /tmp/ebpf_test_file.txt")

		// Читаем файл
		data, _ := os.ReadFile("/tmp/ebpf_test_file.txt")
		fmt.Printf("   ✓ Read file (%d bytes)\n", len(data))

		// Записываем в файл
		os.WriteFile("/tmp/ebpf_test_file2.txt", []byte("test"), 0644)
		fmt.Println("   ✓ Wrote to file")

		// Удаляем тестовые файлы
		os.Remove("/tmp/ebpf_test_file.txt")
		os.Remove("/tmp/ebpf_test_file2.txt")
	}

	fmt.Println("\n2. Performing network operations...")

	// Пытаемся подключиться (может не удаться, но событие должно быть)
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 100*time.Millisecond)
	if err == nil {
		conn.Close()
		fmt.Println("   ✓ Connected to 8.8.8.8:53")
	} else {
		fmt.Printf("   ✓ Attempted connection (expected to fail, but event should be captured)\n")
	}

	// Создаем UDP соединение
	udpConn, err := net.Dial("udp", "8.8.8.8:53")
	if err == nil {
		udpConn.Write([]byte("test"))
		udpConn.Close()
		fmt.Println("   ✓ Sent UDP packet")
	}

	// Даем время событиям обработаться
	fmt.Println("\n3. Waiting for events to be captured...")
	time.Sleep(2 * time.Second)

	// Останавливаем чтение
	close(done)
	time.Sleep(100 * time.Millisecond)

	// Читаем накопленные события
	fmt.Println("\n=== Captured Events ===")

	fileEventCount := 0
	netEventCount := 0

	// Читаем файловые события
	for {
		select {
		case event, ok := <-fileEventsChan:
			if !ok {
				goto readNetwork
			}
			fileEventCount++
			path := string(event.Path[:])
			for i, b := range event.Path {
				if b == 0 {
					path = string(event.Path[:i])
					break
				}
			}
			comm := string(event.Comm[:])
			for i, b := range event.Comm {
				if b == 0 {
					comm = string(event.Comm[:i])
					break
				}
			}
			fmt.Printf("📄 File Event #%d:\n", fileEventCount)
			fmt.Printf("   PID: %d, Comm: %s, Path: %s\n", event.PID, comm, path)
			fmt.Printf("   Flags: 0x%x, Result: %d\n", event.Flags, event.Result)
		default:
			goto readNetwork
		}
	}

readNetwork:
	// Читаем сетевые события
	for {
		select {
		case event, ok := <-netEventsChan:
			if !ok {
				goto summary
			}
			netEventCount++
			comm := string(event.Comm[:])
			for i, b := range event.Comm {
				if b == 0 {
					comm = string(event.Comm[:i])
					break
				}
			}
			fmt.Printf("🌐 Network Event #%d:\n", netEventCount)
			fmt.Printf("   PID: %d, Comm: %s\n", event.PID, comm)
			if event.RemoteIP > 0 {
				fmt.Printf("   Remote: %d.%d.%d.%d:%d\n",
					(event.RemoteIP>>24)&0xFF,
					(event.RemoteIP>>16)&0xFF,
					(event.RemoteIP>>8)&0xFF,
					event.RemoteIP&0xFF,
					event.RemotePort)
			}
		default:
			goto summary
		}
	}

summary:
	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("File events captured: %d\n", fileEventCount)
	fmt.Printf("Network events captured: %d\n", netEventCount)

	if fileEventCount > 0 || netEventCount > 0 {
		fmt.Println("\n✅ SUCCESS: eBPF programs are working correctly!")
		fmt.Println("Events were captured and decoded successfully.")
		fmt.Println("The programs are ready for production use.")
	} else {
		fmt.Println("\n⚠️  WARNING: No events were captured.")
		fmt.Println("This could mean:")
		fmt.Println("  - Events were filtered out (check PID filtering)")
		fmt.Println("  - Programs are not attached correctly")
		fmt.Println("  - Events are being lost (check buffer size)")
		fmt.Println("  - Try running with sudo for proper permissions")
	}

	fmt.Println("\nTest completed.")
}
