# Настройка eBPF мониторинга

## Быстрый старт

eBPF мониторинг автоматически инициализируется при запуске worker node. Если eBPF недоступен, система переключается на режим заглушек.

## Полная настройка для продакшена

### 1. Установка зависимостей

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)

# Проверка версии ядра (требуется >= 4.9)
uname -r
```

### 2. Компиляция eBPF программ

```bash
# Переходим в директорию проекта
cd /path/to/spark

# Компилируем eBPF программы
clang -target bpf -O2 -g \
  -c internal/monitor/ebpf/bpf/bpf_programs.c \
  -o internal/monitor/ebpf/bpf_programs.o \
  -I/usr/include \
  -I/usr/include/bpf \
  -I/usr/include/x86_64-linux-gnu \
  -D__TARGET_ARCH_x86
```

### 3. Проверка прав доступа

```bash
# Проверяем доступ к debugfs
ls -la /sys/kernel/debug/tracing

# Если недоступно, монтируем
sudo mount -t debugfs none /sys/kernel/debug
```

### 4. Настройка capabilities

Для работы без root требуются capabilities:

```bash
# Устанавливаем capabilities для бинарника
sudo setcap cap_bpf,cap_sys_admin,cap_sys_ptrace+ep ./bin/worker
```

### 5. Проверка работы

```bash
# Запускаем worker node
sudo ./bin/worker

# Или с capabilities
./bin/worker
```

## Отладка

### Проверка загрузки eBPF программ

```bash
# Смотрим загруженные программы
sudo bpftool prog list

# Смотрим maps
sudo bpftool map list
```

### Логирование

Установите уровень логирования на `debug`:

```bash
export LOG_LEVEL=debug
./bin/worker
```

### Проблемы и решения

**Ошибка: "permission denied"**
- Убедитесь, что запускаете с правами root или установлены capabilities
- Проверьте доступ к `/sys/kernel/debug`

**Ошибка: "failed to load eBPF spec"**
- Проверьте версию ядра (>= 4.9)
- Убедитесь, что eBPF включен в ядре: `grep BPF /boot/config-$(uname -r)`

**Ошибка: "clang not found"**
- Установите clang и llvm: `sudo apt-get install clang llvm`

**События не поступают**
- Проверьте, что контейнеры запущены
- Убедитесь, что PIDs добавлены в мониторинг
- Проверьте логи на наличие ошибок

## Альтернативный подход: встраивание программ

Для продакшена рекомендуется встраивать скомпилированные eBPF программы в бинарник:

```go
//go:embed bpf_programs.o
var bpfProgramsBytes []byte

func loadEBPFSpec() (*ebpf.CollectionSpec, error) {
    return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfProgramsBytes))
}
```

Это избавляет от необходимости компилировать программы во время выполнения.

## Производительность

eBPF мониторинг имеет минимальный overhead (<2.5%):
- События обрабатываются в ядре
- Передача в userspace через perf event arrays
- Асинхронная обработка событий

## Безопасность

- eBPF программы проверяются верификатором ядра
- Невозможно выполнить произвольный код
- Программы изолированы от остальной системы
- Требуются соответствующие права доступа
