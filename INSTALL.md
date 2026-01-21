# Установка и настройка Spark Worker Node

## Требования

- Go 1.21 или выше
- Docker с поддержкой gVisor (runsc)
- Linux с поддержкой eBPF (для мониторинга)
- OpenSearch кластер (или локальный экземпляр)

## Установка gVisor

gVisor (runsc) необходим для дополнительной изоляции контейнеров. Без него контейнеры будут запускаться с обычной изоляцией Docker.

### Ubuntu/Debian

```bash
# Добавляем репозиторий
sudo apt-get update && sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg

# Устанавливаем gVisor
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
sudo apt-get update && sudo apt-get install -y runsc

# Настраиваем Docker для использования gVisor
sudo runsc install
sudo systemctl restart docker
```

### Проверка установки

```bash
# Проверяем, что runsc доступен
runsc --version

# Проверяем, что Docker видит runtime
docker info | grep -i runtime
```

## Сборка проекта

```bash
# Клонируем репозиторий
git clone <repository-url>
cd spark

# Устанавливаем зависимости
go mod download

# Генерируем protobuf файлы
make proto

# Собираем бинарник
make build
```

## Настройка

Настройка выполняется через переменные окружения:

```bash
export GRPC_ADDRESS=0.0.0.0
export GRPC_PORT=50051
export DOCKER_ENDPOINT=unix:///var/run/docker.sock
export DOCKER_USE_GVISOR=true
export DOCKER_GVISOR_RUNTIME=runsc
export OPENSEARCH_ADDRESSES='["http://localhost:9200"]'
export OPENSEARCH_USERNAME=admin
export OPENSEARCH_PASSWORD=admin
export OPENSEARCH_INDEX=spark-ioc
export MONITOR_ENABLED=true
export MONITOR_FILE_OPS=true
export MONITOR_NETWORK_OPS=true
export LOG_LEVEL=info
```

## Запуск с Docker Compose

```bash
# Запускаем OpenSearch и Worker Node
docker-compose up -d

# Проверяем логи
docker-compose logs -f worker
```

## Запуск локально

```bash
# Убедитесь, что OpenSearch запущен
# Запускаем worker node
./bin/worker
```

## Проверка работы

```bash
# Проверяем, что gRPC сервер отвечает
grpcurl -plaintext localhost:50051 list

# Проверяем состояние
grpcurl -plaintext localhost:50051 worker.WorkerService/GetCurrentState
```

## Примечания

- Для работы eBPF мониторинга требуется доступ к `/sys/kernel/debug` и `/sys/fs/bpf`
- В Docker контейнере требуется `privileged: true` и соответствующие capabilities
- gVisor может замедлить выполнение контейнеров, но обеспечивает лучшую изоляцию
