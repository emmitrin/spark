package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	GRPC struct {
		Address string
		Port    int
	}

	Docker struct {
		Endpoint        string
		UseGVisor       bool
		GVisorRuntime   string
		DefaultCPULimit float64
		DefaultMemLimit int64
	}

	OpenSearch struct {
		Addresses  []string
		Username   string
		Password   string
		IndexName  string
		UseTLS     bool
		SkipVerify bool
	}

	Monitor struct {
		Enabled           bool
		CollectInterval   time.Duration
		FileOpsEnabled    bool
		NetworkOpsEnabled bool
		BPFObjectPath     string // путь к bpf_programs.o; пусто = авто-поиск
		EchoMode          bool   // писать события eBPF в лог вместо OpenSearch; отключает OpenSearch
		PidsFromCgroup    bool   // получать PID контейнера через cgroup (включая docker exec); иначе только главный процесс и дети
	}

	Log struct {
		Level  string
		Format string
	}
}

// Load читает конфиг из опционального YAML-файла и применяет переопределения из env.
// Если configPath пустой, используются только переменные окружения.
// Переменные окружения переопределяют значения из файла.
func Load(configPath string) (*Config, error) {
	var l configLoader
	return l.load(configPath)
}

type configLoader struct{}

type fileConfig struct {
	GRPC struct {
		Address string `yaml:"address"`
		Port    int    `yaml:"port"`
	} `yaml:"grpc"`
	Docker struct {
		Endpoint        string  `yaml:"endpoint"`
		UseGVisor       bool    `yaml:"use_gvisor"`
		GVisorRuntime   string  `yaml:"gvisor_runtime"`
		DefaultCPULimit float64 `yaml:"default_cpu_limit"`
		DefaultMemLimit int64   `yaml:"default_mem_limit"`
	} `yaml:"docker"`
	OpenSearch struct {
		Addresses  []string `yaml:"addresses"`
		Username   string   `yaml:"username"`
		Password   string   `yaml:"password"`
		IndexName  string   `yaml:"index_name"`
		UseTLS     bool     `yaml:"use_tls"`
		SkipVerify bool     `yaml:"skip_verify"`
	} `yaml:"opensearch"`
	Monitor struct {
		Enabled           bool   `yaml:"enabled"`
		CollectInterval   string `yaml:"collect_interval"`
		FileOpsEnabled    bool   `yaml:"file_ops_enabled"`
		NetworkOpsEnabled bool   `yaml:"network_ops_enabled"`
		BPFObjectPath     string `yaml:"bpf_object_path"`
		EchoMode          bool   `yaml:"echo_mode"`
		PidsFromCgroup    bool   `yaml:"pids_from_cgroup"`
	} `yaml:"monitor"`
	Log struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"log"`
}

func (l configLoader) load(configPath string) (*Config, error) {
	cfg := &Config{}

	if configPath != "" {
		if err := l.loadFromFile(configPath, cfg); err != nil {
			return nil, err
		}
	}

	l.setDefaults(cfg)
	l.applyEnvOverrides(cfg)

	return cfg, nil
}

func (l configLoader) loadFromFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	var f fileConfig
	if err := yaml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse config file: %w", err)
	}

	cfg.GRPC.Address = f.GRPC.Address
	cfg.GRPC.Port = f.GRPC.Port

	cfg.Docker.Endpoint = f.Docker.Endpoint
	cfg.Docker.UseGVisor = f.Docker.UseGVisor
	cfg.Docker.GVisorRuntime = f.Docker.GVisorRuntime
	cfg.Docker.DefaultCPULimit = f.Docker.DefaultCPULimit
	cfg.Docker.DefaultMemLimit = f.Docker.DefaultMemLimit

	cfg.OpenSearch.Addresses = f.OpenSearch.Addresses
	cfg.OpenSearch.Username = f.OpenSearch.Username
	cfg.OpenSearch.Password = f.OpenSearch.Password
	cfg.OpenSearch.IndexName = f.OpenSearch.IndexName
	cfg.OpenSearch.UseTLS = f.OpenSearch.UseTLS
	cfg.OpenSearch.SkipVerify = f.OpenSearch.SkipVerify

	cfg.Monitor.Enabled = f.Monitor.Enabled
	cfg.Monitor.FileOpsEnabled = f.Monitor.FileOpsEnabled
	cfg.Monitor.NetworkOpsEnabled = f.Monitor.NetworkOpsEnabled
	cfg.Monitor.BPFObjectPath = f.Monitor.BPFObjectPath
	cfg.Monitor.EchoMode = f.Monitor.EchoMode
	cfg.Monitor.PidsFromCgroup = f.Monitor.PidsFromCgroup

	if f.Monitor.CollectInterval != "" {
		if d, err := time.ParseDuration(f.Monitor.CollectInterval); err == nil {
			cfg.Monitor.CollectInterval = d
		} else {
			cfg.Monitor.CollectInterval = 5 * time.Second
		}
	} else {
		cfg.Monitor.CollectInterval = 5 * time.Second
	}

	cfg.Log.Level = f.Log.Level
	cfg.Log.Format = f.Log.Format

	return nil
}

func (l configLoader) setDefaults(cfg *Config) {
	if cfg.GRPC.Address == "" {
		cfg.GRPC.Address = "0.0.0.0"
	}

	if cfg.GRPC.Port == 0 {
		cfg.GRPC.Port = 50051
	}

	if cfg.Docker.Endpoint == "" {
		cfg.Docker.Endpoint = "unix:///var/run/docker.sock"
	}

	if cfg.Docker.GVisorRuntime == "" {
		cfg.Docker.GVisorRuntime = "runsc"
	}

	if cfg.Docker.DefaultCPULimit == 0 {
		cfg.Docker.DefaultCPULimit = 0.5
	}

	if cfg.Docker.DefaultMemLimit == 0 {
		cfg.Docker.DefaultMemLimit = 512 * 1024 * 1024
	}

	if len(cfg.OpenSearch.Addresses) == 0 {
		cfg.OpenSearch.Addresses = []string{"http://localhost:9200"}
	}

	if cfg.OpenSearch.Username == "" {
		cfg.OpenSearch.Username = "admin"
	}

	if cfg.OpenSearch.Password == "" {
		cfg.OpenSearch.Password = "admin"
	}

	if cfg.OpenSearch.IndexName == "" {
		cfg.OpenSearch.IndexName = "spark-ioc"
	}

	if cfg.Monitor.CollectInterval == 0 {
		cfg.Monitor.CollectInterval = 5 * time.Second
	}

	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}

	if cfg.Log.Format == "" {
		cfg.Log.Format = "json"
	}
}

func (l configLoader) applyEnvOverrides(cfg *Config) {
	cfg.GRPC.Address = l.getEnv("GRPC_ADDRESS", cfg.GRPC.Address)
	cfg.GRPC.Port = l.getEnvInt("GRPC_PORT", cfg.GRPC.Port)

	cfg.Docker.Endpoint = l.getEnv("DOCKER_ENDPOINT", cfg.Docker.Endpoint)
	cfg.Docker.UseGVisor = l.getEnvBool("DOCKER_USE_GVISOR", cfg.Docker.UseGVisor)
	cfg.Docker.GVisorRuntime = l.getEnv("DOCKER_GVISOR_RUNTIME", cfg.Docker.GVisorRuntime)
	cfg.Docker.DefaultCPULimit = l.getEnvFloat("DOCKER_DEFAULT_CPU_LIMIT", cfg.Docker.DefaultCPULimit)
	cfg.Docker.DefaultMemLimit = l.getEnvInt64("DOCKER_DEFAULT_MEM_LIMIT", cfg.Docker.DefaultMemLimit)

	cfg.OpenSearch.Addresses = l.getEnvSlice("OPENSEARCH_ADDRESSES", cfg.OpenSearch.Addresses)
	cfg.OpenSearch.Username = l.getEnv("OPENSEARCH_USERNAME", cfg.OpenSearch.Username)
	cfg.OpenSearch.Password = l.getEnv("OPENSEARCH_PASSWORD", cfg.OpenSearch.Password)
	cfg.OpenSearch.IndexName = l.getEnv("OPENSEARCH_INDEX", cfg.OpenSearch.IndexName)
	cfg.OpenSearch.UseTLS = l.getEnvBool("OPENSEARCH_USE_TLS", cfg.OpenSearch.UseTLS)
	cfg.OpenSearch.SkipVerify = l.getEnvBool("OPENSEARCH_SKIP_VERIFY", cfg.OpenSearch.SkipVerify)

	cfg.Monitor.Enabled = l.getEnvBool("MONITOR_ENABLED", cfg.Monitor.Enabled)
	cfg.Monitor.CollectInterval = l.getEnvDuration("MONITOR_COLLECT_INTERVAL", cfg.Monitor.CollectInterval)
	cfg.Monitor.FileOpsEnabled = l.getEnvBool("MONITOR_FILE_OPS", cfg.Monitor.FileOpsEnabled)
	cfg.Monitor.NetworkOpsEnabled = l.getEnvBool("MONITOR_NETWORK_OPS", cfg.Monitor.NetworkOpsEnabled)
	cfg.Monitor.BPFObjectPath = l.getEnv("MONITOR_BPF_OBJECT_PATH", cfg.Monitor.BPFObjectPath)
	cfg.Monitor.EchoMode = l.getEnvBool("MONITOR_ECHO_MODE", cfg.Monitor.EchoMode)
	cfg.Monitor.PidsFromCgroup = l.getEnvBool("MONITOR_PIDS_FROM_CGROUP", cfg.Monitor.PidsFromCgroup)

	cfg.Log.Level = l.getEnv("LOG_LEVEL", cfg.Log.Level)
	cfg.Log.Format = l.getEnv("LOG_FORMAT", cfg.Log.Format)
}

func (configLoader) getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return defaultValue
}

func (configLoader) getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}

	return defaultValue
}

func (configLoader) getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intVal
		}
	}

	return defaultValue
}

func (configLoader) getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatVal, err := strconv.ParseFloat(value, 64); err == nil {
			return floatVal
		}
	}

	return defaultValue
}

func (configLoader) getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}

	return defaultValue
}

func (configLoader) getEnvSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		value = strings.Trim(value, "[]\"'")
		if value != "" {
			parts := strings.Split(value, ",")
			result := make([]string, 0, len(parts))

			for _, part := range parts {
				part = strings.TrimSpace(part)
				part = strings.Trim(part, "\"'")

				if part != "" {
					result = append(result, part)
				}
			}

			if len(result) > 0 {
				return result
			}
		}
	}

	return defaultValue
}

func (configLoader) getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}

	return defaultValue
}
