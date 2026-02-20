package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	SocketPath   string
	BaseURL      string
	APIKey       string
	AppID        int
	InstallDir   string
	OS           string
	MaxDownloads int
	PollInterval time.Duration
	SkipInstall          bool
	InstallRetryForever  bool
	InstallRetryInterval time.Duration
	SupervisorEnabled     bool
	SupervisorAutoConfig bool
	SupervisorSocket      string
	SupervisorProgram     string
	SupervisorConfPath    string
	SupervisorMainConfPath string
	SupervisorUser        string
	SupervisorPassword    string
	BannerPath      string
	BannerWait      time.Duration
	StartCmd     string
	StartArgs    []string
	StartCwd     string
	StartConfig  StartConfig
	StartIniPath string
	ExtraArgs    []string
	StartUser          string
	ChownInstallDir    bool
	ChmodInstallDir    bool
	VersionCheckEnabled  bool
	VersionCheckURL      string
	VersionCheckTimeout  time.Duration
	CustomID             int
	VersionName          string
}

type Context struct {
	Cfg     Config
	Client  *http.Client
	BaseURL *url.URL
	JobID   string
}

type StartConfig struct {
	AppID int
	OS    string
	Args  StartArgsConfig
	SkipInstall          bool
	InstallRetryForever  bool
	InstallRetryInterval time.Duration
	SupervisorEnabled     bool
	SupervisorAutoConfig bool
	SupervisorSocket      string
	SupervisorProgram     string
	SupervisorConfPath    string
	SupervisorMainConfPath string
	SupervisorUser        string
	SupervisorPassword    string
	BannerPath      string
	BannerWait      time.Duration
	StartUser            string
	ChownInstallDir      bool
	ChmodInstallDir      bool
	VersionCheckEnabled  bool
	VersionCheckURL      string
	VersionCheckTimeout  time.Duration
	CustomID             int
	VersionName          string
}

type StartArgsConfig struct {
	Port          StartIntArg
	QueryPort     StartIntArg
	BeaconPort    StartIntArg
	Log           StartBoolArg
	Unattended    StartBoolArg
	NoCrashDialog StartBoolArg
	Multihome     StartStringArg
}

type StartBoolArg struct {
	Enabled bool
}

type StartIntArg struct {
	Enabled bool
	Value   int
}

type StartStringArg struct {
	Enabled bool
	Value   string
}

func LoadConfig(extraArgs []string) (Config, error) {
	cfg := Config{}
	cfg.SocketPath = firstNonEmpty(
		os.Getenv("STEAMSERVICE_UNIX_SOCKET_PATH"),
		os.Getenv("STEAMDDS_UNIX_SOCKET_PATH"),
		os.Getenv("STEAM_SERVICE_SOCKET"),
	)
	if cfg.SocketPath == "" {
		cfg.SocketPath = "/home/container/.unix/steamdds.sock"
	}

	cfg.BaseURL = strings.TrimSpace(firstNonEmpty(
		os.Getenv("STEAMSERVICE_BASE_URL"),
		os.Getenv("STEAMDDS_BASE_URL"),
		"http://localhost",
	))

	cfg.APIKey = strings.TrimSpace(firstNonEmpty(
		os.Getenv("STEAMDDS_API_KEY"),
		os.Getenv("STEAMSERVICE_API_KEY"),
	))

	cfg.InstallDir = strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_INSTALL_DIR"),
		os.Getenv("STEAMSERVICE_INSTALL_DIR"),
	))
	if cfg.InstallDir == "" {
		cfg.InstallDir = "/home/container/games/satisfactory"
	}

	startDefaults := defaultStartConfig(1690800, "linux")
	startIniPath := defaultStartIniPath()
	startCfg, err := loadOrInitStartConfig(startIniPath, startDefaults)
	if err != nil {
		return Config{}, err
	}

	if v, ok := readIntEnvOK("SATISFACTORY_APP_ID"); ok {
		startCfg.AppID = v
	}
	if v := strings.TrimSpace(firstNonEmpty(os.Getenv("SATISFACTORY_OS"), os.Getenv("STEAMSERVICE_OS"))); v != "" {
		startCfg.OS = v
	}
	if startCfg.OS == "" {
		startCfg.OS = "linux"
	}
	cfg.AppID = startCfg.AppID
	cfg.OS = startCfg.OS
	cfg.StartConfig = startCfg
	cfg.StartIniPath = startIniPath
	cfg.ExtraArgs = append([]string{}, extraArgs...)

	cfg.MaxDownloads = readIntEnv("STEAMSERVICE_MAX_DOWNLOADS", 0)

	intervalRaw := strings.TrimSpace(os.Getenv("STEAMSERVICE_POLL_INTERVAL"))
	if intervalRaw == "" {
		cfg.PollInterval = 2 * time.Second
	} else {
		d, err := time.ParseDuration(intervalRaw)
		if err != nil || d <= 0 {
			return Config{}, errors.New("invalid STEAMSERVICE_POLL_INTERVAL")
		}
		cfg.PollInterval = d
	}

	retryRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("STEAMSERVICE_INSTALL_RETRY_FOREVER"),
		os.Getenv("STEAMSERVICE_INSTALL_RETRY"),
	))
	if retryRaw == "" {
		cfg.InstallRetryForever = startCfg.InstallRetryForever
	} else {
		cfg.InstallRetryForever = parseBool(retryRaw)
	}

	retryIntervalRaw := strings.TrimSpace(os.Getenv("STEAMSERVICE_INSTALL_RETRY_INTERVAL"))
	if retryIntervalRaw == "" {
		if startCfg.InstallRetryInterval > 0 {
			cfg.InstallRetryInterval = startCfg.InstallRetryInterval
		} else {
			cfg.InstallRetryInterval = 10 * time.Second
		}
	} else {
		d, err := time.ParseDuration(retryIntervalRaw)
		if err != nil || d <= 0 {
			return Config{}, errors.New("invalid STEAMSERVICE_INSTALL_RETRY_INTERVAL")
		}
		cfg.InstallRetryInterval = d
	}

	skipInstallRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_SKIP_INSTALL"),
		os.Getenv("STEAMSERVICE_SKIP_INSTALL"),
	))
	if skipInstallRaw == "" {
		cfg.SkipInstall = startCfg.SkipInstall
	} else {
		cfg.SkipInstall = parseBool(skipInstallRaw)
	}

	supervisorEnabledRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_SUPERVISOR_ENABLED"),
		os.Getenv("STEAMSERVICE_SUPERVISOR_ENABLED"),
	))
	if supervisorEnabledRaw == "" {
		cfg.SupervisorEnabled = startCfg.SupervisorEnabled
	} else {
		cfg.SupervisorEnabled = parseBool(supervisorEnabledRaw)
	}

	supervisorAutoConfigRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_SUPERVISOR_AUTO_CONFIG"),
		os.Getenv("STEAMSERVICE_SUPERVISOR_AUTO_CONFIG"),
	))
	if supervisorAutoConfigRaw == "" {
		cfg.SupervisorAutoConfig = startCfg.SupervisorAutoConfig
	} else {
		cfg.SupervisorAutoConfig = parseBool(supervisorAutoConfigRaw)
	}

	supervisorSocketRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_SUPERVISOR_SOCKET"),
		os.Getenv("STEAMSERVICE_SUPERVISOR_SOCKET"),
	))
	if supervisorSocketRaw == "" {
		cfg.SupervisorSocket = startCfg.SupervisorSocket
	} else {
		cfg.SupervisorSocket = supervisorSocketRaw
	}

	supervisorProgramRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_SUPERVISOR_PROGRAM"),
		os.Getenv("STEAMSERVICE_SUPERVISOR_PROGRAM"),
	))
	if supervisorProgramRaw == "" {
		cfg.SupervisorProgram = startCfg.SupervisorProgram
	} else {
		cfg.SupervisorProgram = supervisorProgramRaw
	}

	supervisorConfPathRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_SUPERVISOR_CONF_PATH"),
		os.Getenv("STEAMSERVICE_SUPERVISOR_CONF_PATH"),
	))
	if supervisorConfPathRaw == "" {
		cfg.SupervisorConfPath = startCfg.SupervisorConfPath
	} else {
		cfg.SupervisorConfPath = supervisorConfPathRaw
	}

	supervisorMainConfRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_SUPERVISOR_MAIN_CONF"),
		os.Getenv("STEAMSERVICE_SUPERVISOR_MAIN_CONF"),
	))
	if supervisorMainConfRaw == "" {
		cfg.SupervisorMainConfPath = startCfg.SupervisorMainConfPath
	} else {
		cfg.SupervisorMainConfPath = supervisorMainConfRaw
	}

	supervisorUserRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_SUPERVISOR_USER"),
		os.Getenv("STEAMSERVICE_SUPERVISOR_USER"),
	))
	if supervisorUserRaw == "" {
		cfg.SupervisorUser = startCfg.SupervisorUser
	} else {
		cfg.SupervisorUser = supervisorUserRaw
	}

	supervisorPasswordRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_SUPERVISOR_PASSWORD"),
		os.Getenv("STEAMSERVICE_SUPERVISOR_PASSWORD"),
	))
	if supervisorPasswordRaw == "" {
		cfg.SupervisorPassword = startCfg.SupervisorPassword
	} else {
		cfg.SupervisorPassword = supervisorPasswordRaw
	}

	bannerPathRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_BANNER_PATH"),
		os.Getenv("STEAMSERVICE_BANNER_PATH"),
	))
	if bannerPathRaw == "" {
		cfg.BannerPath = startCfg.BannerPath
	} else {
		cfg.BannerPath = bannerPathRaw
	}

	bannerWaitRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_BANNER_WAIT"),
		os.Getenv("STEAMSERVICE_BANNER_WAIT"),
	))
	if bannerWaitRaw == "" {
		cfg.BannerWait = startCfg.BannerWait
	} else if d, ok := parseDuration(bannerWaitRaw); ok {
		cfg.BannerWait = d
	} else {
		return Config{}, errors.New("invalid SATISFACTORY_BANNER_WAIT")
	}

	applySupervisorDefaults(&cfg)

	cfg.StartCmd = strings.TrimSpace(os.Getenv("SATISFACTORY_START_CMD"))
	cfg.StartArgs = strings.Fields(strings.TrimSpace(os.Getenv("SATISFACTORY_START_ARGS")))
	cfg.StartCwd = strings.TrimSpace(os.Getenv("SATISFACTORY_START_CWD"))
	if cfg.StartCwd == "" {
		cfg.StartCwd = cfg.InstallDir
	}

	startUserRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_START_USER"),
		os.Getenv("SATISFACTORY_RUN_AS_USER"),
		os.Getenv("STEAMSERVICE_START_USER"),
	))
	if startUserRaw == "" {
		cfg.StartUser = startCfg.StartUser
	} else {
		cfg.StartUser = startUserRaw
	}

	chownRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_CHOWN_INSTALL_DIR"),
		os.Getenv("STEAMSERVICE_CHOWN_INSTALL_DIR"),
	))
	if chownRaw == "" {
		cfg.ChownInstallDir = startCfg.ChownInstallDir
	} else {
		cfg.ChownInstallDir = parseBool(chownRaw)
	}

	chmodRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_CHMOD_INSTALL_DIR"),
		os.Getenv("STEAMSERVICE_CHMOD_INSTALL_DIR"),
	))
	if chmodRaw == "" {
		cfg.ChmodInstallDir = startCfg.ChmodInstallDir
	} else {
		cfg.ChmodInstallDir = parseBool(chmodRaw)
	}

	versionCheckEnabledRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_VERSION_CHECK_ENABLED"),
		os.Getenv("STEAMSERVICE_VERSION_CHECK_ENABLED"),
	))
	if versionCheckEnabledRaw == "" {
		cfg.VersionCheckEnabled = startCfg.VersionCheckEnabled
	} else {
		cfg.VersionCheckEnabled = parseBool(versionCheckEnabledRaw)
	}

	versionCheckURLRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_VERSION_CHECK_URL"),
		os.Getenv("STEAMSERVICE_VERSION_CHECK_URL"),
	))
	if versionCheckURLRaw == "" {
		cfg.VersionCheckURL = startCfg.VersionCheckURL
	} else {
		cfg.VersionCheckURL = versionCheckURLRaw
	}

	versionCheckTimeoutRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_VERSION_CHECK_TIMEOUT"),
		os.Getenv("STEAMSERVICE_VERSION_CHECK_TIMEOUT"),
	))
	if versionCheckTimeoutRaw == "" {
		cfg.VersionCheckTimeout = startCfg.VersionCheckTimeout
	} else if d, ok := parseDuration(versionCheckTimeoutRaw); ok {
		cfg.VersionCheckTimeout = d
	} else {
		return Config{}, errors.New("invalid SATISFACTORY_VERSION_CHECK_TIMEOUT")
	}

	customIDRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_CUSTOM_ID"),
		os.Getenv("STEAMSERVICE_CUSTOM_ID"),
	))
	if customIDRaw == "" {
		cfg.CustomID = startCfg.CustomID
	} else if v, err := strconv.Atoi(customIDRaw); err == nil && v > 0 {
		cfg.CustomID = v
	} else {
		return Config{}, errors.New("invalid SATISFACTORY_CUSTOM_ID")
	}

	versionNameRaw := strings.TrimSpace(firstNonEmpty(
		os.Getenv("SATISFACTORY_VERSION_NAME"),
		os.Getenv("STEAMSERVICE_VERSION_NAME"),
	))
	if versionNameRaw == "" {
		cfg.VersionName = startCfg.VersionName
	} else {
		cfg.VersionName = versionNameRaw
	}

	return cfg, nil
}

func NewContext(cfg Config) (*Context, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, errors.New("invalid base url")
	}

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if cfg.SocketPath != "" && cfg.SocketPath != "none" {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", cfg.SocketPath)
		}
	}

	return &Context{
		Cfg: cfg,
		Client: &http.Client{
			Timeout:   0,
			Transport: tr,
		},
		BaseURL: base,
	}, nil
}

func StepCheck(ctx *Context) error {
	if ctx == nil {
		return errors.New("context is nil")
	}

	if ctx.Cfg.SocketPath != "" && ctx.Cfg.SocketPath != "none" {
		conn, err := net.DialTimeout("unix", ctx.Cfg.SocketPath, 5*time.Second)
		if err != nil {
			return fmt.Errorf("steamservice socket connect failed: %w", err)
		}
		_ = conn.Close()
	}

	var out map[string]any
	reqCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := ctx.doJSON(reqCtx, http.MethodGet, "/health", nil, &out); err != nil {
		return fmt.Errorf("steamservice health check failed: %w", err)
	}
	fmt.Println("steamservice health ok")
	return nil
}

func (c *Context) doJSON(ctx context.Context, method, path string, body any, out any) error {
	if c == nil || c.Client == nil || c.BaseURL == nil {
		return errors.New("client not ready")
	}
	method = strings.TrimSpace(method)
	if method == "" {
		method = http.MethodGet
	}
	path = strings.TrimSpace(path)
	if path == "" || !strings.HasPrefix(path, "/") {
		return errors.New("invalid path")
	}

	u := *c.BaseURL
	u.Path = path
	u.RawQuery = ""

	var rd *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Cfg.APIKey != "" {
		req.Header.Set("X-Api-Key", c.Cfg.APIKey)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	b, err := ioReadAllLimit(resp.Body, 32*1024*1024)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = resp.Status
		}
		return errors.New(msg)
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return err
	}
	return nil
}

func ioReadAllLimit(r io.Reader, limit int64) ([]byte, error) {
	lr := io.LimitReader(r, limit)
	return io.ReadAll(lr)
}

func applySupervisorDefaults(cfg *Config) {
	if cfg == nil || !cfg.SupervisorEnabled {
		return
	}
	for _, path := range candidateSupervisorConfPaths(*cfg) {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		info := parseSupervisorMainConf(string(data))
		if cfg.SupervisorAutoConfig {
			if info.socket != "" {
				cfg.SupervisorSocket = info.socket
			}
			if info.user != "" {
				cfg.SupervisorUser = info.user
			}
			if info.pass != "" {
				cfg.SupervisorPassword = info.pass
			}
			if strings.TrimSpace(cfg.SupervisorConfPath) == "" && info.includeGlob != "" {
				cfg.SupervisorConfPath = inferSupervisorConfPath(info.includeGlob, cfg.SupervisorProgram)
			}
			return
		}
		needSocket := strings.TrimSpace(cfg.SupervisorSocket) == ""
		needUser := strings.TrimSpace(cfg.SupervisorUser) == ""
		needPass := strings.TrimSpace(cfg.SupervisorPassword) == ""
		if !needSocket && !needUser && !needPass {
			return
		}
		if needSocket && info.socket != "" {
			cfg.SupervisorSocket = info.socket
		}
		if needUser && info.user != "" {
			cfg.SupervisorUser = info.user
		}
		if needPass && info.pass != "" {
			cfg.SupervisorPassword = info.pass
		}
		return
	}
}

func inferSupervisorConfPath(includeGlob, program string) string {
	includeGlob = strings.TrimSpace(includeGlob)
	if includeGlob == "" {
		return ""
	}
	program = strings.TrimSpace(program)
	if program == "" {
		program = "satisfactory"
	}
	if strings.Contains(includeGlob, "*") {
		dir := filepath.Dir(includeGlob)
		return filepath.Join(dir, program+".ini")
	}
	return includeGlob
}

func candidateSupervisorConfPaths(cfg Config) []string {
	out := make([]string, 0, 4)
	addPath := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		for _, v := range out {
			if v == p {
				return
			}
		}
		out = append(out, p)
	}
	addPath(cfg.SupervisorMainConfPath)
	addPath("/etc/supervisor/supervisord.conf")
	addPath("/etc/supervisord.conf")
	addPath("/home/container/supervisord.conf")
	return out
}

type supervisorMainConfInfo struct {
	socket      string
	user        string
	pass        string
	includeGlob string
}

func parseSupervisorMainConf(text string) supervisorMainConfInfo {
	info := supervisorMainConfInfo{}
	section := ""
	lines := strings.Split(text, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && len(line) > 2 {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		switch section {
		case "unix_http_server":
			switch key {
			case "file":
				info.socket = val
			case "username":
				info.user = val
			case "password":
				info.pass = val
			}
		case "include":
			if key == "files" {
				info.includeGlob = val
			}
		}
	}
	return info
}

func readIntEnv(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

func readIntEnvOK(key string) (int, bool) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, false
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return v, true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		s := strings.TrimSpace(v)
		if s != "" {
			return s
		}
	}
	return ""
}

func defaultStartIniPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "start.ini"
	}
	return filepath.Join(home, "start.ini")
}

func defaultStartConfig(appID int, osName string) StartConfig {
	return StartConfig{
		AppID: appID,
		OS:    osName,
		Args: StartArgsConfig{
			Port:          StartIntArg{Enabled: false, Value: 7777},
			QueryPort:     StartIntArg{Enabled: false, Value: 15777},
			BeaconPort:    StartIntArg{Enabled: false, Value: 15000},
			Log:           StartBoolArg{Enabled: true},
			Unattended:    StartBoolArg{Enabled: true},
			NoCrashDialog: StartBoolArg{Enabled: true},
			Multihome:     StartStringArg{Enabled: false, Value: ""},
		},
		SkipInstall:          false,
		InstallRetryForever:  true,
		InstallRetryInterval: 10 * time.Second,
		SupervisorEnabled:    false,
		SupervisorAutoConfig: true,
		SupervisorSocket:     "/home/container/.unix/supervisor.sock",
		SupervisorProgram:    "satisfactory",
		SupervisorConfPath:   "/home/container/conf.d/supervisor/satisfactory.ini",
		SupervisorMainConfPath: "/etc/supervisor/supervisord.conf",
		BannerPath:           "banner.txt",
		BannerWait:           5 * time.Second,
		StartUser:            "container",
		ChownInstallDir:      true,
		ChmodInstallDir:      true,
		VersionCheckEnabled:  true,
		VersionCheckURL:      "https://version.qestudio.org/images/game_info/custom/new",
		VersionCheckTimeout:  10 * time.Second,
		CustomID:             277,
		VersionName:          "1.0.0",
	}
}

func loadOrInitStartConfig(path string, def StartConfig) (StartConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := writeStartConfig(path, def); err != nil {
				return StartConfig{}, err
			}
			return def, nil
		}
		return StartConfig{}, err
	}
	cfg := def
	text := string(data)
	if err := parseStartConfig(text, &cfg); err != nil {
		return StartConfig{}, err
	}
	if startConfigNeedsMigration(text) {
		if err := writeStartConfig(path, cfg); err != nil {
			return StartConfig{}, err
		}
	}
	return cfg, nil
}

func startConfigNeedsMigration(text string) bool {
	raw := strings.ToLower(text)
	requiredSections := []string{
		"[install]",
		"[supervisor]",
		"[banner]",
		"[start]",
		"[version_check]",
	}
	for _, section := range requiredSections {
		if !strings.Contains(raw, section) {
			return true
		}
	}
	return false
}

func parseStartConfig(text string, cfg *StartConfig) error {
	if cfg == nil {
		return errors.New("start config is nil")
	}
	section := ""
	lines := strings.Split(text, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			section = ""
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && len(line) > 2 {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if section != "" {
			key = section + "." + key
		}
		applyStartConfigKV(cfg, strings.ToLower(key), val)
	}
	return nil
}

func applyStartConfigKV(cfg *StartConfig, key, val string) {
	switch key {
	case "appid", "app_id":
		if v, err := strconv.Atoi(val); err == nil && v > 0 {
			cfg.AppID = v
		}
	case "os":
		if val != "" {
			cfg.OS = val
		}
	case "port.enabled":
		cfg.Args.Port.Enabled = parseBool(val)
	case "port.value":
		if v, err := strconv.Atoi(val); err == nil && v > 0 {
			cfg.Args.Port.Value = v
		}
	case "queryport.enabled", "query_port.enabled":
		cfg.Args.QueryPort.Enabled = parseBool(val)
	case "queryport.value", "query_port.value":
		if v, err := strconv.Atoi(val); err == nil && v > 0 {
			cfg.Args.QueryPort.Value = v
		}
	case "beaconport.enabled", "beacon_port.enabled":
		cfg.Args.BeaconPort.Enabled = parseBool(val)
	case "beaconport.value", "beacon_port.value":
		if v, err := strconv.Atoi(val); err == nil && v > 0 {
			cfg.Args.BeaconPort.Value = v
		}
	case "log.enabled":
		cfg.Args.Log.Enabled = parseBool(val)
	case "unattended.enabled":
		cfg.Args.Unattended.Enabled = parseBool(val)
	case "nocrashdialog.enabled":
		cfg.Args.NoCrashDialog.Enabled = parseBool(val)
	case "multihome.enabled":
		cfg.Args.Multihome.Enabled = parseBool(val)
	case "multihome.value":
		cfg.Args.Multihome.Value = val
	case "skip_install", "install.skip":
		cfg.SkipInstall = parseBool(val)
	case "install_retry_forever", "install.retry_forever":
		cfg.InstallRetryForever = parseBool(val)
	case "install_retry_interval", "install.retry_interval":
		if d, ok := parseDuration(val); ok {
			cfg.InstallRetryInterval = d
		}
	case "supervisor_enabled", "supervisor.enabled":
		cfg.SupervisorEnabled = parseBool(val)
	case "supervisor_auto_config", "supervisor.auto_config":
		cfg.SupervisorAutoConfig = parseBool(val)
	case "supervisor_socket", "supervisor.socket":
		cfg.SupervisorSocket = val
	case "supervisor_program", "supervisor.program":
		cfg.SupervisorProgram = val
	case "supervisor_conf_path", "supervisor.conf_path":
		cfg.SupervisorConfPath = val
	case "supervisor_main_conf_path", "supervisor.main_conf_path":
		cfg.SupervisorMainConfPath = val
	case "supervisor_user", "supervisor.user":
		cfg.SupervisorUser = val
	case "supervisor_password", "supervisor.password":
		cfg.SupervisorPassword = val
	case "banner_path", "banner.path":
		cfg.BannerPath = val
	case "banner_wait", "banner.wait":
		if d, ok := parseDuration(val); ok {
			cfg.BannerWait = d
		}
	case "start_user", "start.user":
		cfg.StartUser = val
	case "chown_install_dir", "start.chown_install_dir":
		cfg.ChownInstallDir = parseBool(val)
	case "chmod_install_dir", "start.chmod_install_dir":
		cfg.ChmodInstallDir = parseBool(val)
	case "version_check_enabled", "version_check.enabled":
		cfg.VersionCheckEnabled = parseBool(val)
	case "version_check_url", "version_check.url":
		cfg.VersionCheckURL = val
	case "version_check_timeout", "version_check.timeout":
		if d, ok := parseDuration(val); ok {
			cfg.VersionCheckTimeout = d
		}
	case "custom_id", "version_check.custom_id":
		if v, err := strconv.Atoi(val); err == nil && v > 0 {
			cfg.CustomID = v
		}
	case "version_name", "version_check.version_name":
		cfg.VersionName = val
	}
}

func parseBool(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func parseDuration(val string) (time.Duration, bool) {
	d, err := time.ParseDuration(strings.TrimSpace(val))
	if err != nil || d <= 0 {
		return 0, false
	}
	return d, true
}
