package cmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func StepStart(ctx *Context) error {
	if ctx == nil {
		return errors.New("context is nil")
	}

	internalArgs := buildInternalArgs(ctx.Cfg)
	args := mergeArgs(internalArgs, ctx.Cfg.ExtraArgs)
	cmdPath, args, err := resolveStartCommand(ctx.Cfg, args)
	if err != nil {
		return err
	}

	if ctx.Cfg.SupervisorEnabled {
		if err := applyStartUserAndPerms(ctx, &exec.Cmd{}); err != nil {
			return err
		}
		if err := ensureSupervisorConfig(ctx, cmdPath, args); err != nil {
			return err
		}
		if err := supervisorEnsureGroup(ctx); err != nil {
			return err
		}
		fmt.Println("starting server via supervisor:", ctx.Cfg.SupervisorProgram)
		if err := supervisorStart(ctx); err != nil {
			return err
		}
		stopCh := make(chan struct{})
		go tailSupervisorLogs(ctx, stopCh)
		err := waitForSupervisorStop(ctx)
		close(stopCh)
		return err
	}

	cmd := exec.Command(cmdPath, args...)
	cmd.Dir = ctx.Cfg.StartCwd
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := applyStartUserAndPerms(ctx, cmd); err != nil {
		return err
	}

	ensureProcessGroup(cmd)

	fmt.Println("starting server:", cmdPath, strings.Join(args, " "))
	if err := cmd.Start(); err != nil {
		return err
	}

	stopCh := make(chan struct{})
	go listenForStop(cmd, stopCh)
	err = cmd.Wait()
	close(stopCh)
	return err
}

func listenForStop(cmd *exec.Cmd, stopCh <-chan struct{}) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		if !scanner.Scan() {
			return
		}
		line := strings.TrimSpace(scanner.Text())
		if strings.EqualFold(line, "stop") {
			sendInterrupt(cmd.Process)
			return
		}
	}
}

func waitForSupervisorStop(ctx *Context) error {
	if ctx == nil {
		return errors.New("context is nil")
	}
	done := make(chan struct{})
	go listenForSupervisorStop(ctx, done)
	<-done
	return nil
}

func listenForSupervisorStop(ctx *Context, done chan struct{}) {
	if ctx == nil {
		close(done)
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.EqualFold(line, "stop") {
			_ = supervisorStop(ctx)
			close(done)
			return
		}
	}
	close(done)
}

func ensureProcessGroup(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

func sendInterrupt(proc *os.Process) {
	if proc == nil {
		return
	}
	if err := syscall.Kill(-proc.Pid, syscall.SIGINT); err == nil {
		return
	}
	_ = proc.Signal(os.Interrupt)
}

func ensureSupervisorConfig(ctx *Context, cmdPath string, args []string) error {
	if ctx == nil {
		return errors.New("context is nil")
	}
	if strings.TrimSpace(ctx.Cfg.SupervisorConfPath) == "" {
		return nil
	}
	confPath := ctx.Cfg.SupervisorConfPath
	stdoutPath, stderrPath := supervisorLogPaths(ctx.Cfg)
	if err := ensureLogDir(stdoutPath); err != nil {
		return err
	}
	if err := ensureLogDir(stderrPath); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(confPath), 0755); err != nil {
		return err
	}
	content := buildSupervisorProgramConfig(ctx.Cfg, cmdPath, args)
	if data, err := os.ReadFile(confPath); err == nil {
		if string(data) == content {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(confPath, []byte(content), 0644)
}

func buildSupervisorProgramConfig(cfg Config, cmdPath string, args []string) string {
	program := cfg.SupervisorProgram
	if strings.TrimSpace(program) == "" {
		program = "satisfactory"
	}
	stdoutPath, stderrPath := supervisorLogPaths(cfg)
	var b strings.Builder
	b.WriteString("[program:" + program + "]\n")
	b.WriteString("command=" + quoteCommand(cmdPath, args) + "\n")
	if strings.TrimSpace(cfg.StartCwd) != "" {
		b.WriteString("directory=" + cfg.StartCwd + "\n")
	}
	if strings.TrimSpace(cfg.StartUser) != "" {
		b.WriteString("user=" + cfg.StartUser + "\n")
	}
	b.WriteString("autostart=false\n")
	b.WriteString("autorestart=true\n")
	b.WriteString("stopsignal=INT\n")
	b.WriteString("stopasgroup=true\n")
	b.WriteString("killasgroup=true\n")
	b.WriteString("stdout_logfile=" + stdoutPath + "\n")
	b.WriteString("stdout_logfile_maxbytes=0\n")
	b.WriteString("stderr_logfile=" + stderrPath + "\n")
	b.WriteString("stderr_logfile_maxbytes=0\n")
	return b.String()
}

func supervisorLogPaths(cfg Config) (string, string) {
	base := "/home/container/logs"
	stdoutPath := filepath.Join(base, "satisfactory.stdout.log")
	stderrPath := filepath.Join(base, "satisfactory.stderr.log")
	return stdoutPath, stderrPath
}

func ensureLogDir(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "." || strings.TrimSpace(dir) == "" {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}

func tailSupervisorLogs(ctx *Context, stopCh <-chan struct{}) {
	if ctx == nil {
		return
	}
	stdoutPath, stderrPath := supervisorLogPaths(ctx.Cfg)
	if strings.TrimSpace(stdoutPath) != "" {
		go tailFile(stdoutPath, stopCh, os.Stdout)
	}
	if strings.TrimSpace(stderrPath) != "" {
		go tailFile(stderrPath, stopCh, os.Stderr)
	}
}

func tailFile(path string, stopCh <-chan struct{}, w io.Writer) {
	if strings.TrimSpace(path) == "" || w == nil {
		return
	}
	var offset int64
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		stat, err := f.Stat()
		if err != nil {
			_ = f.Close()
			continue
		}
		if stat.Size() < offset {
			offset = 0
		}
		for stat.Size() > offset {
			remain := stat.Size() - offset
			if remain <= 0 {
				break
			}
			readSize := int64(8192)
			if remain < readSize {
				readSize = remain
			}
			buf := make([]byte, readSize)
			n, err := f.ReadAt(buf, offset)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				offset += int64(n)
			}
			if err != nil {
				break
			}
		}
		_ = f.Close()
	}
}

func quoteCommand(cmdPath string, args []string) string {
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, quoteArg(cmdPath))
	for _, a := range args {
		parts = append(parts, quoteArg(a))
	}
	return strings.Join(parts, " ")
}

func quoteArg(val string) string {
	if strings.ContainsAny(val, " \t\"") {
		escaped := strings.ReplaceAll(val, `"`, `\"`)
		return `"` + escaped + `"`
	}
	return val
}

func supervisorStart(ctx *Context) error {
	if ctx == nil {
		return errors.New("context is nil")
	}
	name := strings.TrimSpace(ctx.Cfg.SupervisorProgram)
	if name == "" {
		name = "satisfactory"
	}
	return supervisorCall(ctx.Cfg, "supervisor.startProcess", []xmlParam{
		{Type: "string", Value: name},
		{Type: "boolean", Value: "0"},
	}, []string{"ALREADY_STARTED"})
}

func supervisorStop(ctx *Context) error {
	if ctx == nil {
		return errors.New("context is nil")
	}
	name := strings.TrimSpace(ctx.Cfg.SupervisorProgram)
	if name == "" {
		name = "satisfactory"
	}
	return supervisorCall(ctx.Cfg, "supervisor.stopProcess", []xmlParam{
		{Type: "string", Value: name},
		{Type: "boolean", Value: "1"},
	}, []string{"NOT_RUNNING", "ALREADY_STOPPED"})
}

func supervisorEnsureGroup(ctx *Context) error {
	if ctx == nil {
		return errors.New("context is nil")
	}
	if err := supervisorCall(ctx.Cfg, "supervisor.reloadConfig", nil, nil); err != nil {
		return err
	}
	name := strings.TrimSpace(ctx.Cfg.SupervisorProgram)
	if name == "" {
		name = "satisfactory"
	}
	return supervisorCall(ctx.Cfg, "supervisor.addProcessGroup", []xmlParam{
		{Type: "string", Value: name},
	}, []string{"ALREADY_ADDED"})
}

type xmlParam struct {
	Type  string
	Value string
}

func supervisorCall(cfg Config, method string, params []xmlParam, ignoreFaults []string) error {
	socketPath := strings.TrimSpace(cfg.SupervisorSocket)
	if socketPath == "" {
		return errors.New("supervisor socket is empty")
	}
	body := buildSupervisorXML(method, params)
	req, err := http.NewRequest(http.MethodPost, "http://unix/RPC2", bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml")
	if strings.TrimSpace(cfg.SupervisorUser) != "" || strings.TrimSpace(cfg.SupervisorPassword) != "" {
		req.SetBasicAuth(cfg.SupervisorUser, cfg.SupervisorPassword)
	}
	client := supervisorClient(socketPath)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("supervisor rpc failed: %s", resp.Status)
	}
	text := string(data)
	if strings.Contains(text, "<fault>") {
		fault := extractXMLTag(text, "faultString")
		code := extractXMLTag(text, "faultCode")
		if fault == "" {
			fault = "supervisor rpc fault"
			if code != "" {
				fault += " (" + code + ")"
			}
			summary := summarizeXMLFault(text)
			if summary != "" {
				fault += ": " + summary
			}
		}
		for _, ignore := range ignoreFaults {
			if strings.Contains(fault, ignore) {
				return nil
			}
		}
		if strings.Contains(fault, "BAD_NAME") {
			fault += " (program not found in supervisord config)"
		}
		return errors.New(fault)
	}
	return nil
}

func supervisorClient(socketPath string) *http.Client {
	dialer := &net.Dialer{}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &http.Client{Transport: tr}
}

func buildSupervisorXML(method string, params []xmlParam) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>`)
	b.WriteString("<methodCall>")
	b.WriteString("<methodName>" + xmlEscape(method) + "</methodName>")
	if len(params) > 0 {
		b.WriteString("<params>")
		for _, p := range params {
			b.WriteString("<param><value><" + p.Type + ">" + xmlEscape(p.Value) + "</" + p.Type + "></value></param>")
		}
		b.WriteString("</params>")
	}
	b.WriteString("</methodCall>")
	return b.String()
}

func xmlEscape(val string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(val)
}

func extractXMLTag(text, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	start := strings.Index(text, open)
	if start == -1 {
		return ""
	}
	start += len(open)
	end := strings.Index(text[start:], close)
	if end == -1 {
		return ""
	}
	return text[start : start+end]
}

func summarizeXMLFault(text string) string {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if strings.Contains(l, "<string>") && strings.Contains(l, "</string>") {
			val := extractXMLTag(l, "string")
			return strings.TrimSpace(val)
		}
	}
	return ""
}

type startUserInfo struct {
	UID int
	GID int
}

func applyStartUserAndPerms(ctx *Context, cmd *exec.Cmd) error {
	if ctx == nil || cmd == nil {
		return errors.New("start context missing")
	}

	userName := strings.TrimSpace(ctx.Cfg.StartUser)
	isRoot := os.Geteuid() == 0

	if userName == "" {
		if ctx.Cfg.ChownInstallDir {
			if isRoot {
				fmt.Println("chown install dir skipped: start user not set")
			} else {
				fmt.Println("chown install dir skipped: not running as root")
			}
		}
		if ctx.Cfg.ChmodInstallDir && !isRoot {
			fmt.Println("chmod install dir skipped: not running as root")
		}
		if ctx.Cfg.ChmodInstallDir && isRoot {
			if err := fixInstallPermissions(ctx.Cfg.InstallDir, 0, 0, false, true); err != nil {
				return err
			}
		}
		return nil
	}

	if !isRoot {
		fmt.Println("start user is set but current process is not root, ignoring")
		if ctx.Cfg.ChownInstallDir {
			fmt.Println("chown install dir skipped: not running as root")
		}
		if ctx.Cfg.ChmodInstallDir {
			fmt.Println("chmod install dir skipped: not running as root")
		}
		return nil
	}

	info, err := resolveStartUser(userName)
	if err != nil {
		return err
	}

	if ctx.Cfg.ChownInstallDir || ctx.Cfg.ChmodInstallDir {
		if err := fixInstallPermissions(ctx.Cfg.InstallDir, info.UID, info.GID, ctx.Cfg.ChownInstallDir, ctx.Cfg.ChmodInstallDir); err != nil {
			return err
		}
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(info.UID),
			Gid: uint32(info.GID),
		},
	}
	return nil
}

func resolveStartUser(value string) (startUserInfo, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return startUserInfo{}, errors.New("start user is empty")
	}

	usr, err := user.Lookup(value)
	if err != nil {
		if _, convErr := strconv.Atoi(value); convErr == nil {
			usr, err = user.LookupId(value)
		}
	}
	if err != nil {
		return startUserInfo{}, fmt.Errorf("start user lookup failed: %w", err)
	}

	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return startUserInfo{}, fmt.Errorf("invalid user uid: %w", err)
	}
	gid, err := strconv.Atoi(usr.Gid)
	if err != nil {
		return startUserInfo{}, fmt.Errorf("invalid user gid: %w", err)
	}
	return startUserInfo{UID: uid, GID: gid}, nil
}

func fixInstallPermissions(dir string, uid, gid int, doChown, doChmod bool) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("install dir is empty")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("install dir is not a directory")
	}

	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if doChown {
			if err := os.Chown(path, uid, gid); err != nil {
				return err
			}
		}
		if doChmod {
			mode := os.FileMode(0644)
			if d.IsDir() {
				mode = 0755
			} else {
				info, err := d.Info()
				if err == nil && info.Mode()&0111 != 0 {
					mode = 0755
				}
			}
			if err := os.Chmod(path, mode); err != nil {
				return err
			}
		}
		return nil
	})
}

func resolveStartCommand(cfg Config, args []string) (string, []string, error) {
	cmdPath := strings.TrimSpace(cfg.StartCmd)
	if cmdPath == "" {
		cmdPath = defaultStartCommandPath(cfg)
	}
	if !filepath.IsAbs(cmdPath) {
		cmdPath = filepath.Join(cfg.InstallDir, cmdPath)
	}

	info, err := os.Stat(cmdPath)
	if err != nil {
		return "", nil, err
	}
	if info.IsDir() {
		return "", nil, errors.New("start command is a directory")
	}

	ext := strings.ToLower(filepath.Ext(cmdPath))
	if ext == ".ps1" {
		return "powershell", append([]string{"-File", cmdPath}, args...), nil
	}
	if ext == ".bat" || ext == ".cmd" {
		return "cmd", append([]string{"/c", cmdPath}, args...), nil
	}
	if ext == ".sh" && info.Mode()&0111 == 0 {
		return "bash", append([]string{cmdPath}, args...), nil
	}
	if info.Mode()&0111 == 0 && ext == "" {
		return "bash", append([]string{cmdPath}, args...), nil
	}
	return cmdPath, args, nil
}

func defaultStartCommandPath(cfg Config) string {
	if isWindowsOS(cfg.OS) {
		return firstExistingOrDefault(cfg.InstallDir, []string{"FactoryServer.exe", "FactoryServer.bat", "FactoryServer.ps1"}, "FactoryServer.exe")
	}
	return firstExistingOrDefault(cfg.InstallDir, []string{"FactoryServer.sh", "FactoryServer.exe"}, "FactoryServer.sh")
}

func firstExistingOrDefault(base string, names []string, def string) string {
	for _, name := range names {
		if name == "" {
			continue
		}
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(base, path)
		}
		if st, err := os.Stat(path); err == nil && st != nil && !st.IsDir() {
			return name
		}
	}
	return def
}

func isWindowsOS(osName string) bool {
	s := strings.ToLower(strings.TrimSpace(osName))
	return strings.HasPrefix(s, "win") || s == "windows"
}

func buildInternalArgs(cfg Config) []string {
	args := append([]string{}, cfg.StartArgs...)
	aa := cfg.StartConfig.Args
	if aa.Port.Enabled && aa.Port.Value > 0 {
		args = append(args, fmt.Sprintf("-Port=%d", aa.Port.Value))
	}
	if aa.QueryPort.Enabled && aa.QueryPort.Value > 0 {
		args = append(args, fmt.Sprintf("-QueryPort=%d", aa.QueryPort.Value))
	}
	if aa.BeaconPort.Enabled && aa.BeaconPort.Value > 0 {
		args = append(args, fmt.Sprintf("-ReliablePort=%d", aa.BeaconPort.Value))
	}
	if aa.Log.Enabled {
		args = append(args, "-log")
	}
	if aa.Unattended.Enabled {
		args = append(args, "-unattended")
	}
	if aa.NoCrashDialog.Enabled {
		args = append(args, "-NoCrashDialog")
	}
	if aa.Multihome.Enabled {
		val := strings.TrimSpace(aa.Multihome.Value)
		if val != "" {
			args = append(args, "-multihome="+val)
		}
	}
	return args
}

func mergeArgs(internal []string, external []string) []string {
	externalKeys := map[string]struct{}{}
	for _, arg := range external {
		if k := normalizeArgKey(arg); k != "" {
			externalKeys[k] = struct{}{}
		}
	}
	out := make([]string, 0, len(internal)+len(external))
	for _, arg := range internal {
		if k := normalizeArgKey(arg); k != "" {
			if _, ok := externalKeys[k]; ok {
				continue
			}
		}
		out = append(out, arg)
	}
	out = append(out, external...)
	return out
}

func normalizeArgKey(arg string) string {
	s := strings.TrimSpace(arg)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "--") {
		s = strings.TrimPrefix(s, "--")
	} else if strings.HasPrefix(s, "-") {
		s = strings.TrimPrefix(s, "-")
	} else {
		return ""
	}
	if s == "" {
		return ""
	}
	if i := strings.IndexAny(s, "= "); i >= 0 {
		s = s[:i]
	}
	s = strings.ToLower(s)
	switch s {
	case "port":
		return "port"
	case "query_port", "queryport":
		return "queryport"
	case "beacon_port", "beaconport":
		return "beaconport"
	case "log":
		return "log"
	case "unattended":
		return "unattended"
	case "nocrashdialog":
		return "nocrashdialog"
	case "multihome":
		return "multihome"
	default:
		return ""
	}
}
