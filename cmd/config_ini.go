package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func writeStartConfig(path string, cfg StartConfig) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("appid=%d\n", cfg.AppID))
	b.WriteString(fmt.Sprintf("os=%s\n", cfg.OS))
	b.WriteString("\n")
	b.WriteString("[port]\n")
	b.WriteString(fmt.Sprintf("enabled=%v\n", cfg.Args.Port.Enabled))
	b.WriteString(fmt.Sprintf("value=%d\n", cfg.Args.Port.Value))
	b.WriteString("\n")
	b.WriteString("[queryport]\n")
	b.WriteString(fmt.Sprintf("enabled=%v\n", cfg.Args.QueryPort.Enabled))
	b.WriteString(fmt.Sprintf("value=%d\n", cfg.Args.QueryPort.Value))
	b.WriteString("\n")
	b.WriteString("[beaconport]\n")
	b.WriteString(fmt.Sprintf("enabled=%v\n", cfg.Args.BeaconPort.Enabled))
	b.WriteString(fmt.Sprintf("value=%d\n", cfg.Args.BeaconPort.Value))
	b.WriteString("\n")
	b.WriteString("[log]\n")
	b.WriteString(fmt.Sprintf("enabled=%v\n", cfg.Args.Log.Enabled))
	b.WriteString("\n")
	b.WriteString("[unattended]\n")
	b.WriteString(fmt.Sprintf("enabled=%v\n", cfg.Args.Unattended.Enabled))
	b.WriteString("\n")
	b.WriteString("[nocrashdialog]\n")
	b.WriteString(fmt.Sprintf("enabled=%v\n", cfg.Args.NoCrashDialog.Enabled))
	b.WriteString("\n")
	b.WriteString("[multihome]\n")
	b.WriteString(fmt.Sprintf("enabled=%v\n", cfg.Args.Multihome.Enabled))
	b.WriteString(fmt.Sprintf("value=%s\n", cfg.Args.Multihome.Value))
	b.WriteString("\n")
	b.WriteString("[install]\n")
	b.WriteString(fmt.Sprintf("skip=%v\n", cfg.SkipInstall))
	b.WriteString(fmt.Sprintf("retry_forever=%v\n", cfg.InstallRetryForever))
	b.WriteString(fmt.Sprintf("retry_interval=%s\n", formatDuration(cfg.InstallRetryInterval)))
	b.WriteString("\n")
	b.WriteString("[supervisor]\n")
	b.WriteString(fmt.Sprintf("enabled=%v\n", cfg.SupervisorEnabled))
	b.WriteString(fmt.Sprintf("auto_config=%v\n", cfg.SupervisorAutoConfig))
	b.WriteString(fmt.Sprintf("socket=%s\n", cfg.SupervisorSocket))
	b.WriteString(fmt.Sprintf("program=%s\n", cfg.SupervisorProgram))
	b.WriteString(fmt.Sprintf("conf_path=%s\n", cfg.SupervisorConfPath))
	b.WriteString(fmt.Sprintf("main_conf_path=%s\n", cfg.SupervisorMainConfPath))
	b.WriteString(fmt.Sprintf("user=%s\n", cfg.SupervisorUser))
	b.WriteString(fmt.Sprintf("password=%s\n", cfg.SupervisorPassword))
	b.WriteString("\n")
	b.WriteString("[banner]\n")
	b.WriteString(fmt.Sprintf("path=%s\n", cfg.BannerPath))
	b.WriteString(fmt.Sprintf("wait=%s\n", formatDuration(cfg.BannerWait)))
	b.WriteString("\n")
	b.WriteString("[start]\n")
	b.WriteString(fmt.Sprintf("user=%s\n", cfg.StartUser))
	b.WriteString(fmt.Sprintf("chown_install_dir=%v\n", cfg.ChownInstallDir))
	b.WriteString(fmt.Sprintf("chmod_install_dir=%v\n", cfg.ChmodInstallDir))
	b.WriteString("\n")
	b.WriteString("[version_check]\n")
	b.WriteString(fmt.Sprintf("enabled=%v\n", cfg.VersionCheckEnabled))
	b.WriteString(fmt.Sprintf("url=%s\n", cfg.VersionCheckURL))
	b.WriteString(fmt.Sprintf("timeout=%s\n", formatDuration(cfg.VersionCheckTimeout)))
	b.WriteString(fmt.Sprintf("custom_id=%d\n", cfg.CustomID))
	b.WriteString(fmt.Sprintf("version_name=%s\n", cfg.VersionName))

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	return d.String()
}
