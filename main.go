package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"satisfactory-simpfun-for-steamservice-start-script/cmd"
)

//go:embed banner.txt
var defaultBanner string

func main() {
	cfg, err := cmd.LoadConfig(os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	showBanner(cfg)

	if err := cmd.StepVersionCheck(cfg); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	ctx, err := cmd.NewContext(cfg)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if err := cmd.StepCheck(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if !cfg.SkipInstall {
		if err := cmd.StepInstallWithRetry(ctx); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}

	if err := cmd.StepStart(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func showBanner(cfg cmd.Config) {
	path := strings.TrimSpace(cfg.BannerPath)
	var banner string

	if path != "" {
		if !filepath.IsAbs(path) {
			exe, err := os.Executable()
			if err == nil {
				path = filepath.Join(filepath.Dir(exe), path)
			}
		}
		data, err := os.ReadFile(path)
		if err == nil {
			banner = string(data)
		}
	}

	if banner == "" {
		banner = defaultBanner
	}

	fmt.Println(banner)
	if cfg.BannerWait > 0 {
		time.Sleep(cfg.BannerWait)
	}
}
