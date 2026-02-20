package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type VersionCheckRequest struct {
	UUID string `json:"uuid"`
}

type VersionCheckResponse struct {
	Code int                      `json:"code"`
	Data *VersionCheckResponseData `json:"data"`
}

type VersionCheckResponseData struct {
	GameInfo *VersionCheckGameInfo `json:"game_info"`
}

type VersionCheckGameInfo struct {
	GameName        string `json:"game_name"`
	KindName        string `json:"kind_name"`
	VersionName     string `json:"version_name"`
	GameID          int    `json:"game_id"`
	VersionID       int    `json:"version_id"`
	CustomID        int    `json:"custom_id"`
	CustomVersionID int    `json:"custom_version_id"`
	Custom          bool   `json:"custom"`
	Description     string `json:"description"`
	Link            string `json:"link"`
}

func StepVersionCheck(cfg Config) error {
	if !cfg.VersionCheckEnabled {
		return nil
	}

	if cfg.CustomID <= 0 {
		fmt.Println("version check skipped: custom_id not set")
		return nil
	}

	currentVersion := strings.TrimSpace(cfg.VersionName)
	if currentVersion == "" {
		currentVersion = "1.0.0"
	}

	uuid, err := getContainerUUID()
	if err != nil {
		fmt.Printf("get container uuid failed: %v\n", err)
		uuid = ""
	}

	if uuid != "" {
		if !verifyPterodactylEnvironment(uuid) {
			fmt.Printf("pterodactyl environment verification failed for uuid: %s\n", uuid)
		}
	}

	latestInfo, err := fetchLatestVersion(cfg, uuid)
	if err != nil {
		fmt.Printf("version check failed: %v\n", err)
		return nil
	}

	if latestInfo == nil {
		fmt.Println("version check: no response data")
		return nil
	}

	latestVersion := strings.TrimSpace(latestInfo.VersionName)
	if latestVersion == "" {
		fmt.Println("version check: empty version_name in response")
		return nil
	}

	if currentVersion != latestVersion {
		fmt.Printf("version update available: %s -> %s\n", currentVersion, latestVersion)
		fmt.Printf("  game: %s\n", latestInfo.GameName)
		fmt.Printf("  kind: %s\n", latestInfo.KindName)
		if latestInfo.Description != "" {
			fmt.Printf("  description: %s\n", latestInfo.Description)
		}
		if latestInfo.Link != "" {
			fmt.Printf("  link: %s\n", latestInfo.Link)
		}
	} else {
		fmt.Printf("version check: current version %s is up to date\n", currentVersion)
	}

	return nil
}

func getContainerUUID() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return "", errors.New("empty hostname")
	}
	return hostname, nil
}

func isValidUUID(uuid string) bool {
	if uuid == "" {
		return false
	}
	matched, _ := regexp.MatchString(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, strings.ToLower(uuid))
	return matched
}

func verifyPterodactylEnvironment(uuid string) bool {
	score := 0

	if _, err := os.Stat("/.dockerenv"); err == nil {
		score += 3
	}

	mountData, err := os.ReadFile("/proc/mounts")
	if err == nil {
		mountStr := string(mountData)
		if strings.Contains(mountStr, "/home/container") {
			score += 3
		}
		if strings.Contains(mountStr, uuid) {
			score += 3
		}
	}

	hostname, _ := os.Hostname()
	if hostname == uuid {
		score += 2
	}

	if _, err := os.OpenFile("/etc/hostname", os.O_WRONLY, 0); err != nil {
		score += 2
	}

	return score >= 8
}

func fetchLatestVersion(cfg Config, uuid string) (*VersionCheckGameInfo, error) {
	if cfg.VersionCheckURL == "" {
		return nil, errors.New("version check url is empty")
	}

	apiURL := strings.TrimRight(cfg.VersionCheckURL, "/") + fmt.Sprintf("/%d/data.json", cfg.CustomID)

	timeout := cfg.VersionCheckTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	reqBody := VersionCheckRequest{UUID: uuid}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SatisfactoryServerStarter/1.0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.New("version check timeout")
		}
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("version check returned status %d: %s", resp.StatusCode, string(data))
	}

	var result VersionCheckResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse response failed: %w", err)
	}

	if result.Code != 200 {
		return nil, fmt.Errorf("response code %d", result.Code)
	}

	if result.Data == nil || result.Data.GameInfo == nil {
		return nil, errors.New("empty game_info in response")
	}

	return result.Data.GameInfo, nil
}
