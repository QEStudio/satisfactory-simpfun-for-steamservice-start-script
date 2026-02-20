package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type installResp struct {
	JobID string `json:"jobId"`
	ID    string `json:"id"`
}

type jobProgress struct {
	Phase   string   `json:"phase"`
	Percent *float64 `json:"percent"`
	Detail  string   `json:"detail"`
}

type jobDetail struct {
	ID       string       `json:"id"`
	State    string       `json:"state"`
	Error    string       `json:"error"`
	Logs     []string     `json:"logs"`
	Progress *jobProgress `json:"progress"`
}

func StepInstall(ctx *Context) error {
	if ctx == nil {
		return errors.New("context is nil")
	}

	payload := map[string]any{
		"appId": ctx.Cfg.AppID,
		"dir":   ctx.Cfg.InstallDir,
		"os":    ctx.Cfg.OS,
	}
	if ctx.Cfg.MaxDownloads > 0 {
		payload["maxDownloads"] = ctx.Cfg.MaxDownloads
	}

	var resp installResp
	reqCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := ctx.doJSON(reqCtx, http.MethodPost, "/api/install", payload, &resp); err != nil {
		return fmt.Errorf("install request failed: %w", err)
	}

	jobID := strings.TrimSpace(firstNonEmpty(resp.JobID, resp.ID))
	if jobID == "" {
		return errors.New("install response missing job id")
	}
	ctx.JobID = jobID
	fmt.Println("install job started:", jobID)

	return waitJob(ctx, jobID)
}

func waitJob(ctx *Context, jobID string) error {
	lastLogIndex := 0
	lastState := ""
	lastProgress := ""

	for {
		var detail jobDetail
		reqCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := ctx.doJSON(reqCtx, http.MethodGet, "/api/jobs/"+jobID, nil, &detail)
		cancel()
		if err != nil {
			return err
		}

		if detail.State != "" && detail.State != lastState {
			lastState = detail.State
			fmt.Println("job state:", detail.State)
		}

		if detail.Progress != nil {
			p := ""
			if detail.Progress.Phase != "" {
				p = detail.Progress.Phase
			}
			if detail.Progress.Detail != "" {
				if p != "" {
					p += " "
				}
				p += detail.Progress.Detail
			}
			if detail.Progress.Percent != nil {
				if p != "" {
					p += " "
				}
				p += fmt.Sprintf("%.1f%%", *detail.Progress.Percent*100)
			}
			if p != "" && p != lastProgress {
				lastProgress = p
				fmt.Println("progress:", p)
			}
		}

		if len(detail.Logs) > lastLogIndex {
			for _, line := range detail.Logs[lastLogIndex:] {
				fmt.Println(line)
			}
			lastLogIndex = len(detail.Logs)
		}

		if isTerminalState(detail.State) {
			if strings.EqualFold(detail.State, "Succeeded") {
				fmt.Println("install job succeeded")
				return nil
			}
			msg := strings.TrimSpace(detail.Error)
			if msg == "" {
				msg = "install job ended: " + detail.State
			}
			return errors.New(msg)
		}

		time.Sleep(ctx.Cfg.PollInterval)
	}
}

func isTerminalState(state string) bool {
	switch strings.TrimSpace(state) {
	case "Succeeded", "Failed", "Canceled":
		return true
	default:
		return false
	}
}

func StepInstallWithRetry(ctx *Context) error {
	if ctx == nil {
		return errors.New("context is nil")
	}

	attempt := 0
	for {
		attempt++
		err := StepInstall(ctx)
		if err == nil {
			return nil
		}
		if !ctx.Cfg.InstallRetryForever {
			return err
		}
		wait := ctx.Cfg.InstallRetryInterval
		if wait <= 0 {
			wait = 10 * time.Second
		}
		fmt.Println("install attempt failed:", err.Error())
		fmt.Println("retrying in", wait.String())
		time.Sleep(wait)
	}
}
