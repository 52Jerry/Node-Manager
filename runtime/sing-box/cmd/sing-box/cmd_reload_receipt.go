package main

import (
	"encoding/json"
	"os"
	"regexp"
	"time"
)

var reloadReceiptPath string
var reloadNoncePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func init() {
	mainCommand.PersistentFlags().StringVar(&reloadReceiptPath, "reload-receipt", "", "private reload request and acknowledgement path")
}

func requestedReloadNonce() string {
	if reloadReceiptPath == "" {
		return ""
	}
	data, err := os.ReadFile(reloadReceiptPath)
	if err != nil || len(data) > 1024 {
		return ""
	}
	var request struct {
		Nonce string `json:"nonce"`
	}
	if json.Unmarshal(data, &request) != nil || !reloadNoncePattern.MatchString(request.Nonce) {
		return ""
	}
	return request.Nonce
}

func acknowledgeReload(nonce, mode string, success bool) {
	if nonce == "" || reloadReceiptPath == "" {
		return
	}
	data, err := json.Marshal(map[string]any{"nonce": nonce, "mode": mode, "success": success, "completed_at": time.Now().UTC()})
	if err != nil {
		return
	}
	temporary := reloadReceiptPath + ".result.tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr == nil && syncErr == nil && closeErr == nil {
		_ = os.Rename(temporary, reloadReceiptPath+".result")
	}
}
