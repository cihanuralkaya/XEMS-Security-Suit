package script

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"xems.corp/suite/scriptwire"
)

// Result, sınırlı yürütmenin sonucudur.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
}

// interpreterCmd, bilinen yorumlayıcı adını (exe, gövde-bayrağı) çiftine eşler.
func interpreterCmd(name string) (string, string, bool) {
	switch name {
	case "powershell":
		return "powershell", "-NoProfile -NonInteractive -Command", true
	case "cmd":
		return "cmd", "/c", true
	case "sh":
		return "sh", "-c", true
	case "bash":
		return "bash", "-c", true
	case "node":
		return "node", "-e", true
	default:
		return "", "", false
	}
}

// minimalEnv, çalıştırma için kısıtlı bir ortam değişkeni kümesi döner (tam
// ortamı miras almaz). Yorumlayıcının çalışabilmesi için gerekli asgari
// değişkenler geçirilir.
func minimalEnv() []string {
	keep := []string{"PATH"}
	if runtime.GOOS == "windows" {
		keep = append(keep, "SystemRoot", "ComSpec", "PATHEXT", "TEMP", "TMP", "windir")
	}
	var env []string
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// cappedBuffer, en fazla max bayt biriktirir; fazlasını sessizce atar (çıktı
// bombalarına karşı).
type cappedBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - len(c.buf); room > 0 {
		if len(p) > room {
			c.buf = append(c.buf, p[:room]...)
		} else {
			c.buf = append(c.buf, p...)
		}
	}
	return len(p), nil // her zaman "yazıldı" de ki süreç bloklanmasın
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.buf)
}

// Run, DOĞRULANMIŞ bir scripti sınırlı biçimde çalıştırır: timeout, çıktı
// sınırı (her akış için maxOutput), minimal env, stdin kapalı. Çağıran, Run'dan
// ÖNCE imzayı doğrulamış olmalıdır (bkz. Verifier).
func Run(ctx context.Context, s scriptwire.Script, timeout time.Duration, maxOutput int) (Result, error) {
	exe, flag, ok := interpreterCmd(s.Interpreter)
	if !ok {
		return Result{}, errors.New("script: desteklenmeyen yorumlayıcı: " + s.Interpreter)
	}
	if maxOutput <= 0 {
		maxOutput = 1 << 20 // 1 MiB
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := append([]string{flag, s.Body}, s.Args...)
	cmd := exec.CommandContext(runCtx, exe, args...)
	cmd.Env = minimalEnv()
	cmd.Stdin = nil
	// SINIR: CommandContext yalnız doğrudan süreci öldürür; torun süreçler
	// (ör. cmd'nin başlattığı ping) OS job object olmadan hemen ölmeyebilir.
	// WaitDelay, timeout sonrası Run'ın G/Ç için sonsuz beklemesini sınırlar.
	// Gerçek süreç-ağacı sonlandırma (Windows Job Object / Unix process group)
	// ileri bir faz.
	cmd.WaitDelay = 3 * time.Second
	outBuf := &cappedBuffer{max: maxOutput}
	errBuf := &cappedBuffer{max: maxOutput}
	cmd.Stdout = outBuf
	cmd.Stderr = errBuf

	err := cmd.Run()
	res := Result{Stdout: outBuf.String(), Stderr: errBuf.String()}
	if runCtx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		res.ExitCode = -1
		return res, nil
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
			return res, nil // script hata kodu döndürdü; yürütme başarılı
		}
		return res, err // yürütme başlatılamadı
	}
	res.ExitCode = 0
	return res, nil
}
