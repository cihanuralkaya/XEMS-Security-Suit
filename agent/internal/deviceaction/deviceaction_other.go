//go:build !windows && !linux

package deviceaction

// Lock, desteklenmeyen platformda hata döner.
func Lock() error { return ErrActionUnsupported }

// Restart, desteklenmeyen platformda hata döner.
func Restart() error { return ErrActionUnsupported }

// Wipe, desteklenmeyen platformda hata döner.
func Wipe() error { return ErrActionUnsupported }
