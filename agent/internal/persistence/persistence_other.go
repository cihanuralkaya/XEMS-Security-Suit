//go:build !windows && !linux

package persistence

type noScanner struct{}

// NewScanner, desteklenmeyen platformlar için boş tarayıcı döner.
func NewScanner() Scanner { return noScanner{} }

func (noScanner) Scan() []Entry { return nil }
