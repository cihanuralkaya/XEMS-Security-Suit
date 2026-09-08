//go:build !windows && !linux

package usbmon

type noScanner struct{}

// NewScanner, desteklenmeyen platformlar için boş tarayıcı döner.
func NewScanner() Scanner { return noScanner{} }

func (noScanner) Scan() []Drive { return nil }

// Block, desteklenmeyen platformda hata döner.
func Block(string) error { return ErrBlockUnsupported }
