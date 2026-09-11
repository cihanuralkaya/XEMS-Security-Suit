package connector

import (
	"context"

	"xems.corp/suite/server/internal/model"
)

// builtin.go — dış bağımlılık gerektirmeyen yerleşik örnek bağlayıcılar. Hem
// çerçeveyi kanıtlar hem de yeni bağlayıcılar için şablondur.

// StaticConnector, sabit bir olay kümesi döndüren bağlayıcıdır (test/demo).
type StaticConnector struct {
	ConnName string
	ConnKind string
	Events   []model.Event
	Err      error // Health/Fetch'te dönecek hata (nil = sağlıklı)
}

func (c *StaticConnector) Name() string { return c.ConnName }
func (c *StaticConnector) Kind() string {
	if c.ConnKind == "" {
		return "static"
	}
	return c.ConnKind
}
func (c *StaticConnector) Health() error { return c.Err }
func (c *StaticConnector) Fetch(_ context.Context) ([]model.Event, error) {
	if c.Err != nil {
		return nil, c.Err
	}
	return c.Events, nil
}

// FuncConnector, bir fetch işlevini saran bağlayıcıdır — çağıranlar çekirdek kodu
// değiştirmeden ad-hoc kaynaklar kaydedebilir.
type FuncConnector struct {
	ConnName string
	ConnKind string
	FetchFn  func(ctx context.Context) ([]model.Event, error)
	HealthFn func() error
}

func (c *FuncConnector) Name() string { return c.ConnName }
func (c *FuncConnector) Kind() string {
	if c.ConnKind == "" {
		return "func"
	}
	return c.ConnKind
}
func (c *FuncConnector) Health() error {
	if c.HealthFn != nil {
		return c.HealthFn()
	}
	return nil
}
func (c *FuncConnector) Fetch(ctx context.Context) ([]model.Event, error) {
	if c.FetchFn == nil {
		return nil, nil
	}
	return c.FetchFn(ctx)
}
