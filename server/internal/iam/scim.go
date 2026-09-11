package iam

import (
	"errors"
	"sync"
	"time"
)

// SCIM 2.0 çekirdek User şeması tanımlayıcısı (RFC 7643).
const (
	// SchemaUser, SCIM çekirdek User kaynağının şema URN'sidir.
	SchemaUser = "urn:ietf:params:scim:schemas:core:2.0:User"
	// ResourceTypeUser, meta.resourceType için User değeridir.
	ResourceTypeUser = "User"
)

// SCIM sağlama hataları.
var (
	// ErrUserExists, verilen id ile zaten bir kullanıcı varsa döner.
	ErrUserExists = errors.New("iam: SCIM kullanıcısı zaten var")
	// ErrUserNotFound, istenen kullanıcı bulunamazsa döner.
	ErrUserNotFound = errors.New("iam: SCIM kullanıcısı bulunamadı")
	// ErrSAMLNotImplemented, varsayılan SAML sağlayıcısı çağrıldığında döner.
	ErrSAMLNotImplemented = errors.New("iam: SAML onaylama doğrulaması gerçeklenmedi (entegrasyon dikişi)")
)

// Name, SCIM User'ın adının bileşenlerini tutar (RFC 7643 §4.1.1 alt kümesi).
type Name struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// Email, SCIM çok-değerli e-posta girdisidir.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Meta, SCIM kaynak meta verisidir (RFC 7643 §3.1).
type Meta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
}

// User, SCIM 2.0 çekirdek User şemasının bir alt kümesidir. Yalnız sağlama
// (provisioning) için gereken çekirdek alanlar modellenir. JSON etiketleri
// SCIM'in camelCase sözleşmesini izler (snake_case değil); bu, şemanın RFC
// 7643 ile tel-uyumlu kalması içindir.
type User struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id,omitempty"`
	ExternalID string   `json:"externalId,omitempty"`
	UserName   string   `json:"userName"`
	Name       Name     `json:"name"`
	Emails     []Email  `json:"emails,omitempty"`
	Active     bool     `json:"active"`
	Meta       Meta     `json:"meta,omitempty"`
}

// Provisioner, bir kimlik sağlayıcısının (IdP) SCIM üzerinden kullanıcı yaşam
// döngüsünü yönettiği arayüzdür: oluşturma, tam değiştirme (PUT), devre dışı
// bırakma (soft-delete) ve okuma.
type Provisioner interface {
	// Create, yeni bir kullanıcı sağlar. id zaten varsa ErrUserExists döner.
	Create(u User) (User, error)
	// Replace, verilen id'deki kullanıcıyı tümüyle değiştirir (SCIM PUT).
	Replace(id string, u User) (User, error)
	// Deactivate, kullanıcıyı active=false yaparak devre dışı bırakır.
	Deactivate(id string) (User, error)
	// Get, verilen id'deki kullanıcıyı döndürür.
	Get(id string) (User, error)
}

// MemProvisioner, Provisioner'ın eşzamanlı-güvenli, bellek-içi bir
// gerçeklemesidir. Test ve tek-düğüm kurulumlar için uygundur.
type MemProvisioner struct {
	mu    sync.RWMutex
	users map[string]User
	// now, meta zaman damgaları için enjekte edilebilir saat (nil ise time.Now).
	now func() time.Time
}

// NewMemProvisioner, boş bir bellek-içi sağlayıcı oluşturur.
func NewMemProvisioner() *MemProvisioner {
	return &MemProvisioner{users: make(map[string]User)}
}

// nowTime, enjekte edilmiş saati veya time.Now'u döndürür.
func (m *MemProvisioner) nowTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// normalize, kaydedilen kullanıcının şema ve meta alanlarının tutarlı olmasını
// sağlar.
func (m *MemProvisioner) normalize(u User) User {
	if len(u.Schemas) == 0 {
		u.Schemas = []string{SchemaUser}
	}
	u.Meta.ResourceType = ResourceTypeUser
	return u
}

// Create, Provisioner arayüzünü gerçekler.
func (m *MemProvisioner) Create(u User) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u.ID == "" {
		return User{}, errors.New("iam: SCIM kullanıcısı id gerektirir")
	}
	if _, ok := m.users[u.ID]; ok {
		return User{}, ErrUserExists
	}
	u = m.normalize(u)
	t := m.nowTime()
	u.Meta.Created = t
	u.Meta.LastModified = t
	m.users[u.ID] = u
	return u, nil
}

// Replace, Provisioner arayüzünü gerçekler (SCIM PUT semantiği).
func (m *MemProvisioner) Replace(id string, u User) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, ok := m.users[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	u = m.normalize(u)
	u.ID = id
	u.Meta.Created = existing.Meta.Created
	u.Meta.LastModified = m.nowTime()
	m.users[id] = u
	return u, nil
}

// Deactivate, Provisioner arayüzünü gerçekler: active=false yapar (soft-delete;
// kalıcı silme kasten desteklenmez — denetim izi korunur).
func (m *MemProvisioner) Deactivate(id string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	u.Active = false
	u.Meta.LastModified = m.nowTime()
	m.users[id] = u
	return u, nil
}

// Get, Provisioner arayüzünü gerçekler.
func (m *MemProvisioner) Get(id string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}

// SAMLProvider, SAML 2.0 onaylamalarını (assertion) doğrulayan bir sağlayıcının
// arayüzüdür. Tam SAML desteği, imzalı XML belgelerinin XML-dsig ile
// doğrulanmasını (canonicalization/C14N, XML imza çözümleme) gerektirir; bu,
// standart kütüphanenin ötesinde yetenekler (harici bir XML-dsig kütüphanesi)
// ister. Bu nedenle SAML, çekirdek paketin sıfır-bağımlılık kuralını bozmamak
// için kasten bir entegrasyon dikişi olarak bırakılmıştır. Üretim kullanımı
// için bu arayüz, XML-dsig yeteneğine sahip bir yan-hizmet veya derleme
// etiketli bir eklenti tarafından gerçeklenmelidir.
type SAMLProvider interface {
	// ValidateAssertion, ham bir SAML onaylamasını doğrular ve eşlenmiş
	// Claims döndürür.
	ValidateAssertion(assertion []byte) (Claims, error)
}

// NotImplementedSAML, SAMLProvider'ın varsayılan gerçeklemesidir; her çağrıda
// ErrSAMLNotImplemented döner. Gerçek bir sağlayıcı yapılandırılana dek
// güvenli bir varsayılan (fail-closed) sağlar.
type NotImplementedSAML struct{}

// ValidateAssertion, SAMLProvider arayüzünü gerçekler ve her zaman
// ErrSAMLNotImplemented döndürür.
func (NotImplementedSAML) ValidateAssertion(assertion []byte) (Claims, error) {
	return Claims{}, ErrSAMLNotImplemented
}
