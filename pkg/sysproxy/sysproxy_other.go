//go:build !darwin

package sysproxy

import (
	"errors"
	"log"
)

type Manager struct {
	service string
}

func NewManager() (*Manager, error) {
	return &Manager{service: "default"}, nil
}

func (m *Manager) ServiceName() string {
	return m.service
}

func (m *Manager) EnableHTTP(host string, port int) error {
	log.Printf("[SysProxy] Automatic system proxy configuration is only implemented for macOS. Please configure proxy %s:%d manually.", host, port)
	return errors.New("unsupported on this OS")
}

func (m *Manager) DisableHTTP() error {
	return nil
}

func (m *Manager) EnableSOCKS(host string, port int) error {
	return errors.New("unsupported on this OS")
}

func (m *Manager) DisableSOCKS() error {
	return nil
}

func (m *Manager) DisableAll() error {
	return nil
}

func (m *Manager) SetupCleanupHook() {}
