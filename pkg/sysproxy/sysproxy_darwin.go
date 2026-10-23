//go:build darwin

package sysproxy

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

// Manager manages macOS system proxy settings via networksetup.
type Manager struct {
	service string
}

// NewManager discovers the active network service (e.g. Wi-Fi) and returns a Manager.
func NewManager() (*Manager, error) {
	service, err := DetectActiveService()
	if err != nil {
		return nil, err
	}
	return &Manager{service: service}, nil
}

// ServiceName returns the detected network service name.
func (m *Manager) ServiceName() string {
	return m.service
}

// EnableHTTP configures both HTTP (webproxy) and HTTPS (securewebproxy).
func (m *Manager) EnableHTTP(host string, port int) error {
	pStr := strconv.Itoa(port)

	// Set Web Proxy (HTTP)
	if out, err := exec.Command("/usr/sbin/networksetup", "-setwebproxy", m.service, host, pStr).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set webproxy: %s: %w", string(out), err)
	}
	_ = exec.Command("/usr/sbin/networksetup", "-setwebproxystate", m.service, "on").Run()

	// Set Secure Web Proxy (HTTPS)
	if out, err := exec.Command("/usr/sbin/networksetup", "-setsecurewebproxy", m.service, host, pStr).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set securewebproxy: %s: %w", string(out), err)
	}
	_ = exec.Command("/usr/sbin/networksetup", "-setsecurewebproxystate", m.service, "on").Run()

	log.Printf("[SysProxy] Enabled HTTP/HTTPS proxy on service '%s' -> %s:%d", m.service, host, port)
	return nil
}

// DisableHTTP turns off webproxy and securewebproxy.
func (m *Manager) DisableHTTP() error {
	_ = exec.Command("/usr/sbin/networksetup", "-setwebproxystate", m.service, "off").Run()
	_ = exec.Command("/usr/sbin/networksetup", "-setsecurewebproxystate", m.service, "off").Run()
	log.Printf("[SysProxy] Disabled HTTP/HTTPS proxy on service '%s'", m.service)
	return nil
}

// EnableSOCKS configures the macOS SOCKS firewall proxy.
func (m *Manager) EnableSOCKS(host string, port int) error {
	pStr := strconv.Itoa(port)
	if out, err := exec.Command("/usr/sbin/networksetup", "-setsocksfirewallproxy", m.service, host, pStr).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set socks proxy: %s: %w", string(out), err)
	}
	_ = exec.Command("/usr/sbin/networksetup", "-setsocksfirewallproxystate", m.service, "on").Run()
	log.Printf("[SysProxy] Enabled SOCKS proxy on service '%s' -> %s:%d", m.service, host, port)
	return nil
}

// DisableSOCKS turns off the SOCKS proxy.
func (m *Manager) DisableSOCKS() error {
	_ = exec.Command("/usr/sbin/networksetup", "-setsocksfirewallproxystate", m.service, "off").Run()
	log.Printf("[SysProxy] Disabled SOCKS proxy on service '%s'", m.service)
	return nil
}

// DisableAll turns off all proxy settings on the active service.
func (m *Manager) DisableAll() error {
	_ = m.DisableHTTP()
	_ = m.DisableSOCKS()
	return nil
}

// SetupCleanupHook catches termination signals and guarantees system proxy settings are restored.
func (m *Manager) SetupCleanupHook() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		sig := <-c
		log.Printf("\n[SysProxy] Received signal %v, restoring network proxy settings...", sig)
		_ = m.DisableAll()
		os.Exit(0)
	}()
}

// DetectActiveService identifies the primary network service handling internet traffic.
func DetectActiveService() (string, error) {
	// 1. Get default route interface (e.g. en0)
	routeOut, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	var defaultDev string
	if err == nil {
		lines := strings.Split(string(routeOut), "\n")
		for _, l := range lines {
			trimmed := strings.TrimSpace(l)
			if strings.HasPrefix(trimmed, "interface:") {
				parts := strings.Fields(trimmed)
				if len(parts) >= 2 {
					defaultDev = parts[1]
					break
				}
			}
		}
	}

	// 2. Map interface (en0) to Hardware Port Name (e.g. Wi-Fi)
	if defaultDev != "" {
		hwOut, err := exec.Command("/usr/sbin/networksetup", "-listallhardwareports").CombinedOutput()
		if err == nil {
			blocks := strings.Split(string(hwOut), "\n\n")
			for _, b := range blocks {
				var portName, devName string
				for _, line := range strings.Split(b, "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "Hardware Port:") {
						portName = strings.TrimSpace(strings.TrimPrefix(line, "Hardware Port:"))
					} else if strings.HasPrefix(line, "Device:") {
						devName = strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
					}
				}
				if devName == defaultDev && portName != "" {
					return portName, nil
				}
			}
		}
	}

	// 3. Fallback: inspect enabled network services
	listOut, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to list network services: %w", err)
	}

	lines := strings.Split(string(listOut), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		if bytes.Contains([]byte(strings.ToLower(line)), []byte("wi-fi")) ||
			bytes.Contains([]byte(strings.ToLower(line)), []byte("ethernet")) {
			return line, nil
		}
	}

	// Default fallback
	return "Wi-Fi", nil
}
