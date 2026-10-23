package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"bypass-proxy/pkg/doh"
	"bypass-proxy/pkg/proxy"
	"bypass-proxy/pkg/sni"
	"bypass-proxy/pkg/sysproxy"
)

var version = "1.0.0"

func main() {
	httpPort := flag.Int("http-port", 8080, "Port for HTTP/HTTPS proxy")
	socksPort := flag.Int("socks-port", 1080, "Port for SOCKS5 proxy")
	bindHost := flag.String("bind", "127.0.0.1", "Bind address for proxy listeners")
	strategyStr := flag.String("strategy", "early", "SNI split strategy: 'early' (split at byte 30, recommended), 'sni' (split middle of hostname), 'multi' (multi-chunk)")
	delayMs := flag.Int("delay", 15, "Delay between packet fragments in milliseconds")
	dohList := flag.String("doh", "https://1.1.1.1/dns-query,https://1.0.0.1/dns-query,https://8.8.8.8/resolve", "Comma-separated DoH endpoints")
	relayWorker := flag.String("relay", "bypass-relay.willson2016pos.workers.dev", "Cloudflare Worker relay host for IP-blackholed sites (leave blank to disable)")
	autoSysProxy := flag.Bool("sysproxy", true, "Automatically configure macOS system proxy on start/exit")
	runTest := flag.Bool("test", false, "Run connectivity self-test against blocked targets")
	flag.Parse()

	var strategy sni.SplitStrategy
	switch strings.ToLower(*strategyStr) {
	case "early":
		strategy = sni.SplitEarly
	case "multi":
		strategy = sni.SplitMultiChunk
	default:
		strategy = sni.SplitAtSNI
	}

	dohEndpoints := strings.Split(*dohList, ",")
	for i := range dohEndpoints {
		dohEndpoints[i] = strings.TrimSpace(dohEndpoints[i])
	}
	resolver := doh.NewResolver(dohEndpoints...)

	cfg := proxy.Config{
		Resolver:      resolver,
		SplitStrategy: strategy,
		MicroDelay:    time.Duration(*delayMs) * time.Millisecond,
		DialTimeout:   10 * time.Second,
		RelayWorker:   strings.TrimSpace(*relayWorker),
	}

	tunnel := proxy.NewTunnel(cfg)

	if *runTest {
		runConnectivitySelfTest(tunnel)
		return
	}

	printBanner(*httpPort, *socksPort, *bindHost, *strategyStr, *delayMs)

	// Start HTTP Proxy
	httpAddr := fmt.Sprintf("%s:%d", *bindHost, *httpPort)
	httpServer := proxy.NewHTTPServer(httpAddr, tunnel)
	go func() {
		if err := httpServer.Start(); err != nil {
			log.Fatalf("HTTP Proxy error: %v", err)
		}
	}()

	// Start SOCKS5 Proxy
	socksAddr := fmt.Sprintf("%s:%d", *bindHost, *socksPort)
	socksServer := proxy.NewSOCKS5Server(socksAddr, tunnel)
	go func() {
		if err := socksServer.Start(); err != nil {
			log.Fatalf("SOCKS5 Proxy error: %v", err)
		}
	}()

	var sysProxyMgr *sysproxy.Manager
	if *autoSysProxy {
		mgr, err := sysproxy.NewManager()
		if err == nil {
			sysProxyMgr = mgr
			if err := mgr.EnableHTTP(*bindHost, *httpPort); err != nil {
				log.Printf("[SysProxy Warning] Could not set system proxy automatically: %v", err)
			} else {
				mgr.SetupCleanupHook()
			}
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	fmt.Println("\n[!] Shutting down bypass-proxy...")

	if sysProxyMgr != nil {
		_ = sysProxyMgr.DisableAll()
	}
	_ = httpServer.Close()
	_ = socksServer.Close()
	fmt.Println("[✓] Clean exit. System proxy restored.")
}

func printBanner(httpPort, socksPort int, bindHost, strategy string, delayMs int) {
	fmt.Println("=========================================================")
	fmt.Printf("   🚀 BYPASS-PROXY v%s (Anti-Censorship & DPI Evasion)\n", version)
	fmt.Println("=========================================================")
	fmt.Printf(" [•] HTTP/HTTPS Proxy: http://%s:%d\n", bindHost, httpPort)
	fmt.Printf(" [•] SOCKS5 Proxy:     socks5://%s:%d\n", bindHost, socksPort)
	fmt.Printf(" [•] SNI Strategy:     %s (MicroDelay: %dms)\n", strategy, delayMs)
	fmt.Println(" [•] DNS Security:    DNS-over-HTTPS (DoH Cloudflare/Google)")
	fmt.Println("---------------------------------------------------------")
	fmt.Println(" Quick Test in another terminal:")
	fmt.Printf("   curl -x http://%s:%d -I https://www.reddit.com\n", bindHost, httpPort)
	fmt.Println("=========================================================")
	fmt.Println(" Press Ctrl+C anytime to stop and restore network settings.")
	fmt.Println("")
}

func runConnectivitySelfTest(tunnel *proxy.Tunnel) {
	fmt.Println("=========================================================")
	fmt.Println("   🔍 RUNNING CONNECTIVITY & DPI-BYPASS TEST")
	fmt.Println("=========================================================")

	testSites := []struct {
		name string
		url  string
	}{
		{"Reddit (DPI Blocked)", "https://www.reddit.com"},
		{"Vimeo (DPI Blocked)", "https://vimeo.com"},
		{"DuckDuckGo", "https://duckduckgo.com"},
		{"Pornhub (IP Blackhole -> CF Relay)", "https://www.pornhub.com"},
	}

	// Spin up a temporary proxy on random port for testing
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("failed to bind test listener: %v", err)
	}
	defer l.Close()

	testServer := proxy.NewHTTPServer(l.Addr().String(), tunnel)
	go func() {
		_ = testServer.Serve(l)
	}()
	defer testServer.Close()

	proxyURL, _ := url.Parse("http://" + l.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
		Timeout: 8 * time.Second,
	}

	for _, site := range testSites {
		fmt.Printf(" Testing %-32s ... ", site.name)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		req, err := http.NewRequestWithContext(ctx, "GET", site.url, nil)
		if err != nil {
			cancel()
			fmt.Printf("❌ FAILED (%v)\n", err)
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			fmt.Printf("❌ FAILED (%v)\n", err)
			continue
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		cancel()

		fmt.Printf("✅ SUCCESS (Status: %d)\n", resp.StatusCode)
	}
	fmt.Println("=========================================================")
}
