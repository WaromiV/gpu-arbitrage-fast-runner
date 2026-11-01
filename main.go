package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	minerURL  = "https://github.com/doktor83/SRBMiner-Multi/releases/download/3.8.3/SRBMiner-Multi-3-8-3-Linux.tar.gz"
	minerSHA  = "c9e10baae24d1811c04d30a416e237774e9e16110276c864a4221395f9f55e8b"
	minerPath = "SRBMiner-Multi-3-8-3/SRBMiner-MULTI"
)

var hashLine = regexp.MustCompile(`(?i)#\d+\s+.*?([0-9]+(?:\.[0-9]+)?)\s+TH/s`)

type status struct {
	sync.Mutex
	StartedAt    time.Time `json:"started_at"`
	Stage        string    `json:"stage"`
	StageAt      time.Time `json:"stage_at"`
	GPU          string    `json:"gpu,omitempty"`
	PoolProbeMS  int64     `json:"pool_probe_ms,omitempty"`
	PoolError    string    `json:"pool_error,omitempty"`
	DownloadMS   int64     `json:"download_ms,omitempty"`
	FirstPoolAt  time.Time `json:"first_pool_at,omitempty"`
	FirstHashAt  time.Time `json:"first_hash_at,omitempty"`
	FirstShareAt time.Time `json:"first_share_at,omitempty"`
	HashTH       float64   `json:"hash_th,omitempty"`
	Accepted     int       `json:"accepted"`
	Rejected     int       `json:"rejected"`
	Error        string    `json:"error,omitempty"`
}

func (s *status) update(stage string) {
	s.Lock()
	s.Stage, s.StageAt = stage, time.Now().UTC()
	s.Unlock()
}

func (s *status) snapshot() status {
	s.Lock()
	defer s.Unlock()
	return status{StartedAt: s.StartedAt, Stage: s.Stage, StageAt: s.StageAt,
		GPU: s.GPU, PoolProbeMS: s.PoolProbeMS, PoolError: s.PoolError,
		DownloadMS: s.DownloadMS, FirstPoolAt: s.FirstPoolAt,
		FirstHashAt: s.FirstHashAt, FirstShareAt: s.FirstShareAt,
		HashTH: s.HashTH, Accepted: s.Accepted, Rejected: s.Rejected, Error: s.Error}
}

func serve(s *status, token string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		given := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(given) != len(token) || subtle.ConstantTimeCompare([]byte(given), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.snapshot())
	})
	if err := http.ListenAndServe(":8080", mux); err != nil {
		fmt.Fprintln(os.Stderr, "status listener:", err)
	}
}

func poolProbe(s *status, pool string) {
	start := time.Now()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", pool, &tls.Config{MinVersion: tls.VersionTLS12})
	s.Lock()
	s.PoolProbeMS = time.Since(start).Milliseconds()
	if err != nil {
		s.PoolError = err.Error()
	} else {
		_ = conn.Close()
	}
	s.Unlock()
}

// extractRelease streams the official archive, extracts only within dest, and
// refuses to execute anything until its full SHA-256 matches the pinned value.
func extractRelease(ctx context.Context, client *http.Client, url, wantSHA, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("release download HTTP %d", resp.StatusCode)
	}
	hash := sha256.New()
	stream := io.TeeReader(io.LimitReader(resp.Body, 100<<20), hash)
	gz, err := gzip.NewReader(stream)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	root, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(hdr.Name)
		path := filepath.Join(root, name)
		if name == "." || !strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return fmt.Errorf("unsafe archive path: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if hdr.Size < 0 || hdr.Size > 100<<20 {
				return fmt.Errorf("invalid archive member size")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(f, tr)
			closeErr := f.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("unexpected archive member type")
		}
	}
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return err
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != wantSHA {
		return fmt.Errorf("release SHA-256 mismatch")
	}
	return nil
}

func scanMiner(r io.Reader, wallet string, s *status) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(strings.ReplaceAll(line, wallet, "<wallet>"))
		low := strings.ToLower(line)
		s.Lock()
		now := time.Now().UTC()
		if strings.Contains(low, "connected to prl-") && s.FirstPoolAt.IsZero() {
			s.FirstPoolAt = now
		}
		if match := hashLine.FindStringSubmatch(line); match != nil {
			s.HashTH, _ = strconv.ParseFloat(match[1], 64)
			if s.FirstHashAt.IsZero() {
				s.FirstHashAt = now
			}
		}
		if strings.Contains(low, "share accepted") {
			s.Accepted++
			if s.FirstShareAt.IsZero() {
				s.FirstShareAt = now
			}
		}
		if strings.Contains(low, "share rejected") {
			s.Rejected++
		}
		s.Unlock()
	}
}

func run(ctx context.Context) error {
	wallet := os.Getenv("PRL_WALLET")
	token := os.Getenv("STATUS_TOKEN")
	if !strings.HasPrefix(wallet, "prl1") || len(wallet) < 30 {
		return fmt.Errorf("PRL_WALLET must be an authorized public PRL address")
	}
	if len(token) < 32 {
		return fmt.Errorf("STATUS_TOKEN must be at least 32 characters")
	}
	pool := os.Getenv("PRL_POOL")
	if pool == "" {
		pool = "prl-eu.kryptex.network:8048"
	}
	worker := os.Getenv("PRL_WORKER")
	if worker == "" {
		worker = "clore-fast"
	}
	s := &status{StartedAt: time.Now().UTC()}
	s.update("starting")
	go serve(s, token)
	go poolProbe(s, pool)
	gpuResult := make(chan error, 1)
	go func() {
		out, err := exec.CommandContext(ctx, "nvidia-smi", "--query-gpu=name,power.limit", "--format=csv,noheader").Output()
		if err == nil {
			name := strings.TrimSpace(string(out))
			s.Lock()
			s.GPU = name
			s.Unlock()
			if expected := os.Getenv("EXPECTED_GPU"); expected != "" && !strings.Contains(name, expected) {
				err = fmt.Errorf("GPU model mismatch")
			}
		}
		gpuResult <- err
	}()
	s.update("downloading")
	start := time.Now()
	dest, err := os.MkdirTemp("", "prl-release-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dest)
	client := &http.Client{Timeout: 90 * time.Second}
	if err := extractRelease(ctx, client, minerURL, minerSHA, dest); err != nil {
		return err
	}
	s.Lock()
	s.DownloadMS = time.Since(start).Milliseconds()
	s.Unlock()
	s.update("verified")
	if err := <-gpuResult; err != nil {
		return fmt.Errorf("GPU check: %w", err)
	}
	miner := filepath.Join(dest, minerPath)
	s.update("mining")
	args := []string{"--disable-cpu", "--algorithm", "pearlhash", "--pool", pool,
		"--wallet", wallet, "--worker", worker, "--tls", "true", "--password", "x"}
	cmd := exec.CommandContext(ctx, miner, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); scanMiner(stdout, wallet, s) }()
	go func() { defer wg.Done(); scanMiner(stderr, wallet, s) }()
	err = cmd.Wait()
	wg.Wait()
	s.update("stopped")
	return err
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "runner:", err)
		os.Exit(1)
	}
}
