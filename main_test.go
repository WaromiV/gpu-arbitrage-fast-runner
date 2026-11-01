package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func archive(t *testing.T, name string) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	content := []byte("test miner")
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o700, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestVerifiedStreamingExtraction(t *testing.T) {
	data := archive(t, "release/miner")
	sum := sha256.Sum256(data)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data)
	}))
	defer server.Close()
	dest := t.TempDir()
	if err := extractRelease(context.Background(), server.Client(), server.URL,
		hex.EncodeToString(sum[:]), dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "release/miner"))
	if err != nil || string(got) != "test miner" {
		t.Fatalf("extracted content: %q, %v", got, err)
	}
	if err := extractRelease(context.Background(), server.Client(), server.URL,
		"0000000000000000000000000000000000000000000000000000000000000000", t.TempDir()); err == nil {
		t.Fatal("accepted incorrect SHA-256")
	}
}

func TestArchivePathTraversalRejected(t *testing.T) {
	data := archive(t, "../outside")
	sum := sha256.Sum256(data)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data)
	}))
	defer server.Close()
	if err := extractRelease(context.Background(), server.Client(), server.URL,
		hex.EncodeToString(sum[:]), t.TempDir()); err == nil {
		t.Fatal("accepted path traversal")
	}
}
