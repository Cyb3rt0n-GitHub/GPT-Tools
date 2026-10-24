package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestReportRendersResultsAndEscapesEvidence(t *testing.T) {
	data, err := renderHTML([]*SSLScanResult{{Domain: "one.example", ScanResults: "<script>bad()</script>", DNSRecords: "v=spf1 -all", DNSRecommendations: "dns-comment"}, {Domain: "two.example", ScanResults: "second-domain"}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"one.example", "two.example", "second-domain", "v=spf1 -all", "dns-comment", "&lt;script&gt;"} {
		if !strings.Contains(text, want) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Contains(text, "<script>") {
		t.Error("unescaped evidence")
	}
}

func TestLookupFailureIsUnknownAndDoesNotPanic(t *testing.T) {
	original := lookupTXT
	defer func() { lookupTXT = original }()
	lookupTXT = func(context.Context, string) ([]string, error) { return nil, errors.New("test resolver failure") }
	result, err := fetchDNSAndMTASTSRecords("example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.DNSRecords, "presence unknown") || !strings.Contains(result.MTASTSRecords, "presence unknown") {
		t.Fatal("failure misreported as missing")
	}
}

func TestEmptyAnswerDoesNotIndexMissingTXT(t *testing.T) {
	original := lookupTXT
	defer func() { lookupTXT = original }()
	lookupTXT = func(context.Context, string) ([]string, error) { return []string{}, nil }
	result, err := fetchDNSAndMTASTSRecords("example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.DNSRecords, "No matching TXT record") {
		t.Fatal("empty answer not reported")
	}
}
