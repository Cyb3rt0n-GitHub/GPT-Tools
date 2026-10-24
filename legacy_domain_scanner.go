package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Set the path to the input and output files
const (
	inputFilePath     = "domains.txt"
	outputFilePath    = "domain_results.txt"
	sslscanOutputFile = "sslscan_results.txt"
	htmlOutputFile    = "domain_results.html"
)

// SSLScanResult holds the SSL scan results and recommendations
type SSLScanResult struct {
	Domain             string
	ScanResults        string
	Recommendations    string
	DNSRecommendations string
	DNSRecords         string
	MTASTSRecords      string
}

// DNSAndMTARecords holds the DNS and MTA-STS records for a domain
type DNSAndMTARecords struct {
	Domain             string
	DNSRecords         string
	MTASTSRecords      string
	DNSRecommendations string
}

// Function to perform SSL scan and return the results as a string
func performSSLScan(domain string) (string, error) {
	fmt.Printf("\033[1mScanning %s...\033[0m\n", domain)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sslscan", "--no-colour", domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("\033[1mERROR: %s\033[0m\n", err)
		return string(output), err
	}
	fmt.Printf("\033[1m%s SSL scan completed.\033[0m\n", domain)
	return string(output), nil
}

var lookupTXT = net.DefaultResolver.LookupTXT

// Function to fetch DNS records and MTA-STS for a domain
func fetchDNSAndMTASTSRecords(domain string) (*DNSAndMTARecords, error) {
	dnsRecordsInfo := ""
	mtaSTSInfo := ""
	for _, q := range []struct{ label, name, prefix string }{
		{"DMARC", "_dmarc." + domain, "v=DMARC1"},
		{"DKIM (default selector only)", "default._domainkey." + domain, ""},
		{"SPF", domain, "v=spf1"},
		{"MTA-STS advertisement", "_mta-sts." + domain, "v=STSv1"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		records, err := lookupTXT(ctx, q.name)
		cancel()
		line := q.label + ": "
		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				line += "No TXT record at queried name\n"
			} else {
				line += "DNS lookup failed; presence unknown\n"
			}
		} else {
			var matching []string
			for _, record := range records {
				first := strings.Split(strings.Split(record, ";")[0], " ")[0]
				match := q.prefix != "" && first == q.prefix
				if q.prefix == "" {
					for _, part := range strings.Split(record, ";") {
						if strings.HasPrefix(strings.TrimSpace(part), "p=") {
							match = true
						}
					}
				}
				if match {
					matching = append(matching, record)
				}
			}
			if len(matching) == 0 {
				line += "No matching TXT record\n"
			} else {
				line += strings.Join(matching, " | ") + "\n"
			}
		}
		if q.prefix == "v=STSv1" {
			mtaSTSInfo = line
		} else {
			dnsRecordsInfo += line
		}
	}

	return &DNSAndMTARecords{
		Domain:             domain,
		DNSRecords:         dnsRecordsInfo,
		MTASTSRecords:      mtaSTSInfo,
		DNSRecommendations: "",
	}, nil
}

func main() {
	// Read domains from file
	domainData, err := os.ReadFile(inputFilePath)
	if err != nil {
		log.Fatal(err)
	}
	domains := strings.Split(string(domainData), "\n")

	// Validate all inputs before creating output or making network requests.
	var domainsToScan []string
	seen := make(map[string]bool)
	labelPattern := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	for _, line := range domains {
		domain := strings.TrimSuffix(strings.TrimSpace(strings.SplitN(line, "#", 2)[0]), ".")
		domain = strings.ToLower(domain)
		if domain == "" {
			continue
		}
		if len(domain) > 253 {
			log.Fatal("Invalid hostname: ", domain)
		}
		for _, label := range strings.Split(domain, ".") {
			if !labelPattern.MatchString(label) {
				log.Fatal("Invalid hostname: ", domain)
			}
		}
		if !seen[domain] {
			domainsToScan = append(domainsToScan, domain)
			seen[domain] = true
		}
	}
	if len(domainsToScan) == 0 {
		log.Fatal("No domains supplied")
	}
	if _, err := exec.LookPath("sslscan"); err != nil {
		log.Fatal("Install sslscan and ensure it is on PATH")
	}
	// Separate runs, refuse existing directory, and retain raw evidence.
	outputDir := "scan-go-" + time.Now().UTC().Format("20060102T150405.000000000Z")
	if len(os.Args) > 1 {
		outputDir = os.Args[1]
	}
	if err := os.Mkdir(outputDir, 0700); err != nil {
		log.Fatal(err)
	}
	if err := os.Chdir(outputDir); err != nil {
		log.Fatal(err)
	}
	var results []*SSLScanResult
	failed := false
	// Sequential execution avoids the original unbuffered-channel deadlock and bounds load.
	for _, domain := range domainsToScan {
		scan, scanErr := performSSLScan(domain)
		if scanErr != nil {
			failed = true
			scan += "\nSCAN FAILED: " + scanErr.Error()
		}
		dns, _ := fetchDNSAndMTASTSRecords(domain)
		results = append(results, &SSLScanResult{
			Domain: domain, ScanResults: scan, DNSRecords: dns.DNSRecords, MTASTSRecords: dns.MTASTSRecords,
			Recommendations:    "AI commentary not implemented in Go.",
			DNSRecommendations: "AI commentary not implemented in Go.",
		})
	}

	// Create or open output files
	sslOutputFile, err := os.Create(sslscanOutputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer sslOutputFile.Close()

	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		log.Fatal(err)
	}
	defer outputFile.Close()

	htmlOutputFile, err := os.Create(htmlOutputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer htmlOutputFile.Close()

	// Write results to files and generate HTML output
	var sslScanResults []*SSLScanResult
	for _, result := range results {
		// Write SSL scan results to file
		writeString(sslOutputFile, fmt.Sprintf("SSL scan results for %s:\n", result.Domain))
		writeString(sslOutputFile, result.ScanResults)

		// Write DNS and MTA-STS results to output file
		writeString(outputFile, fmt.Sprintf("%s\nDNS Records:\n%s\n%s\n\n",
			result.Domain, result.DNSRecords, result.MTASTSRecords))

		// Prepare the chat payload for DNS records
		writeString(outputFile, fmt.Sprintf("Recommendation (DNS Records):\n%s\n\n", result.DNSRecommendations))

		// Prepare the chat payload for SSL scan results
		if result.Recommendations != "" {
			writeString(outputFile, fmt.Sprintf("Recommendation (SSL scan results):\n%s\n\n", result.Recommendations))
		}

		sslScanResults = append(sslScanResults, result)
	}

	htmlBytes, err := renderHTML(sslScanResults)
	if err != nil {
		log.Fatal(err)
	}

	_, err = htmlOutputFile.Write(htmlBytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Reports saved in", outputDir)
	if failed {
		os.Exit(1)
	}
}

func writeString(file *os.File, value string) {
	if _, err := file.WriteString(value); err != nil {
		log.Fatal(err)
	}
}

func renderHTML(results []*SSLScanResult) ([]byte, error) {
	// Generate the disclaimer
	disclaimer := "<h3>Please Note:</h3><p>Personal prototype: DNS record presence is not policy validation. Only the default DKIM selector is queried; MTA-STS HTTPS policy is not checked. This Go version makes no AI calls.</p>"

	// Generate the complete HTML content
	var htmlContent bytes.Buffer
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
<title>Domain Results</title>
</head>
<body>
<h1>SSL and DNS Security Scans - Legacy domain scanner</h1>
{{range .Results}}
<h2>{{.Domain}}</h2>
<h3>SSL scan results:</h3>
<pre>{{.ScanResults}}</pre>
{{if .Recommendations}}
<h3>Recommendations for improvement (SSL scan results):</h3>
<pre>{{.Recommendations}}</pre>
{{end}}
<h3>DNS Records:</h3>
<pre>{{.DNSRecords}}</pre>
<h3>MTA-STS Records:</h3>
<pre>{{.MTASTSRecords}}</pre>
<h3>Recommendations for improvement (DNS Records):</h3>
<pre>{{.DNSRecommendations}}</pre>
{{end}}
{{.Disclaimer}}
</body>
</html>
`
	tmpl, err := template.New("html").Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}

	// Execute the template with data and write to HTML file
	htmlData := struct {
		Results    []*SSLScanResult
		Disclaimer template.HTML
	}{
		Results:    results,
		Disclaimer: template.HTML(disclaimer),
	}

	err = tmpl.Execute(&htmlContent, htmlData)
	if err != nil {
		return nil, err
	}

	return htmlContent.Bytes(), nil
}
