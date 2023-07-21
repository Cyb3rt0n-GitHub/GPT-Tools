package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Set the path to the input and output files
const (
	inputFilePath    = "domains.txt"
	outputFilePath   = "domain_results.txt"
	sslscanOutputFile = "sslscan_results.txt"
	htmlOutputFile   = "domain_results.html"
)

// Define the GPT-3.5 API key and endpoint
const (
	apiKey   = "INSERT_API_KEY_HERE" // Replace this with your actual GPT-3.5 API key
	endpoint = "https://api.openai.com/v1/chat/completions"
)

// SSLScanResult holds the SSL scan results and recommendations
type SSLScanResult struct {
	Domain          string
	ScanResults     string
	Recommendations string
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
	cmd := exec.Command("sslscan", "-color", domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("\033[1mERROR: %s\033[0m\n", err)
		return "", err
	}
	fmt.Printf("\033[1m%s SSL scan completed.\033[0m\n", domain)
	return string(output), nil
}

// Function to fetch DNS records and MTA-STS for a domain
func fetchDNSAndMTASTSRecords(domain string) (*DNSAndMTARecords, error) {
	dnsRecordsInfo := ""
	mtaSTSInfo := ""

	// Query for DMARC record
	dmarcRecord, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		dnsRecordsInfo += "DMARC: No DMARC record found\n"
	} else {
		dnsRecordsInfo += fmt.Sprintf("DMARC: %s\n", dmarcRecord[0])
	}

	// Query for DKIM record
	dkimRecord, err := net.LookupTXT("default._domainkey." + domain)
	if err != nil {
		dnsRecordsInfo += "DKIM: No DKIM record found\n"
	} else {
		dnsRecordsInfo += fmt.Sprintf("DKIM: %s\n", dkimRecord[0])
	}

	// Query for SPF record
	spfRecord, err := net.LookupTXT(domain)
	if err != nil {
		dnsRecordsInfo += "SPF: No SPF record found\n"
	} else {
		for _, record := range spfRecord {
			if strings.Contains(record, "v=spf1") {
				dnsRecordsInfo += fmt.Sprintf("SPF: %s\n", record)
				break
			}
		}
	}

	// Fetch MTA-STS record using net.LookupTXT
	mtaSTSRecords, err := net.LookupTXT("_mta-sts." + domain)
	if err != nil {
		mtaSTSInfo = "MTA-STS: No MTA-STS record found\n"
	} else {
		mtaSTSInfo = fmt.Sprintf("MTA-STS: %s\n", strings.Join(mtaSTSRecords, "\n"))
	}

	return &DNSAndMTARecords{
		Domain:             domain,
		DNSRecords:         dnsRecordsInfo,
		MTASTSRecords:      mtaSTSInfo,
		DNSRecommendations: "",
	}, nil
}

// Function to generate SSL scan recommendations using GPT-3.5 Turbo
func generateSSLScanRecommendations(sslScanResults string) (string, error) {
	fmt.Printf("\033[1mGenerating SSL scan recommendations...\033[0m\n")
	// Placeholder API call to generate recommendations (example)
	return "SSL scan recommendation example", nil
}

// Function to generate DNS records recommendations using GPT-3.5 Turbo
func generateDNSRecommendations(dnsRecordsInfo string) (string, error) {
	fmt.Printf("\033[1mGenerating DNS records recommendations...\033[0m\n")
	// Placeholder API call to generate recommendations (example)
	return "DNS records recommendation example", nil
}

func main() {
	// Read domains from file
	domainData, err := ioutil.ReadFile(inputFilePath)
	if err != nil {
		log.Fatal(err)
	}
	domains := strings.Split(string(domainData), "\n")

	// Perform SSL scan and fetch DNS/MTA records concurrently
	var wg sync.WaitGroup
	resultsChan := make(chan *SSLScanResult)

	for _, domain := range domains {
		domain = strings.TrimSpace(domain)

		if domain == "" {
			continue // Skip empty domain names
		}

		wg.Add(1)
		go func(domain string) {
			defer wg.Done()

			sslScanResults, err := performSSLScan(domain)
			if err != nil {
				return
			}

			// Fetch DNS records and MTA-STS for the domain
			fmt.Printf("\033[1mQuerying DNS records and MTA-STS for %s...\033[0m\n", domain)
			dnsMTAResults, err := fetchDNSAndMTASTSRecords(domain)
			if err != nil {
				return
			}

			// Generate SSL scan recommendations
			recommendations, err := generateSSLScanRecommendations(sslScanResults)
			if err != nil {
				return
			}
			sslScanResults := &SSLScanResult{
				Domain:          domain,
				ScanResults:     sslScanResults,
				Recommendations: recommendations,
			}

			// Generate DNS records recommendations
			dnsRecommendations, err := generateDNSRecommendations(dnsMTAResults.DNSRecords)
			if err != nil {
				return
			}
			dnsMTAResults.DNSRecommendations = dnsRecommendations

			resultsChan <- sslScanResults
		}(domain)
	}

	// Wait for all goroutines to finish
	wg.Wait()
	close(resultsChan)

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
	for result := range resultsChan {
		// Write SSL scan results to file
		sslOutputFile.WriteString(fmt.Sprintf("SSL scan results for %s:\n", result.Domain))
		sslOutputFile.WriteString(result.ScanResults)
		sslOutputFile.WriteString(strings.Repeat("=", 50) + "\n")

		// Write DNS and MTA-STS results to output file
		outputFile.WriteString(fmt.Sprintf("%s\nDNS Records:\n%s\n%s\n\n",
			result.Domain, dnsMTAResults.DNSRecords, dnsMTAResults.MTASTSRecords))

		// Prepare the chat payload for DNS records
		outputFile.WriteString(fmt.Sprintf("Recommendation (DNS Records):\n%s\n\n", dnsMTAResults.DNSRecommendations))

		// Prepare the chat payload for SSL scan results
		if result.Recommendations != "" {
			outputFile.WriteString(fmt.Sprintf("Recommendation (SSL scan results):\n%s\n\n", result.Recommendations))
		}

		sslScanResults = append(sslScanResults, result)
	}

	// Generate the disclaimer
	disclaimer := "<h3>Please Note:</h3><p>The observations and recommendations have been generated by OpenAI and may not be correct, therefore they should be reviewed by someone knowledgeable in the field.</p>"

	// Generate the complete HTML content
	var htmlContent bytes.Buffer
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
<title>Domain Results</title>
</head>
<body>
<h1>SSL and DNS Security Scans - Powered by SecureScanBot</h1>
{{range .}}
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
		log.Fatal(err)
	}

	// Execute the template with data and write to HTML file
	htmlData := struct {
		Results    []*SSLScanResult
		Disclaimer template.HTML
	}{
		Results:    sslScanResults,
		Disclaimer: template.HTML(disclaimer),
	}

	err = tmpl.Execute(&htmlContent, htmlData)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(htmlOutputFile, htmlContent.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("All scans and data processing completed.")
}
