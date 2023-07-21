import subprocess
import dns.resolver
import requests

# Set the path to the input and output files
input_file_path = "domains.txt"
output_file_path = "domain_results.txt"
sslscan_output_file = "sslscan_results.txt"

# Define the GPT-3.5 API key and headers
api_key = "INSERT_API_KEY_HERE"  # Replace this with your actual GPT-3.5 API key
headers = {"Authorization": f"Bearer {api_key}"}

# Function to truncate text to fit within API token limit
def truncate_text(text, token_limit):
    tokens = text.split(" ")
    if len(tokens) > token_limit:
        truncated_text = " ".join(tokens[:token_limit-1])  # Subtract 1 to leave space for "..."
        return truncated_text + "..."
    return text

# Function to split text into chunks
def split_text_into_chunks(text, chunk_size=4096):
    chunks = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]
    return chunks

# Function to perform SSL scan and return the results as a string
def perform_ssl_scan(domain):
    print(f"\033[1mScanning {domain}...\033[0m")
    try:
        result = subprocess.run(["sslscan", "-color", domain], capture_output=True, text=True, check=True)
        ssl_scan_results = result.stdout
        print(f"\033[1m{domain} SSL scan completed.\033[0m")
        return ssl_scan_results
    except subprocess.CalledProcessError as e:
        print(f"\033[1mERROR: {e}\033[0m")
        return ""

# Function to fetch DNS records and MTA-STS for a domain
def fetch_dns_and_mta_sts_records(domain):
    dns_records_info = ""
    mta_sts_info = ""

    try:
        # Query for DMARC record
        dmarc_record = dns.resolver.resolve("_dmarc." + domain, "TXT")
        dns_records_info += f"DMARC: {str(dmarc_record.response.answer[0][0])}\n"
    except dns.resolver.NXDOMAIN:
        dns_records_info += "DMARC: No DMARC record found\n"

    try:
        # Query for DKIM record
        dkim_record = dns.resolver.resolve("default._domainkey." + domain, "TXT")
        dns_records_info += f"DKIM: {str(dkim_record.response.answer[0][0])}\n"
    except dns.resolver.NXDOMAIN:
        dns_records_info += "DKIM: No DKIM record found\n"
    except dns.resolver.NoAnswer:
        dns_records_info += "DKIM: No DKIM record found\n"

    try:
        # Query for SPF record
        spf_record = dns.resolver.resolve(domain, "TXT")
        for record in spf_record.response.answer:
            if "v=spf1" in str(record[0]):
                dns_records_info += f"SPF: {str(record[0])}\n"
                break
        else:
            dns_records_info += "SPF: No SPF record found\n"
    except dns.resolver.NoAnswer:
        dns_records_info += "SPF: No SPF record found\n"

    try:
        # Fetch MTA-STS record using DNS resolver
        mta_sts_response = dns.resolver.resolve("_mta-sts." + domain, "TXT")
        mta_sts_records = [rdata.to_text().strip('\"') for rdata in mta_sts_response]
        if mta_sts_records:
            mta_sts_info = "\n".join(f"MTA-STS: {record}" for record in mta_sts_records)
        else:
            mta_sts_info = "MTA-STS: No MTA-STS record found\n"
    except dns.resolver.NXDOMAIN:
        mta_sts_info = "MTA-STS: No MTA-STS record found\n"
    except dns.resolver.NoAnswer:
        mta_sts_info = "MTA-STS: No MTA-STS record found\n"

    return dns_records_info, mta_sts_info

# Function to generate SSL scan recommendations using GPT-3.5 Turbo
def generate_sslscan_recommendations(ssl_scan_results):
    print(f"\033[1mGenerating SSL scan recommendations...\033[0m")
    truncated_ssl_scan_results = truncate_text(ssl_scan_results, 4096)

    chat_payload_ssl = {
        "messages": [
            {"role": "system", "content": "You are a Developer"},
            {"role": "user", "content": f"make recommendations for improvement:\n{truncated_ssl_scan_results}\n\nAny suggestions to improve the SSL scan results?"}
        ],
        "model": "gpt-3.5-turbo"
    }

    response_ssl = requests.post("https://api.openai.com/v1/chat/completions", json=chat_payload_ssl, headers=headers)

    if response_ssl.status_code == 200:
        response_data_ssl = response_ssl.json()
        recommendation_ssl = response_data_ssl["choices"][0]["message"]["content"]
        print(f"\033[1mRecommendations for improvement (SSL scan results):\033[0m")
        print(f"Recommendation:\n{recommendation_ssl}")
        return recommendation_ssl
    else:
        print(f"\033[1mError sending SSL scan data to the API:\033[0m")
        print(response_ssl.text)
        return ""

# Banner
banner = '''
███████ ███████  ██████ ██    ██ ██████  ███████       ███████  ██████  █████  ███    ██       ██████   ██████  ████████
██      ██      ██      ██    ██ ██   ██ ██            ██      ██      ██   ██ ████   ██       ██   ██ ██    ██    ██
███████ █████   ██      ██    ██ ██████  █████   █████ ███████ ██      ███████ ██ ██  ██ █████ ██████  ██    ██    ██
     ██ ██      ██      ██    ██ ██   ██ ██                 ██ ██      ██   ██ ██  ██ ██       ██   ██ ██    ██    ██
███████ ███████  ██████  ██████  ██   ██ ███████       ███████  ██████ ██   ██ ██   ████       ██████   ██████     ██


SSL and DNS Security Scans - Powered by SecureScanBot
			   - Created by Cyb3rt0n
			   - Beloved by ALL	
			   
'''

print(banner)

# Read domains from file
with open(input_file_path, "r") as f:
    domains = f.read().splitlines()

# Perform SSL scan and write results to a file
with open(sslscan_output_file, "w") as ssl_output_file:
    for domain in domains:
        ssl_scan_results = perform_ssl_scan(domain)
        ssl_output_file.write(f"SSL scan results for {domain}:\n")
        ssl_output_file.write(f"{ssl_scan_results}\n")
        ssl_output_file.write("=" * 50 + "\n")

# Convert the SSL scan results to HTML
html_output_file = "sslscan_results.html"
aha_command = f"aha -f {sslscan_output_file} > {html_output_file}"
try:
    subprocess.run(aha_command, shell=True, check=True)
except subprocess.CalledProcessError as e:
    print(f"\033[1mError converting SSLScan results to HTML: {e}\033[0m")
    exit(1)

# Loop over each domain and query DNS records and perform MTA-STS check
for domain in domains:
    domain = domain.strip()

    if not domain:
        continue  # Skip empty domain names

    # Create the output file for the current domain
    with open(output_file_path, "a") as output_file, open("domain_results.html", "a") as html_output_file:
        # Query for DNS records and MTA-STS
        print(f"\033[1mQuerying DNS records and MTA-STS for {domain}...\033[0m")
        dns_records_info, mta_sts_info = fetch_dns_and_mta_sts_records(domain)

        # Write the results to the output file
        output_file.write(f"{domain}\n")
        output_file.write(f"DNS Records:\n{dns_records_info}\n")
        output_file.write(f"{mta_sts_info}\n\n")

        # Prepare the chat payload for DNS records
        truncated_dns_records_info = truncate_text(dns_records_info, 4096)
        chat_payload_dns = {
            "messages": [
                {"role": "system", "content": "You are a Developer"},
                {"role": "user", "content": ""}
            ],
            "model": "gpt-3.5-turbo"
        }

        # Make the API request for DNS records
        chat_payload_dns["messages"][1]["content"] = f"make recommendations for improvement:\n{truncated_dns_records_info}\n\nAny suggestions to improve the DNS records?"
        response_dns = requests.post("https://api.openai.com/v1/chat/completions", json=chat_payload_dns, headers=headers)

        # Parse the response for DNS records
        if response_dns.status_code == 200:
            response_data_dns = response_dns.json()
            recommendation_dns = response_data_dns["choices"][0]["message"]["content"]
            print(f"\033[1mRecommendations for improvement for {domain} (DNS Records):\033[0m")
            print(f"Recommendation:\n{recommendation_dns}")
            output_file.write(f"Recommendation (DNS Records):\n{recommendation_dns}\n\n")
        else:
            print(f"\033[1mError sending DNS record data to the API for {domain}:\033[0m")
            print(response_dns.text)

        # Prepare the chat payload for SSL scan results
        recommendation_ssl = generate_sslscan_recommendations(ssl_scan_results)
        if recommendation_ssl:
            output_file.write(f"Recommendation (SSL scan results):\n{recommendation_ssl}\n\n")

        # Write the HTML output for each domain
        html_output_file.write(f"<h2>{domain}</h2>")
        html_output_file.write("<h3>DNS Records:</h3>")
        html_output_file.write("<pre>" + truncated_dns_records_info + "</pre>")
        html_output_file.write("<h3>MTA-STS Records:</h3>")
        html_output_file.write("<pre>" + mta_sts_info + "</pre>")
        html_output_file.write("<h3>Recommendations for improvement (DNS Records):</h3>")
        html_output_file.write("<pre>" + recommendation_dns + "</pre>")
        if recommendation_ssl:
            html_output_file.write("<h3>Recommendations for improvement (SSL scan results):</h3>")
            html_output_file.write("<pre>" + recommendation_ssl + "</pre>")

# Append the HTML content for SSL scan results to domain_results.html
with open("sslscan_results.html", "r") as sslscan_html_file, open("domain_results.html", "a") as html_output_file:
    html_content = sslscan_html_file.read()
    html_output_file.write(html_content)

# Add the disclaimer
with open("domain_results.html", "a") as html_output_file:
    html_output_file.write("<h3>Please Note:</h3>")
    html_output_file.write("<p>The observations and recommendations have been generated by OpenAI and may not be correct, therefore they should be reviewed by someone knowledgeable in the field.</p>")
