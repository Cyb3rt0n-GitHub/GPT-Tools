# GPT-Tools

Below is the detailed description for the Python SecureScanBot script:

    Purpose:
    The script is designed to perform SSL scans and fetch DNS records and MTA-STS (Mail Transfer Agent Strict Transport Security) records for a list of domains specified in the domains.txt file. Additionally, the script generates recommendations for improving SSL scan results and DNS records using the GPT-3.5 Turbo API provided by OpenAI.

    The provided Python script requires two external dependencies: sslscan and aha.

    sslscan:
    sslscan is an external command-line tool used for performing SSL scans on domains. It helps identify SSL/TLS vulnerabilities and cipher suites supported by a server. The script calls sslscan using the subprocess module to perform the SSL scans. To use sslscan, you need to have it installed and accessible in your system's PATH. You can find more information and download the tool from its official website or the respective package manager for your operating system.
        Official website: https://github.com/rbsec/sslscan

    aha:
    aha is another external command-line tool used for converting text-based ANSI color output to HTML. In the script, it is used to convert the SSL scan results to an HTML report. Similar to sslscan, you need to have aha installed and accessible in your system's PATH. You can find more information and download the tool from its official website or the respective package manager for your operating system.
        Official website: https://github.com/theZiz/aha

Before running the Python script, make sure both sslscan and aha are installed and accessible from the command line. You can verify their availability by opening a terminal or command prompt and typing sslscan --version and aha --version. If the commands are recognized, you are good to go.

If you have any trouble installing or using sslscan or aha, refer to their respective documentation or seek help from your system administrator or online resources.

    Setup:
        Before running the script, ensure you have Python installed on your computer.
        Replace "INSERT_API_KEY_HERE" with your actual GPT-3.5 API key in the api_key variable.
        Create an input file named domains.txt in the same directory as the script. Add the list of domains you want to scan, with each domain on a separate line.

    Dependencies:
        The script uses the subprocess, dns.resolver, and requests modules from Python's standard library.
        The aha command-line tool is used for converting the SSL scan results to HTML. Ensure it is installed and accessible in your environment.

    Functions:
        truncate_text(text, token_limit): A helper function to truncate text to fit within the GPT-3.5 API token limit of 4096 tokens.
        split_text_into_chunks(text, chunk_size): A helper function to split text into chunks, but it is not currently used in the main script.
        perform_ssl_scan(domain): Function to perform SSL scans using the external sslscan tool. The scan results are returned as a string.
        fetch_dns_and_mta_sts_records(domain): Function to fetch DNS records and MTA-STS records for a domain. The DNS records are queried using the dns.resolver module.
        generate_sslscan_recommendations(ssl_scan_results): Function to generate SSL scan recommendations using the GPT-3.5 Turbo API. It sends the SSL scan results as input to the API and receives the generated recommendations.

    Banner:
    The script starts with an ASCII art banner displaying "SecureScanBot" and some creative text. This is for aesthetic purposes and can be customized as needed.

    Main Execution:
    The script starts by reading the list of domains from the domains.txt file and stores them in the domains variable.

    It then performs SSL scans for each domain in the list, writes the scan results to the sslscan_results.txt file, and converts the scan results to an HTML file named sslscan_results.html using the aha command.

    For each domain, it queries DNS records and MTA-STS records and writes the results to the domain_results.txt file. It also generates recommendations for DNS records using the GPT-3.5 API and saves them to the output file.

    Additionally, it generates recommendations for SSL scan results using the GPT-3.5 API and appends the HTML content for SSL scan results to the domain_results.html file.

    Disclaimer:
    The script adds a disclaimer to the domain_results.html file, indicating that the observations and recommendations are generated by OpenAI and may not be accurate, so they should be reviewed by someone knowledgeable in the field.

    Usage:
    To use the script, follow the instructions mentioned earlier. Execute the script in the terminal or command prompt, and it will process the domains, perform the scans, fetch DNS records, generate recommendations, and create the final HTML report.
