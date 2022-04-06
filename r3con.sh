#!/bin/bash
#thenurhabib

# Import Config file
. ./config.cfg

actualDir=$(pwd)

clear
clear
pwd
echo "Bash : ${BASH_VERSION}"

# passive Recon Function
passiveReconFunction(){
    echo -e "${BOLD}${GREEN}[*] Scan Started...${NORMAL}\n\n"
    echo -e "${BOLD}${GREEN}[*] Domain Name : ${YELLOW} $domain ${NORMAL}\n"
    ipaddress=$(dig +short $domain)
    echo -e "${BOLD}${GREEN}[*] IP Adress : ${YELLOW} $ipaddress ${NORMAL}\n\n"
    
    domain=$1
    domainName="https://"$domain
    company=$(echo -e $domain | awk -F[.] '{print $1}')
    
    cd targets
    
    if [ -d $domain ]; then rm -Rf $domain; fi
    mkdir $domain
    
    cd $domain
    
    if [ -d footprinting ]; then rm -Rf footprinting; fi
    mkdir footprinting
    
    cd footprinting
    
    echo -e "${GREEN}[+] Checking target is up or down...${NORMAL}\n"
    if ping -c 1 -W 1 "$domain" &> /dev/null;
    then
        echo -e "\n${BOLD}${YELLOW}$domain${NORMAL} is up!${NORMAL}\n\n"
    else
        if [ $mode == "more" ]
        then
            echo -e "\n${BOLD}${YELLOW}$domain${RED} is not up.${NORMAL}\n\n"
            return
        else
            echo -e "\n${BOLD}${YELLOW}$domain${RED} is not up. Skipping passive reconnaissance${NORMAL}\n\n"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}[+] Whois Lookup${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching domain name details, contact details of domain owner, domain name servers, netRange, domain dates, expiry records, records last updated...${NORMAL}\n\n"
    whois $domain | grep 'Domain\|Registry\|Registrar\|Updated\|Creation\|Registrant\|Name Server\|DNSSEC:\|Status\|Whois Server\|Admin\|Tech' | grep -v 'the Data in VeriSign Global Registry' | tee whois.txt
    
    echo -e "\n${GREEN}[+] Nslookup ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching DNS Queries...${NORMAL}\n\n"
    nslookup $domain | tee nslookup.txt
    
    echo -e "\n${GREEN}[+] Horizontal domain correlation/acquisitions ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching horizontal domains...${NORMAL}\n\n"
    email=$(whois $domain | grep "Registrant Email" | egrep -ho "[[:graph:]]+@[[:graph:]]+")
    curl -s -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36" "https://viewdns.info/reversewhois/?q=$email" | html2text | grep -Po "[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)" | tail -n +4  | head -n -1
    
    echo -e "\n${GREEN}[+] ASN Lookup ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching ASN number of a company that owns the domain...${NORMAL}\n\n"
    python3 ~/tools/Asnlookup/asnlookup.py -o $company | tee -a asn.txt
    
    echo -e "\n${GREEN}[+] WhatWeb ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching platform, type of script, google analytics, web server platform, IP address, country, server headers, cookies...${NORMAL}\n\n"
    whatweb $domain | tee whatweb.txt
    
    echo -e "\n${GREEN}[+] SSL Checker ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Collecting SSL/TLS information...${NORMAL}\n\n"
    python3 ~/tools/ssl-checker/ssl_checker.py -H $domainName | tee ssl.txt
    
    echo -e "\n${GREEN}[+] Aquatone ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Taking screenshot...${NORMAL}\n\n"
    echo -e $domainName | aquatone -screenshot-timeout $aquatoneTimeout -out screenshot &> /dev/null
    
    echo -e "\n${GREEN}[+] TheHarvester ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching emails, subdomains, hosts, employee names...${NORMAL}\n\n"
    python3 ~/tools/theHarvester/theHarvester.py -d $domain -b all -l 500 -f theharvester.html > theharvester.txt
    echo -e "${NORMAL}${CYAN}Users found: ${NORMAL}\n\n"
    cat theharvester.txt | awk '/Users/,/IPs/' | sed -e '1,2d' | head -n -2 | anew -q users.txt
    cat users.txt
    echo -e "${NORMAL}${CYAN}IP's found: ${NORMAL}\n\n"
    cat theharvester.txt | awk '/IPs/,/Emails/' | sed -e '1,2d' | head -n -2 | anew -q ips.txt
    cat ips.txt
    echo -e "${NORMAL}${CYAN}Emails found: ${NORMAL}\n\n"
    cat theharvester.txt | awk '/Emails/,/Hosts/' | sed -e '1,2d' | head -n -2 | anew -q emails.txt
    cat emails.txt
    echo -e "${NORMAL}${CYAN}Hosts found: ${NORMAL}\n\n"
    cat theharvester.txt | awk '/Hosts/,/Trello/' | sed -e '1,2d' | head -n -2 | anew -q hosts.txt
    cat hosts.txt
    
    echo -e "\n${GREEN}[+] CloudEnum ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching public resources in AWS, Azure, and Google Cloud....${NORMAL}\n\n"
    key=$(echo -e $domain | sed s/".com"//)
    python3 ~/tools/cloud_enum/cloud_enum.py -k $key --quickscan | tee cloud.txt
    
    echo -e "\n${GREEN}[+] GitDorker ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching interesting data on GitHub...${NORMAL}\n\n"
    domainName="https://"$domain
    python3 ~/tools/GitDorker/GitDorker.py -t $github_token -d ~/tools/GitDorker/Dorks/alldorksv3 -q $domain -o dorks.txt
    
    if [ "$2" = true ];
    then
        echo -e "\n${GREEN}[+] Whois results: ${NORMAL}\n" | notify -silent | cat whois.txt | notify -silent
        echo -e "\n${GREEN}[+] Nslookup results: ${NORMAL}\n" | notify -silent | cat nslookup.txt | notify -silent
        echo -e "\n${GREEN}[+] ASN Lookup results: ${NORMAL}\n" | notify -silent | cat asn.txt | notify -silent
        echo -e "\n${GREEN}[+] WhatWeb results: ${NORMAL}\n" | notify -silent | cat whatweb.txt | notify -silent
        echo -e "\n${GREEN}[+] SSL Checker results: ${NORMAL}\n" | notify -silent | cat ssl.txt | notify -silent
        echo -e "\n${GREEN}[+] TheHarvester users results: ${NORMAL}\n" | notify -silent | cat users.txt | notify -silent
        echo -e "\n${GREEN}[+] TheHarvester ips results: ${NORMAL}\n" | notify -silent | cat ips.txt | notify -silent
        echo -e "\n${GREEN}[+] TheHarvester emails results: ${NORMAL}\n" | notify -silent | cat emails.txt | notify -silent
        echo -e "\n${GREEN}[+] TheHarvester hosts results: ${NORMAL}\n" | notify -silent | cat hosts.txt | notify -silent
        echo -e "\n${GREEN}[+] CloudEnum results: ${NORMAL}\n" | notify -silent | cat cloud.txt | notify -silent
        echo -e "\n${GREEN}[+] GitDorker results: ${NORMAL}\n" | notify -silent | cat dorks.txt | notify -silent
        
    fi
    
    cd $actualDir
}

# active Recon Function
activeReconFunction(){
    echo -e "${BOLD}${GREEN}[*] Starting scaning${NORMAL}\n\n"
    echo -e "${BOLD}${GREEN}[*] Domain Name : ${YELLOW} $domain ${NORMAL}\n"
    ipaddress=$(dig +short $domain)
    echo -e "${BOLD}${GREEN}[*] IP Adress : ${YELLOW} $ipaddress ${NORMAL}\n\n"
    
    domain=$1
    domainName="https://"$domain
    
    cd targets
    
    if [ -d $domain ]; then rm -Rf $domain; fi
    mkdir $domain
    
    cd $domain
    
    if [ -d fingerprinting ]; then rm -Rf fingerprinting; fi
    mkdir fingerprinting
    
    cd fingerprinting
    
    echo -e "\n${GREEN}[+] Robots.txt ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Checking directories and files from robots.txt...${NORMAL}\n\n"
    python3 ~/tools/robotScraper/robotScraper.py -d $domain -s outputrobots.txt
    
    echo -e "\n${GREEN}[+] Hakrawler & gau ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Gathering URLs and JavaSript file locations...${NORMAL}\n\n"
    echo -e $domainName | hakrawler | tee -a paths.txt
    gau $domain >> paths.txt
    sort -u paths.txt -o paths.txt
    
    echo -e "\n${GREEN}[+] Arjun ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Finding query parameters for URL endpoints....${NORMAL}\n\n"
    arjun -u $domainName -oT parameters.txt
    
    echo -e "\n${GREEN}[+] Vulnerability: Secrets in JS${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Obtaining all the JavaScript files of the domain ...${NORMAL}\n\n"
    echo -e $domain | gau | grep '\.js$' | httpx -mc 200 -content-type -silent | grep 'application/javascript' | awk -F '[' '{print $1}' | tee -a js.txt
    echo -e "\n${NORMAL}${CYAN}Discovering sensitive data like apikeys, accesstoken, authorizations, jwt, etc in JavaScript files...${NORMAL}\n\n"
    for url in $(cat js.txt);do
        python3 ~/tools/SecretFinder/SecretFinder.py --input $url -o cli | tee -a secrefinder.txt
    done
    
    echo -e "\n${GREEN}[+] DirSearch ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching interesting directories and files...${NORMAL}\n\n"
    sudo dirsearch -u $domain --deep-recursive --random-agent --exclude-status $excludeStatus -w $dictionary -o dirsearch
    
    echo -e "\n${GREEN}[+] Nmap ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching open ports...${NORMAL}\n\n"
    nmap -p- --open -T5 -v -n $domain -oN nmap.txt
    
    if [ "$2" = true ];
    then
        echo -e "\n${GREEN}[+] Robots.txt results: ${NORMAL}\n" | notify -silent | cat outputrobots.txt | notify -silent
        echo -e "\n${GREEN}[+] Hakrawler & gau results: ${NORMAL}\n" | notify -silent | cat paths.txt | notify -silent
        echo -e "\n${GREEN}[+] Arjun results: ${NORMAL}\n" | notify -silent | cat parameters.txt | notify -silent
        echo -e "\n${GREEN}[+] Secrets in JS results: ${NORMAL}\n" | notify -silent | cat secrefinder.txt | notify -silent
        echo -e "\n${GREEN}[+] Dirsearch results: ${NORMAL}\n" | notify -silent | cat dirsearch | notify -silent
        echo -e "\n${GREEN}[+] Nmap results: ${NORMAL}\n" | notify -silent | cat nmap.txt | notify -silent
    fi
    
    cd $actualDir
}


all(){
    passiveReconFunction $domain
    activeReconFunction $domain
    vulnerabilities $domain
}


# Full Recon Function
fullReconFunction(){
    passiveReconFunction
    activeReconFunction
}

# Massive Recon Function
massiveReconFunction(){
    echo -e "${BOLD}${GREEN}[*] Starting massive vulnerability analysis${NORMAL}\n\n"
    echo -e "${BOLD}${GREEN}[*] Wildcard:${YELLOW} *.$wildcard ${NORMAL}\n"
    
    if [ -d automatedRecon ];
    then
        rm -Rf automatedRecon;
    fi
    
    mkdir automatedRecon
    cd automatedRecon
    
    while true;
    do
        subfinder -d $wildcard | anew subdomains.txt | httpx | nuclei -t ~/tools/nuclei-templates/ | notify ; sleep $massiveTime;
        echo -e "${NORMAL}${CYAN}[+] The vulnerabilities found have been notified. Waiting $massiveTime seconds for the new scan.${NORMAL}\n\n"
    done
    
    cd $actualDir
}


# Starting vulnerability scan
vulnerabilities(){
    echo -e "${BOLD}${GREEN}[*] Starting vulnerability scan${NORMAL}\n\n"
    echo -e "${BOLD}${GREEN}[*] Domain Name : ${YELLOW} $domain ${NORMAL}\n"
    ipaddress=$(dig +short $domain)
    echo -e "${BOLD}${GREEN}[*] IP Adress : ${YELLOW} $ipaddress ${NORMAL}\n\n"
    
    domain=$1
    domainName="https://"$domain
    
    cd targets
    
    if [ -d $domain ]; then rm -Rf $domain; fi
    mkdir domain
    
    cd domain
    
    if [ -d vulnerabilities ]; then rm -Rf vulnerabilities; fi
    mkdir vulnerabilities
    
    cd vulnerabilities
    
    echo -e "\n${GREEN}[+] Vulnerability: Missing headers${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Cheking security headers...${NORMAL}\n\n"
    python3 ~/tools/shcheck/shcheck.py $domainName | tee headers.txt | grep 'Missing security header:\|There are\|--'
    
    echo -e "\n${GREEN}[+] Vulnerability: Email spoofing ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Cheking SPF and DMARC record...${NORMAL}\n\n"
    mailspoof -d $domain | tee spoof.json
    
    echo -e "\n${GREEN}[+] Vulnerability: Subdomain takeover ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Checking if sub-domain is pointing to a service that has been removed or deleted...${NORMAL}\n\n"
    subjack -d $domain -ssl -v | tee takeover.txt
    
    echo -e "\n${GREEN}[+] Vulnerability: CORS${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Checking all known misconfigurations in CORS implementations...${NORMAL}\n\n"
    python3 ~/tools/Corsy/corsy.py -u $domainName | tee cors.txt
    
    echo -e "\n${GREEN}[+] Vulnerability: 403 bypass${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Gathering endpoints that they return 403 status code...${NORMAL}\n\n"
    touch endpoints403.txt
    saveUoutputFile=$actualDir"/targets/"$domain"/vulnerabilities/endpoints403.txt"
    sudo dirsearch -u $domainName --random-agent --include-status 403 -w $dictionary --format plain -o $saveUoutputFile
    echo -e "\n${NORMAL}${CYAN}Trying to bypass 403 status code...${NORMAL}\n\n"
    for url in $(cat endpoints403.txt);
    do
        domainAWK=$domain":443"
        endpoint=$(echo -e $url | awk -F $domainAWK '{print $2}')
        if [ -n "$endpoint" ]
        then
            python3 ~/tools/403bypass/4xx.py $domainName $endpoint | tee -a bypass403.txt
        fi
    done
    
    echo -e "\n${GREEN}[+] Vulnerability:  Cross Site Request Forgery (CSRF/XSRF)${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Checking all known misconfigurations in CSRF/XSRF implementations...${NORMAL}\n\n"
    python3 ~/tools/Bolt/bolt.py -u $domainName -l 2 | tee -a csrf.txt
    
    echo -e "\n${GREEN}[+] Vulnerability: Open Redirect${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Finding Open redirect entry points in the domain...${NORMAL}\n\n"
    gau $domain | gf redirect archive | qsreplace | tee orURLs.txt
    echo -e "\n"
    echo -e "${NORMAL}${CYAN}Checking if the entry points are vulnerable...${NORMAL}\n\n"
    cat orURLs.txt | qsreplace "https://google.com" | httpx -silent -status-code -location
    cat orURLs.txt | qsreplace "//google.com/" | httpx -silent -status-code -location
    cat orURLs.txt | qsreplace "//\google.com" | httpx -silent -status-code -location
    
    echo -e "\n${GREEN}[+] Vulnerability: SSRF${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Trying to find SSRF vulnerabilities...${NORMAL}\n\n"
    echo -e "${RED}[!] Remember to enter your Burp Collaborator link in the configuration.cfg file \n\n${NORMAL}"
    findomain -t $domain | httpx -silent -threads 1000 | gau |  grep "=" | qsreplace $burpCollaborator | tee -a ssrf.txt
    
    echo -e "\n${GREEN}[+] Vulnerability: XSS${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Trying to find XSS vulnerabilities...${NORMAL}\n\n"
    gau $domain | gf xss | sed 's/=.*/=/' | sed 's/URL: //' | dalfox pipe -o xss.txt
    
    echo -e "\n${GREEN}[+] Vulnerability: SQLi${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Finding SQLi entry points in the domain...${NORMAL}\n\n"
    gau $domain | gf sqli | tee sqlInjectionParameters.txt
    echo -e "\n"
    echo -e "${NORMAL}${CYAN}Checking if the entry points are vulnerable...${NORMAL}\n\n"
    sqlmap -m sqlInjectionParameters.txt --batch --random-agent --level 1 | tee -a sqli.txt
    
    echo -e "\n${GREEN}[+] Vulnerability: Multiples vulnerabilities${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Running multiple templates to discover vulnerabilities...${NORMAL}\n\n"
    nuclei -u $domain -t ~/tools/nuclei-templates/ -severity low,medium,high,critical -silent -o multipleVulnerabilities.txt
    
    if [ "$2" = true ];
    then
        echo -e "\n${GREEN}[+] Missing headers results: ${NORMAL}\n" | notify -silent | cat headers.txt | notify -silent
        echo -e "\n${GREEN}[+] Email spoofing results: ${NORMAL}\n" | notify -silent | cat spoof.json | notify -silent
        echo -e "\n${GREEN}[+] Subdomain takeover results: ${NORMAL}\n" | notify -silent | cat takeover.txt | notify -silent
        echo -e "\n${GREEN}[+] CORS results: ${NORMAL}\n" | notify -silent | cat cors.txt | notify -silent
        echo -e "\n${GREEN}[+] 403 bypass results: ${NORMAL}\n" | notify -silent | cat bypass403.txt | notify -silent
        echo -e "\n${GREEN}[+] Cross Site Request Forgery (CSRF/XSRF) results: ${NORMAL}\n" | notify -silent | cat csrf.txt | notify -silent
        echo -e "\n${GREEN}[+] Open Redirect results: ${NORMAL}\n" | notify -silent | cat orURLs.txt | notify -silent
        echo -e "\n${GREEN}[+] SSRF results: ${NORMAL}\n" | notify -silent | cat ssrf.txt | notify -silent
        echo -e "\n${GREEN}[+] XSS results: ${NORMAL}\n" | notify -silent | cat xss.txt | notify -silent
        echo -e "\n${GREEN}[+] SQLi results: ${NORMAL}\n" | notify -silent | cat sqli.txt | notify -silent
        echo -e "\n${GREEN}[+] Nuclei results: ${NORMAL}\n" | notify -silent | cat multipleVulnerabilities.txt | notify -silent
    fi
    
    cd $actualDir
}


# Wildcard Recon Function
wildcardReconFunction(){
    echo -e "${BOLD}${RED}[!] This mode does not accept any arguments${NORMAL}\n"
    echo -e "${BOLD}${RED}[!] A complete analysis will be carried out on all the subdomains found of the entered wildcard ${NORMAL}\n\n"
    
    echo -e "${BOLD}${GREEN}[*] starting subdomain enumeration${NORMAL}\n\n"
    echo -e "${BOLD}${GREEN}[*] Wildcard:${YELLOW} *.$wildcard ${NORMAL}\n"
    
    if [ -d subdomains ]; then rm -Rf subdomains; fi
    mkdir subdomains
    cd subdomains
    
    echo -e "\n${GREEN}[+] Subfinder ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching subdomains...${NORMAL}\n\n"
    subfinder -silent -d $wildcard -o subdomains.txt
    
    echo -e "\n${GREEN}[+] Amass ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Searching subdomains with bruteforce...${NORMAL}\n\n"
    amass enum -d $wildcard -w $dnsDictionary -o bruteforce.txt
    cat bruteforce.txt >> subdomains.txt
    rm bruteforce.txt
    sort -u subdomains.txt -o subdomains.txt
    
    echo -e "\n${GREEN}[+] Httpx ${NORMAL}\n"
    echo -e "${NORMAL}${CYAN}Checking up subdomains...${NORMAL}\n\n"
    httpx -l subdomains.txt -silent -o up.txt
    
    cp up.txt activesubdomain.txt
    sed -i 's#^http://##; s#/score/$##' activesubdomain.txt
    sed -i 's#^https://##; s#/score/$##' activesubdomain.txt
    sort -u activesubdomain.txt -o activesubdomain.txt
    
    cat activesubdomain.txt | python -c "import sys; import json; print (json.dumps({'domains':list(sys.stdin)}))" > up.json
    cat subdomains.txt | python -c "import sys; import json; print (json.dumps({'domains':list(sys.stdin)}))" > subdomains.json
    
    sed 's/ \+/,/g' activesubdomain.txt > up.csv
    sed 's/ \+/,/g' subdomains.txt > subdomains.csv
    
    mode="more"
    
    for domain in $(cat activesubdomain.txt);do
        all $domain $more
    done
    
    cd $actualDir
}

# Help Menu
help(){
    echo -e "${BOLD}${GREEN}USAGE${NORMAL}\n"
    echo -e "$0 [-d domain.com] [-w domain.com] [-l listdomains.txt]"
    echo -e "           	      [-a] [-p] [-x] [-r] [-v] [-m] [-n] [-h] \n\n"
    echo -e "${BOLD}${GREEN}TARGET OPTIONS${NORMAL}"
    echo -e "   -d domain.com     Target domain"
    echo -e "   -w domain.com     Wildcard domain"
    echo -e "   -l list.txt       Target list"
    echo -e " \n"
    echo -e "${BOLD}${GREEN}MODE OPTIONS${NORMAL}"
    echo -e "   -a, --all                 All mode - Full scan."
    echo -e "   -p, --passive             Passive reconnaissance."
    echo -e "   -x, --active              Active reconnaissance."
    echo -e "   -m, --massive             Massive recon."
    echo -e "   -r, --recon               Active and passive reconnaissance."
    echo -e "   -v, --vulnerabilities     Check Vulnerabilities only."
    echo -e "   -h, --help                Help - Show help menu"
    
}


usage(){
    echo -e "\n"
    echo -e "Usage: $0 [-d domain.com] [-w domain.com] [-l listdomains.txt]"
    echo -e "\n           	      [-a] [-p] [-x] [-r] [-v] [-m] [-n] [-h] \n\n"
    exit 2
}

# Print Banner
echo -e "${BOLD}${YELLOW}"
echo -e "${BOLD}
   __ _____   ___   ___    __
  /__\___ /  / __\ /___\/\ \ \\
 / \// |_ \ / /   //  //  \/ /
/ _  \___) / /___/ \_// /\  /
\/ \_/____/\____/\___/\_\ \/  ${NORMAL}"

echo -e "${BOLD}${MAGENTA}${RED}\n\t\t@thenurhabib \n${NORMAL}"

parsedArguments=$(getopt -a -n r3con -o "d:w:l:apxrvmnh" --long "domain:,wildcard:,list:,all,passive,active,recon,vulnerabilities,massive,notify,help" -- "$@")
validArguments=$?

if [ $validArguments != "0" ];
then
    usage
fi

if [ $# == 0 ]
then
    echo -e "${RED}[!] No arguments detected. \n${NORMAL}"
    exit 1
fi

eval set -- "$parsedArguments"

modrecon=0
vulnerabilitiesMode=false
notifyMode=false

while :
do
    case "$1" in
        '-d' | '--domain')
            domain=$2
            shift
            shift
            continue
        ;;
        '-w' | '--wildcard')
            wildcard=$2
            shift
            shift
            continue
        ;;
        '-l' | '--list')
            domainList=$2
            shift
            shift
            continue
        ;;
        '-a' | '--all')
            modrecon=1
            shift
            continue
        ;;
        '-p' | '--passive')
            modrecon=2
            shift
            continue
        ;;
        '-x' | '--active')
            modrecon=3
            shift
            continue
        ;;
        '-r' | '--recon')
            modrecon=4
            shift
            continue
        ;;
        '-v' | '--vulnerabilities')
            vulnerabilitiesMode=true
            shift
            continue
        ;;
        '-m' | '--massive')
            modrecon=5
            shift
            continue
        ;;
        '-n' | '--notify')
            notifyMode=true
            shift
            continue
        ;;
        '-h' | '--help')
            help
            exit
        ;;
        '--')
            shift
            break
        ;;
        *)
            echo -e "${RED}[!] Unexpected option: $1 - this should not happen. \n${NORMAL}"
            usage
        ;;
    esac
done

if [ -z "$domain" ] && [ -z "$wildcard" ] && [ -z "$domainList" ]
then
    echo -e "${RED}[!] Please specify a domain (-d | --domain), a wildcard (-w | --wildcard) or a list of domains(-l | --list) \n${NORMAL}"
    exit 1
fi

if [ ! -d targets ];
then
    mkdir targets
fi

if [ ! -z "$wildcard" ] && [ $modrecon != 5 ]
then
    wildcardReconFunction $wildcard
    exit 1
fi

case $modrecon in
    0)
        if [ -z "$domainList" ]
        then
            if [ $vulnerabilitiesMode == true ]
            then
                vulnerabilities $domain $notifyMode
            fi
        else
            if [ $vulnerabilitiesMode == true ]
            then
                for domain in $(cat $domainList);do
                    vulnerabilities $domain $notifyMode
                done
            fi
        fi
    ;;
    1)
        if [ -z "$domainList" ]
        then
            all $domain $notifyMode
        else
            for domain in $(cat $domainList);do
                all $domain $notifyMode
            done
        fi
    ;;
    2)
        if [ -z "$domainList" ]
        then
            passiveReconFunction $domain $notifyMode $vulnerabilitiesMode
        else
            for domain in $(cat $domainList);do
                passiveReconFunction $domain $notifyMode $vulnerabilitiesMode
            done
        fi
    ;;
    3)
        if [ -z "$domainList" ]
        then
            activeReconFunction $domain $notifyMode $vulnerabilitiesMode
        else
            for domain in $(cat $domainList);do
                activeReconFunction $domain $notifyMode $vulnerabilitiesMode
            done
        fi
    ;;
    4)
        if [ -z "$domainList" ]
        then
            fullReconFunction $domain $notifyMode
        else
            for domain in $(cat $domainList);do
                fullReconFunction $domain $notifyMode
            done
        fi
    ;;
    5)
        if [ ! -z "$wildcard"  ]
        then
            massiveReconFunction $wildcard
        else
            echo -e "${RED}[!] This mode only works with a wildcard (-w | --wildcard) \n${NORMAL}"
            exit 1
        fi
    ;;
    *)
        help
        exit 1
    ;;
esac