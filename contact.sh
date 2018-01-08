#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
END='\033[0m'

LOGO="\n"
LOGO+="\n"
LOGO+=" _  _ __ _|_ _  _ _|_    _ |_ \n"
LOGO+="(_ (_)| | |_(_|(_  |_ o _> | |\n"
LOGO+="            ---\n"
LOGO+="        by EdOverflow\n\n\n"

# Print this message when there are no arguments.
if [[ $# -eq 0 ]] ; then
	printf "%b" "$LOGO"
    printf "${CYAN}[i]${END} Description: An OSINT tool to find contacts in order to report security vulnerabilities.\n${CYAN}[i]${END} Usage: ./contact.sh [Options] use -d for hostnames (-d example.com), -c for vendor name (-c example), and -f for a list of hostnames in a file (-f domains.txt) \n${CYAN}[i]${END} Example: ./contact.sh -d google.com -c google\n"
    exit 0
fi

domain() {
    # security.txt
    printf "${GREEN}[+]${END} Finding security.txt files \n | Confidence level: ${GREEN}★ ★ ★${END} \n"
    ROBOTSTXT=$(curl -L --silent "http://$1/robots.txt" | grep -A1 "User-agent: \*" | grep -w "Disallow: \/$")
    
    if [ ${#ROBOTSTXT} -gt 0 ]; then
        printf "${RED}[!]${END} The robots.txt file does not permit crawling this hostname.\n"
    else
        WELL_KNOWN=$(curl --silent --max-time 9 "https://$1/.well-known/security.txt" | grep "Contact:")
        ROOT=$(curl --silent --max-time 9 "https://$1/security.txt" | grep "Contact:")
        if [ ${#WELL_KNOWN} -gt 0 ]; then
            echo "security.txt file found: https://$1/.well-known/security.txt"
            echo "$WELL_KNOWN"
            # return 0
        elif [ ${#ROOT} -gt 0 ]; then
            echo "security.txt file found: https://$1/security.txt"
            echo "$ROOT"
            # return 0
        fi
    fi
    printf "\n"

    # HackerOne
    printf "${GREEN}[+]${END} Checking HackerOne's directory for hostname \n | Confidence level: ${GREEN}★ ★ ★${END} \n"
    HACKERONE_PATH=$(curl -q --silent "https://hackerone.com/programs/search?query=domain%3A$1&sort=published_at%3Adescending&page=1" | jq -r '.results[].url')
    if [ ${#HACKERONE_PATH} -gt 0 ]; then
        for line in $HACKERONE_PATH; do
            echo "https://hackerone.com$line"
        done
        # return 0
    fi
    printf "\n"

    # Bugcrowd
    printf "${GREEN}[+]${END} Checking Bugcrowd's list for hostname \n | Confidence level: ${GREEN}★ ★ ★${END} \n"
    curl --silent https://www.bugcrowd.com/bug-bounty-list/ | grep -i "$1" | sed 's/^ *//g' | sed -E 's/^.+href="([^"]+)".+$/\1/' | tr " " "\n" | sort -u
    printf "\n"

    # General bug bounty lists
    printf "${GREEN}[+]${END} Checking bug bounty lists for hostname \n | Confidence level: ${YELLOW}★ ★ ☆${END} \n"
    curl --silent "https://www.vulnerability-lab.com/list-of-bug-bounty-programs.php" | grep $1 | sed 's/^ *//g' | sed -E 's/^.+href="([^"]+)".+$/\1/' | tr " " "\n" | sort -u
    BOUNTYFACTORY_PATH=$(curl --silent "https://bountyfactory.io/programs" | grep -i "$1" | grep media-heading | sed -E 's/^.+href="([^"]+)".+$/\1/')
    if [ ${#BOUNTYFACTORY_PATH} -gt 0 ]; then
        for line in $BOUNTYFACTORY; do
            echo "https://bountyfactory.io$line"
        done
    fi
    printf "\n"

    # Addresses on website.
    printf "${GREEN}[+]${END} Searching for addresses on website \n | Confidence level: ${YELLOW}★ ★ ☆${END} \n"
    if [ ${#ROBOTSTXT} -gt 0 ]; then
        printf "${RED}[!]${END} The robots.txt file does not permit crawling this hostname.\n"
    else
        ADDRESS=$(curl -L --silent --max-time 9 "https://$1/" | sed -n 's/.*href="\([^"]*\).*/\1/p' | grep -i "twitter.com\|facebook.com\|keybase.io\|github.com\|gitlab.com\|contact")
        if [ ${#ADDRESS} -gt 0 ]; then
            echo $ADDRESS | tr " " "\n" | sort -u
        fi
    fi
    printf "\n"

    # WHOIS
    printf "${GREEN}[+]${END} Checking WHOIS record \n | Confidence level: ${YELLOW}★ ★ ☆${END} \n"
    whois $OPTARG | grep "@$OPTARG" | tr -d "\t\r" | sort -u | sed 's/ //g'
    printf "\n"


    # "EXPERIMENTAL" RECURSIVE WHOIS
    # this tries to extract all emails from WHOIS ... note parsing is likely buggy so do not merge into master until further tested
    printf "${GREEN}[+]${END} Checking WHOIS records recursively listing all addresses\n | Confidence level: ${RED}★${END} \n"

    # FIXME: extracting the top domain needs more work ... there is probably already solutions for that
    topdomain=$(echo $OPTARG | grep -o "[^\/\.]*\.\(com\|cn\|net\|co\.id\|vn\|se\|my\|cl\|eu\|com\.\(cn\|my\|tw\)\)$")
    printf " | Using domain: ${topdomain}\n"

    # 1st get the real whois server the registra uses from the WHOIS record
    tmp_whois_record="tmp_whois_record.txt" # TODO:FIXME:5325325325: prevent creating tmp files
    whois $topdomain > $tmp_whois_record # TODO:FIXME:5325325325: prevent creating tmp files
    # FIXME: greping the whois server from the record could be buggy as hell
    WHOIS_SERVER=$(cat ${tmp_whois_record} | grep -v "^\(%\|#\)" | grep -i whois | head -n1 | cut -d: -f 2 | sed 's/^ *//g') # TODO:FIXME:5325325325: prevent creating tmp files
    printf " | Using WHOIS server: ${WHOIS_SERVER}\n"

    # 2nd query the registras WHOIS server if it exists
    if [[ -n "${WHOIS_SERVER}" ]]; then
	# append to the other whois record
        whois ${topdomain} -h ${WHOIS_SERVER} >> $tmp_whois_record # TODO:FIXME:5325325325: prevent creating tmp files
    fi

    # 3rd extract all emails
    cat $tmp_whois_record | grep -o "[^ :]*@[^ ]*" | sort -u # TODO:FIXME:5325325325: prevent creating tmp files

    rm $tmp_whois_record # TODO:FIXME:5325325325: prevent creating tmp files

    printf "\n"

    # RFC 2142 (security@)
    printf "${GREEN}[+]${END} Doing an RFC 2142 check (security@$1) \n | Confidence level: ${YELLOW}★ ★ ☆${END} \n"
    SECURITYAT=$(curl --max-time 9 -X POST --silent http://mailtester.com/testmail.php -d "email=security@$OPTARG" | grep "E-mail address is valid")
    if [ ${#SECURITYAT} -gt 0 ]; then
        echo "security@$1 is valid!"
    else
        printf "security@$1 is ${RED}not${END} valid.\n"
    fi
    printf "\n"

    if [ ${#SECURITYAT} -lt 1 ]; then
        printf "${GREEN}[+]${END} Checking for other security addresses \n | Confidence level: ${YELLOW}★ ★ ☆${END} \n"
        ADDRESSES=("psirt" "whitehat" "contact" "responsible.disclosure" "responsible-disclosure" "vuln")
        for i in ${ADDRESSES[@]}; do
            EMAIL=$(curl --max-time 9 -X POST --silent http://mailtester.com/testmail.php -d "email=$i@$OPTARG" | grep "E-mail address is valid")
            if [ ${#EMAIL} -gt 0 ]; then
                echo "$i@$1 is valid!"
            else
                printf "$i@$1 is ${RED}not${END} valid.\n"
            fi
        done
    fi
    printf "\n"

    # Contact pages on website.
    printf "${GREEN}[+]${END} Searching for contact pages \n | Confidence level: ${YELLOW}★ ★ ☆${END} \n"
    if [ ${#ROBOTSTXT} -gt 0 ]; then
        printf "${RED}[!]${END} The robots.txt file does not permit crawling this hostname.\n"
    else
        while read page; do
        CONTACT_PAGE=$(curl -L -I --silent --max-time 9 "https://$1/$page")
        STATUS=$(echo "$CONTACT_PAGE" | grep -i "200 ok")
        REDIRECT=$(echo "$CONTACT_PAGE" | grep "Location" | sed 's/Location: //')
        if [ ${#STATUS} -gt 0 ]; then
            if [ $REDIRECT == "https://$1/$page" ]; then
        	    printf "(${GREEN}⏺${END} 200 OK) https://$1/$page -> $REDIRECT\n"
            else
                printf "(${GREEN}⏺${END} 200 OK) https://$1/$page\n"
            fi
        fi
        done < contact_pages.txt
    fi
    printf "\n"

    # GitHub
    printf "${GREEN}[+]${END} Checking GitHub for addresses \n | Confidence level: ${RED}★ ☆ ☆${END} \n"
    ORG=$(echo "$1" | sed 's/\([[:alnum:]][[:alnum:]]*\)\.\([[:graph:]][[:graph:]]*\)/\1/g')
    GITHUB=$(curl --silent "https://github.com/search?q=org%3A$ORG+%22$1%22&type=Code" | grep "@<em>$ORG" | sed -E 's/<[^>]*>//g' | sed -E 's/&[^;]+;//g' | grep -oE "[^ ]+@$OPTARG")
    if [ ${#GITHUB} -gt 0 ]; then
        echo $GITHUB | tr " " "\n" | sort -u
    fi
    printf "\n"

    # PGP keys
    printf "${GREEN}[+]${END} Checking MIT PGP Public Key Server \n | Confidence level: ${RED}★ ☆ ☆${END} \n"
    curl --max-time 60 --silent "https://pgp.mit.edu/pks/lookup?search=$1&op=index" | sed -E 's/<[^>]*>//g' | sed -E 's/&[^;]+;//g' | grep -oE "[^ ]+@$OPTARG"
    printf "\n"
    
    # Response header
    printf "${GREEN}[+]${END} Checking response header \n | Confidence level: ${RED}★ ☆ ☆${END} \n"
    curl -L -I --silent --max-time 9 "https://$1/" | grep "@"
    printf "\n"
}

while getopts ":c:d:f:h:" opt; do
    case $opt in
        d)
            #############################################
            # Check hostname                            #
            #############################################

            printf "%b" "$LOGO"
            OPTARG=$(basename "$OPTARG" | tr '[:upper:]' '[:lower:]')
            domain $OPTARG
        ;;
        c)
            #############################################
            # Check company name                        #
            #############################################
         
            printf "%b" "$LOGO"
            
            # OPTARG should always be lowercase.
            OPTARG=${OPTARG,,}
            
            # HackerOne
            printf "${GREEN}[+]${END} Checking HackerOne's directory for company name\n"
            INITIAL=${OPTARG:0:1}
            HACKERONE=$(curl -H "Accept: application/json" --silent "https://hackerone.com/sitemap?first=$INITIAL" | jq -r '.[] | .[] | .handle' | grep -w "^$OPTARG")
            if [ ${#HACKERONE} -ge 1 ]; then
                for line in $HACKERONE; do
                    echo "https://hackerone.com/$line"
                done
                # return 0
            fi
            printf "\n"

            # Bugcrowd
            printf "${GREEN}[+]${END} Checking Bugcrowd's list for company name\n"
            BUGCROWD=$(curl --silent https://www.bugcrowd.com/bug-bounty-list/ | grep -i "$OPTARG" | sed -E 's/^.+href="([^"]+)".+$/\1/')
            if [ ${#BUGCROWD} -gt 0 ]; then
                echo $BUGCROWD | tr " " "\n"
                # return 0
            fi
            printf "\n"

            # General bug bounty lists
            printf "${GREEN}[+]${END} Checking other bug bounty lists for company name\n"
            curl --silent "https://www.vulnerability-lab.com/list-of-bug-bounty-programs.php" | grep -i -w "^$OPTARG" | sed -E 's/^.+href="([^"]+)".+$/\1/'
            BOUNTYFACTORY=$(curl --silent "https://bountyfactory.io/programs" | grep -i "$OPTARG" | grep media-heading | sed -E 's/^.+href="([^"]+)".+$/\1/')
            if [ ${#BOUNTYFACTORY} -gt 0 ]; then
                for line in $BOUNTYFACTORY; do
                    echo "https://bountyfactory.io$line"
                done
            fi
            printf "\n"
        ;;
        f)
            #############################################
            # Check a list of hostnames.                #
            #############################################

            printf "%b" "$LOGO"

            while read line; do
                printf "\n§===================================================§\n"
                printf "\n${CYAN}[i]${END} Running contact.sh against $line.\n"
                printf "\n§===================================================§\n"
               	domain $line
            done < $OPTARG
        ;;
        :)
            printf "%b" "$LOGO"
            printf "${CYAN}[i]${END} Usage: ./contact.sh [Options] use -d for hostnames (-d example.com), -c for vendor name (-c example), and -f for a list of hostnames in a file (-f domains.txt)\n${CYAN}[i]${END} Example: ./contact.sh -d google.com -c google\n"
        ;;
        \?)
            printf "%b" "$LOGO"
            printf "${YELLOW}[!]${END} Invalid option: -$OPTARG\n" >&2
            printf "${CYAN}[i]${END} Usage: ./contact.sh [Options] use -d for hostnames (-d example.com) and -c for vendor name (-c example)\n${CYAN}[i]${END} Example: ./contact.sh -d google.com -c google\n"
            exit 1
        ;;
  esac
done
