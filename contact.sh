#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
END='\033[0m'

echo "

 _  _ __ _|_ _  _ _|_    _ |_ 
(_ (_)| | |_(_|(_  |_ o _> | |
            ---
        by EdOverflow
"
printf "\n"

# Print this message when there are no arguments.
if [[ $# -eq 0 ]] ; then
    printf "${CYAN}[i]${END} Description: An OSINT tool to find contacts in order to report security vulnerabilities.\n${CYAN}[i]${END} Usage: ./contact.sh [Options] use -d for hostnames (-d example.com) and -c for vendor name (-c example)\n${CYAN}[i]${END} Example: ./contact.sh -d google.com -c google\n"
    exit 0
fi

while getopts ":c:d:h:" opt; do
    case $opt in
        d)
            #############################################
            # Check hostname                            #
            #############################################

            # Set OPTARG to the basename. This allows the user
            # to specify URLs.
            OPTARG=$(basename "$OPTARG" | tr '[:upper:]' '[:lower:]')

            # security.txt
            printf "${GREEN}[+]${END} Finding security.txt files\n"
            ROBOTSTXT=$(curl -L --silent "http://$OPTARG/robots.txt" | grep -A1 "User-agent: \*" | grep -w "Disallow: \/$")
            
            if [ ${#ROBOTSTXT} -gt 0 ]; then
                printf "${RED}[!]${END} The robots.txt file does not permit crawling this hostname.\n"
            else
                WELL_KNOWN=$(curl --silent "https://$OPTARG/.well-known/security.txt" | grep "Contact:")
                ROOT=$(curl --silent "https://$OPTARG/security.txt" | grep "Contact:")
                if [ ${#WELL_KNOWN} -gt 0 ]; then
                    echo "security.txt file found: https://$OPTARG/.well-known/security.txt"
                    echo "$WELL_KNOWN"
                    exit 0
                elif [ ${#ROOT} -gt 0 ]; then
                    echo "security.txt file found: https://$OPTARG/security.txt"
                    echo "$ROOT"
                    exit 0
                fi
            fi
            printf "\n"

            # HackerOne
            printf "${GREEN}[+]${END} Checking HackerOne's directory for hostname\n"
            HACKERONE_PATH=$(curl --silent "https://hackerone.com/programs/search?query=domain%3A$OPTARG&sort=published_at%3Adescending&page=1" | jq -r '.results[].url')
            if [ ${#HACKERONE_PATH} -gt 0 ]; then
                for line in $HACKERONE_PATH; do
                    echo "https://hackerone.com$line"
                done
                exit 0
            fi
            printf "\n"

            # Bugcrowd
            printf "${GREEN}[+]${END} Checking Bugcrowd's list for hostname\n"
            curl --silent https://www.bugcrowd.com/bug-bounty-list/ | grep -w "^$OPTARG" | sed 's/^ *//g' | sed -r 's/^.+href="([^"]+)".+$/\1/'
            printf "\n"

            # General bug bounty lists
            printf "${GREEN}[+]${END} Checking bug bounty lists for hostname\n"
            curl --silent "https://www.vulnerability-lab.com/list-of-bug-bounty-programs.php" | grep $OPTARG | sed 's/^ *//g' | sed -r 's/^.+href="([^"]+)".+$/\1/' | tr " " "\n" | sort -u
            BOUNTYFACTORY_PATH=$(curl --silent "https://bountyfactory.io/programs" | grep -i "$OPTARG" | grep media-heading | sed -r 's/^.+href="([^"]+)".+$/\1/')
            if [ ${#BOUNTYFACTORY} -gt 0 ]; then
                for line in $BOUNTYFACTORY; do
                    echo "https://bountyfactory.io$line"
                done
            fi
            printf "\n"

            # Addresses on website.
            printf "${GREEN}[+]${END} Searching for addresses on website\n"
            if [ ${#ROBOTSTXT} -gt 0 ]; then
                printf "${RED}[!]${END} The robots.txt file does not permit crawling this hostname.\n"
            else
                ADDRESS=$(curl -L --silent "https://$OPTARG/" | sed 's/</\n/g' | grep "@$OPTARG\|twitter.com\|facebook.com\|keybase.io" | sed -r 's/^.+href="([^"]+)".+$/\1/' | sed -r 's/^.+content="([^"]+)".+$/\1/')
                if [ ${#ADDRESS} -gt 0 ]; then
                    echo $ADDRESS | tr " " "\n" | sort -u
                fi
            fi
            printf "\n"

            # WHOIS
            printf "${GREEN}[+]${END} Checking WHOIS record\n"
            whois $OPTARG | sed 's/ /\n/g' | grep "@$OPTARG" | tr " " "\n" | sort -u
            printf "\n"

            # RFC 2142 (security@)
            printf "${GREEN}[+]${END} Doing an RFC 2142 check (security@$OPTARG)\n"
            SECURITYAT=$(curl --max-time 9 -X POST --silent http://mailtester.com/testmail.php -d "email=security@$OPTARG" | grep "E-mail address is valid")
            if [ ${#SECURITYAT} -gt 0 ]; then
                echo "security@$OPTARG is valid!"
            else
                printf "security@$OPTARG is ${RED}not${END} valid.\n"
            fi
            printf "\n"

            # GitHub
            printf "${GREEN}[+]${END} Checking GitHub for addresses\n"
            ORG=$(echo "$OPTARG" | sed 's/\([[:alnum:]][[:alnum:]]*\)\.\([[:graph:]][[:graph:]]*\)/\1/g')
            GITHUB=$(curl --silent "https://github.com/search?q=org%3A$ORG+%22$OPTARG%22&type=Code" | grep "@<em>$ORG" | sed -r 's/<[^>]*>//g' | sed -r 's/&[^;]+;//g' | grep -oE "[^ ]+@$OPTARG")
            echo $GITHUB | tr " " "\n" | sort -u
            printf "\n"

            # PGP keys
            printf "${GREEN}[+]${END} Checking MIT PGP Public Key Server\n"
            curl --max-time 9 --silent "https://pgp.mit.edu/pks/lookup?search=$OPTARG&op=index" | sed -r 's/<[^>]*>//g' | sed -r 's/&[^;]+;//g' | grep -oE "[^ ]+@$OPTARG"
            printf "\n"
            
            # Response header
            printf "${GREEN}[+]${END} Checking response header\n"
            curl -I --silent "https://$OPTARG/" | grep "@"
            printf "\n"
        ;;
        c)
            #############################################
            # Check company name                        #
            #############################################
         
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
                exit 0
            fi
            printf "\n"

            # Bugcrowd
            printf "${GREEN}[+]${END} Checking Bugcrowd's list for company name\n"
            BUGCROWD=$(curl --silent https://www.bugcrowd.com/bug-bounty-list/ | grep -i -w "^$OPTARG" | sed -r 's/^.+href="([^"]+)".+$/\1/')
            if [ ${#BUGCROWD} -ge 1 ]; then
                echo $BUGCROWD
                exit 0
            fi
            printf "\n"

            # General bug bounty lists
            printf "${GREEN}[+]${END} Checking other bug bounty lists for company name\n"
            curl --silent "https://www.vulnerability-lab.com/list-of-bug-bounty-programs.php" | grep -i -w "^$OPTARG" | sed -r 's/^.+href="([^"]+)".+$/\1/'
            BOUNTYFACTORY=$(curl --silent "https://bountyfactory.io/programs" | grep -i "$OPTARG" | grep media-heading | sed -r 's/^.+href="([^"]+)".+$/\1/')
            if [ ${#BOUNTYFACTORY} -gt 0 ]; then
                for line in $BOUNTYFACTORY; do
                    echo "https://bountyfactory.io$line"
                done
            fi
            printf "\n"
        ;;
        :)
            printf "${CYAN}[i]${END} Usage: ./contact.sh [Options] use -d for hostnames (-d example.com) and -c for vendor name (-c example)\n${CYAN}[i]${END} Example: ./contact.sh -d google.com -c google\n"
        ;;
        \?)
            printf "${YELLOW}[!]${END} Invalid option: -$OPTARG\n" >&2
            printf "${CYAN}[i]${END} Usage: ./contact.sh [Options] use -d for hostnames (-d example.com) and -c for vendor name (-c example)\n${CYAN}[i]${END} Example: ./contact.sh -d google.com -c google\n"
            exit 1
        ;;
  esac
done
