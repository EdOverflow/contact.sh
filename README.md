# contact.sh
An OSINT tool to find contacts in order to report security vulnerabilities.

![image](https://user-images.githubusercontent.com/18099289/34496486-135def44-effa-11e7-8680-3e6ea79ed13a.png)

# Installation

## 🐧 Linux

Make sure you have installed the `whois` and `jq` packages.

```
$ git clone https://github.com/EdOverflow/contact.sh.git
$ cd contact.sh/
$ chmod u+x contact.sh
$ ./contact.sh -d google.com -c google
```

## 🍎 OSX

```
$ brew install gnu-sed --with-default-names
$ brew install jq
$ git clone https://github.com/EdOverflow/contact.sh.git
$ cd contact.sh/
$ chmod u+x contact.sh
$ ./contact.sh -d google.com -c google
```

# Usage

```
$ ./contact.sh


 _  _ __ _|_ _  _ _|_    _ |_ 
(_ (_)| | |_(_|(_  |_ o _> | |
            ---
        by EdOverflow


[i] Description: An OSINT tool to find contacts in order to report security vulnerabilities.
[i] Usage: ./contact.sh [Options] use -d for hostnames (-d example.com), -c for vendor name (-c example), and -f for a list of hostnames in a file (-f domains.txt) 
[i] Example: ./contact.sh -d google.com -c google
```

Use the `-d` flag when trying to find addresses linked to a domain. _contact.sh_ will return a "Confidence level" based on the source of the information retrieved. A security.txt file located on the domain will have a higher priority than a Twitter account on the company's website.

```
$ ./contact.sh -d google.com
```

The `-c` flag allows you to specify the company's name.

```
$ ./contact.sh -c google
```

If the company's name contains spaces, make sure to place the name inside quotes.

```
$ ./contact.sh -c "keeper security"
```

You can check a list of domains using the `-f` flag.

```
$ ./contact.sh -f domains.txt
```

For the best results, combine both flags as follows:

```
$ ./contact.sh -d google.com -c google
```

_contact.sh_ abides by the target's robots.txt file.

```
$ ./contact.sh -d linkedin.com


 _  _ __ _|_ _  _ _|_    _ |_ 
(_ (_)| | |_(_|(_  |_ o _> | |
            ---
        by EdOverflow


[+] Finding security.txt files
[!] The robots.txt file does not permit crawling this hostname.

[+] Checking HackerOne's directory for hostname
https://hackerone.com/linkedin
```
