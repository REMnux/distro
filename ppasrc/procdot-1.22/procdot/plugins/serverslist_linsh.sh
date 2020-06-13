#!/bin/bash

# ****************************************************************************
# *             THIS IS AN EXEMPLARY TEST PLUGIN FOR PROCDOT                 *
# *--------------------------------------------------------------------------*
# * As such it returns a list of all the servers (domains and according IPs) *
# * for the current session.                                                 *
# ****************************************************************************

#PROCDOTPLUGIN_GraphFileDetails=/tmp/procdot.dot.procdot
#PROCDOTPLUGIN_ResultCSV=/tmp/serverslist.txt

in=$PROCDOTPLUGIN_GraphFileDetails
out=$PROCDOTPLUGIN_ResultCSV

echo "\"Domain\",\"IP-Address\"" > $out
echo "\"*\",\"*\"" >> $out

while read line; do
	regex='^Domain ='
	if [[ $line =~ $regex ]]; then
		regex='^Domain = (.*)'
		[[ $line =~ $regex ]]
		domain="${BASH_REMATCH[1]}"
	fi
	regex='^IP-Address ='
	if [[ $line =~ $regex ]]; then
		regex='^IP-Address = (.*)'
		[[ $line =~ $regex ]]
		ip="${BASH_REMATCH[1]}"
	fi
	regex='^OnlyInPCAP ='
	if [[ $line =~ $regex ]]; then
		regex='^OnlyInPCAP = (.*)'
		[[ $line =~ $regex ]]
		onlyinpcap="${BASH_REMATCH[1]}"
	fi
	regex='^RelevantBecauseOfProcmonLines ='
	if [[ $line =~ $regex ]]; then
		if [[ $domain != $ip ]]; then
			regex='^RelevantBecauseOfProcmonLines = (.*)'
			[[ $line =~ $regex ]]
			procmon="${BASH_REMATCH[1]}"
			if [[ $procmon != "" ]]; then
				echo "\"$domain\",\"$ip\"" >> $out
			fi
			if [[ $onlyinpcap = "Yes" ]]; then
				echo "{{color:blue}}\"$domain\",\"$ip\"" >> $out
			fi
		fi
		domain=''
		ip=''
	fi
done < $in
