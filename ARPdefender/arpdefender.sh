#!/bin/bash

# It allows you to counter ARP spoofing with iptables (and ISC-DHCP).

# Copyright (C) 2023 Alguna, Cyberzen (https://www.cyberzen.com/)

# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with this program; if not, see <https://www.gnu.org/licenses>.

# Custom variables
MAIN_IP="192.168.1.2" # TO UPDATE
CHAIN_NAME="IP_MAC_CHECK"
declare -a EXCEPTIONS=( "100" ) # EX : 192.168.100.0/24 -> 100
declare -a IP_ALLOWED=( "10" "1.2.3.4" ) # EX : 10 -> [].10 -> 192.168.1.10

# Colors
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PINK="\033[35m"
LIGHT_BLUE="\033[36m"
RESET="\033[0m"

module='0'

# Prerequisites
if ! cat /boot/config-`uname -r` | grep CONFIG_NETFILTER_XT_MATCH_MAC | grep "y\|m" > /dev/null ; then
    echo -e "[!] ${RED}The xt_mac kernel module is not activated or cannot be activated.${RESET}"
    module='1'
fi

if ! cat /boot/config-`uname -r` | grep CONFIG_NETFILTER_XT_MARK | grep "y\|m" > /dev/null ; then
    echo -e "[!] ${RED}The xt_mark kernel module is not activated or cannot be activated.${RESET}"
    module='1'
fi

if ! cat /boot/config-`uname -r` | grep CONFIG_NETFILTER_XT_MATCH_MARK | grep "y\|m" > /dev/null ; then
    echo -e "[!] ${RED}The xt_match_mark kernel module is not activated or cannot be activated.${RESET}"
    module='1'
fi

if [[ "$module" == '1' ]] ; then
    exit 1
fi

if [[ ! -f "/etc/dhcp/dhcpd.conf" ]] ; then
    echo -e "[!] ${RED}The /etc/dhcp/dhcpd.conf file does not exist.${RESET}"
    exit 1
fi

# Retrieve the list of physical interfaces
interfaces="$(ip link show | awk -F: '$0 !~ "lo|docker|vnet|tun|tap|brd" {print $2}')"

# Declaration of the table for storing networks not affected by filtering
declare -a network_exceptions
declare -a other_ips

echo -e "[+] ${LIGHT_BLUE}Search for the networks concerned${RESET}"

# Browse each interface to obtain the IP addresses
for intf in ${interfaces} ; do
    echo -e "-> ${YELLOW}${intf}${RESET}"

    # Extract IP addresses and add them to the table
    while IFS= read -r addr ; do
        IFS='.' read -ra ADDR <<< "${addr}"
        IFS='/' read -ra MASK <<< "${ADDR[3]}"
        fourth_part="$((${MASK[0]}-1))"
        addr_without_mask="${ADDR[0]}.${ADDR[1]}.${ADDR[2]}.${MASK[0]}"
        network="${ADDR[0]}.${ADDR[1]}.${ADDR[2]}.$fourth_part/${MASK[1]}"
        third_part="$(echo ${ADDR[2]})"

        # Save the IP addresses
        other_ips+=( "${addr_without_mask}" )

        # Main network concerned?
        if [[ "${addr_without_mask}" == "${MAIN_IP}" ]] ; then
            continue
        fi

        # Browse the exceptions entered at the start of the script
        for exception in "${EXCEPTIONS[@]}" ; do
            if [[ "${third_part}" -eq "${exception}" ]] ; then
                echo -en "  ${RED}[ignored]${RESET}"
                network_exceptions+=( "${network}" )
                break
            fi
        done

        echo "  ${network}"
    done < <(ip a show ${intf} | grep 'inet ' | awk '{print $2}')
done

# Counter
count_known=0

# Declaration of the table for storing @MAC/@IP correspondences
declare -a mac_ip_associations

echo
echo -e "[+] ${LIGHT_BLUE}Search for @MAC/@IP matches in /etc/dhcp/dhcpd.conf${RESET}"

while IFS= read -r line ; do
    if [[ "${line}" =~ "hardware ethernet" ]] ; then
        mac="$(echo ${line} | awk '{print $3}' | sed 's/;//' | tr a-z A-Z)"

        if [ ! -z "${ip}" ] ; then
            echo "  ${ip} -> ${mac}"
            mac_ip_associations+=( "${mac} ${ip}" )
            unset ip
            unset mac
        fi
    elif [[ "${line}" =~ "fixed" ]] ; then
        ip="$(echo ${line} | awk '{print $2}' | sed 's/;//')"

        if [ ! -z "${mac}" ] ; then
            echo "  ${ip} -> ${mac}"
            mac_ip_associations+=( "${mac} ${ip}" )
            unset ip
            unset mac
        fi
    fi
done < <(grep -E "hardware ethernet|fixed-address" /etc/dhcp/dhcpd.conf)

echo
echo -e "[+] ${LIGHT_BLUE}Check for the presence of the ${CHAIN_NAME} chain ${RESET}"

if iptables -t mangle -L "${CHAIN_NAME}" -n >/dev/null ; then
    echo -e "-> The chain ${YELLOW}${CHAIN_NAME}${RESET} already exists."

    # Flush the chain
    iptables -t mangle -F ${CHAIN_NAME}
    echo -e "  $ ${PINK}iptables -t mangle -F ${CHAIN_NAME}${RESET}"
    echo -e "-> The chain ${YELLOW}${CHAIN_NAME}${RESET} has been flushed."
else
    # Create the chain
    iptables -t mangle -N ${CHAIN_NAME}
    echo -e "  $ ${PINK}iptables -t mangle -N ${CHAIN_NAME}${RESET}"
    echo -e "-> The chain ${YELLOW}${CHAIN_NAME}${RESET} has been created."
fi

echo
echo -e "[+] ${LIGHT_BLUE}Customising the ${CHAIN_NAME} chain${RESET}"

# Allow ESTABLISHED and RELATED connections from the WAN
iptables -t mangle -A IP_MAC_CHECK -m state --state ESTABLISHED,RELATED -j MARK --set-mark 1
echo -e "  $ ${PINK}iptables -t mangle -A IP_MAC_CHECK -m state --state ESTABLISHED,RELATED -j MARK --set-mark 1${RESET}"

# Browse the network_exceptions table
for network in "${network_exceptions[@]}" ; do
    # Add an iptables rule
    iptables -t mangle -A IP_MAC_CHECK -s ${network} -j MARK --set-mark 1
    echo -e "  $ ${PINK}iptables -t mangle -A IP_MAC_CHECK -s ${network} -j MARK --set-mark 1${RESET}"
done

# Browse the IP_ALLOWED table
for ip_allowed in "${IP_ALLOWED[@]}" ; do
    if ! [[ "$ip_allowed" =~ '.' ]] ; then
        IFS='.' read -ra ADDR <<< "${MAIN_IP}"
        ip_allowed="${ADDR[0]}.${ADDR[1]}.${ADDR[2]}.${ip_allowed}"
    fi

    # Add an iptables rule
    iptables -t mangle -A IP_MAC_CHECK -s ${ip_allowed} -j MARK --set-mark 1
    echo -e "  $ ${PINK}iptables -t mangle -A IP_MAC_CHECK -s ${ip_allowed} -j MARK --set-mark 1${RESET}"
done

# Browse the other_ips array
for ip in "${other_ips[@]}" ; do
    # Add an iptables rule
    iptables -t mangle -A IP_MAC_CHECK -s ${ip} -j MARK --set-mark 1
    echo -e "  $ ${PINK}iptables -t mangle -A IP_MAC_CHECK -s ${ip} -j MARK --set-mark 1${RESET}"
done

# Browse the mac_ip_associations table
for mac_ip in "${mac_ip_associations[@]}" ; do
    mac="${mac_ip%% *}"
    ip="${mac_ip##* }"

    # Add an iptables rule
    iptables -t mangle -A IP_MAC_CHECK -s ${ip} -m mac --mac-source ${mac} -j MARK --set-mark 1
    echo -e "  $ ${PINK}iptables -t mangle -A IP_MAC_CHECK -s ${ip} -m mac --mac-source ${mac} -j MARK --set-mark 1${RESET}"
    count_known="$((count_known+1))"
done

# Anything that arrives at the end of the chain and has not been authorised must be definitively refused
iptables -t mangle -A IP_MAC_CHECK -m mark ! --mark 1 -j MARK --set-mark 0
echo -e "  $ ${PINK}iptables -t mangle -A IP_MAC_CHECK -m mark ! --mark 1 -j MARK --set-mark 0${RESET}"

declare -a values=( "FORWARD -j IP_MAC_CHECK" "FORWARD -m mark" )

for value in "${values[@]}" ; do
    if cat /etc/iptables.rules | grep "$value" > /dev/null ; then
        continue
    fi

    echo

    case "$value" in
        "FORWARD -j IP_MAC_CHECK") # Redirect traffic in the FORWARD chain to IP_MAC_CHECK (mangle table)
            echo -e "[+] ${LIGHT_BLUE}Added to the FORWARD chain (mangle table)${RESET}"

            # Send traffic to the customised channel first
            iptables -t mangle -I FORWARD -j IP_MAC_CHECK
            echo -e "  $ ${PINK}iptables -t mangle -I FORWARD -j IP_MAC_CHECK${RESET}"

            ;;
        "FORWARD -m mark") # Managing markers in the FORWARD chain (table filter)
            echo -e "[+] ${LIGHT_BLUE}Added to the FORWARD chain (filter table)${RESET}"

            # Packets marked 0 are rejected
            iptables -I FORWARD -m mark --mark 0 -j DROP
            echo -e "  $ ${PINK}iptables -I FORWARD -m mark --mark 0 -j DROP${RESET}"
            
            ;;
        *)
            continue
            ;;
    esac
done

echo
echo -e "[+] ${LIGHT_BLUE}Saving rules in /etc/iptables.rules${RESET}"

# Saving iptables rules
iptables-save -c > /etc/iptables.rules
echo -e "  $ ${PINK}iptables-save -c > /etc/iptables.rules${RESET}"

# Final results
echo
echo -e "=> ${count_known} @MAC/@IP pair(s) have been ${GREEN}authorized${RESET} on the LAN"
echo "   As well as the networks: "

# Browse the network_exceptions table
for network in "${network_exceptions[@]}" ; do
    echo -e "      - ${YELLOW}${network}${RESET}"
done

echo "   And IP addresses: "

# Browse the IP_ALLOWED table
for ip_allowed in "${IP_ALLOWED[@]}" ; do
    if ! [[ "$ip_allowed" =~ '.' ]] ; then
        IFS='.' read -ra ADDR <<< "${MAIN_IP}"
        ip_allowed="${ADDR[0]}.${ADDR[1]}.${ADDR[2]}.${ip_allowed}"
    fi

    echo -e "      - ${YELLOW}${ip_allowed}${RESET}"
done

# Browse the other_ips array
for ip in "${other_ips[@]}" ; do
    echo -e "      - [gateway] ${YELLOW}${ip}${RESET}"
done

exit 0