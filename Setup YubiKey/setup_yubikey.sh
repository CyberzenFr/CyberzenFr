#!/bin/bash

# It allows you to configure the OTP on your YubiKey (HTOP or TOTP, your choice).

# Copyright (C) 2025 Alguna, Cyberzen (https://www.cyberzen.com/)

# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along with this program; if not, see <https://www.gnu.org/licenses>.

# Check if ykman is installed
if ! command -v ykman &> /dev/null; then
    echo "ykman n'est pas installé. Veuillez l'installer avec : apt install yubikey-manager"
    exit 1
fi

# Check if xxd is installed
if ! command -v xxd &> /dev/null; then
    echo "xxd n'est pas installé. Veuillez l'installer avec : apt install xxd"
    exit 1
fi

# Requests the type of configuration (HOTP or TOTP)
read -p "Entrez le type de jeton OTP (hotp/totp) [default: hotp]: " type
type=${type:-hotp}

# Request the length of the OTP
read -p "Entrez la longueur de l'OTP (6/8) [default: 8]: " otplen
otplen=${otplen:-8}

# Requests the time interval for TOTP and the hash algorithm to be used
if [ "$type" == "totp" ]; then
    read -p "Entrez l'intervalle de temps (en secondes) [default: 30]: " timestep
    timestep=${timestep:-30}
    
    read -p "Entrez l'algorithme de hachage (sha1/sha256/sha512) [default: sha512]: " algo
	algo=${algo:-sha512}
fi

# Generates a raw secret key in hexadecimal for PrivacyIDEA
seed_raw=$(openssl rand -hex 20)

# Encodes the raw key in Base32 for YubiKey Manager
seed_base32=$(echo "$seed_raw" | xxd -r -p | base32 --wrap=0)

# Configure YubiKey
echo "Configuration de la YubiKey..."

if [ "$type" == "totp" ]; then
    ykman oath accounts add "test-account" "$seed_base32" --oath-type TOTP --digits $otplen --period $timestep --algorithm "$algo"
    echo "TOTP configuré avec succès. Utilisez 'ykman oath accounts code' pour générer des codes."
elif [ "$type" == "hotp" ]; then
    ykman oath accounts add "test-account" "$seed_base32" --oath-type HOTP --digits $otplen
    echo "HOTP configuré avec succès. Utilisez 'ykman oath accounts code' pour générer des codes."
else
    echo "Type $type non pris en charge dans ce script."
    exit 1
fi

# Recover YubiKey's serial number
serial=$(ykman info | grep "Serial number" | awk '{print $NF}')

# Generates the CSV file
csv_filename="oath_tokens.csv"

if [ "$type" == "totp" ]; then
    echo "$serial,$seed_raw,$type,$otplen,$timestep" > $csv_filename
else
    echo "$serial,$seed_raw,$type,$otplen" > $csv_filename
fi

echo "Fichier CSV généré : $csv_filename"
exit 0