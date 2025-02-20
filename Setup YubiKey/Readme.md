# Setup YubiKey

*It allows you to configure the OTP on your YubiKey (HTOP or TOTP, your choice).*

An article about this tool was written on [MISC magazine](to be updated when the article is published).



## I) What does the script do?

Answer:

1. It checks whether the `ykman` and `xxd` commands are available on your machine.
2. It asks you several questions: TOTP or HOTP? How long should your code be? What time interval and hash algorithm should you use if you want to use TOTP?
3. It generates a raw key in base32 which will be the seed of your OTP.
4. It configures your key via `ykman` (YubiKey Manager CLI) using the answers you gave it previously and the generated key.
5. It saves all the necessary elements relating to your OTP in a file in CSV format.

<u>Note</u>: privacyIDEA (technology used in the article written) supports algorithms up to **HMAC-SHA512** for OTP authentication, offering great flexibility. However, when using `ykman` to configure OATH-HOTP on YubiKeys, it only configures the key with **HMAC-SHA1**.



## II) Usage

The script must be run on a Linux environment.

```bash
# Obtain permission to run the script
$ chmod +x setup_yubikey.sh

# Run the script
$ ./setup_yubikey.sh
```

Once the script has been run, the key will be ready and a nice *oath_tokens.csv* file will be generated. This file will be used to enrol your key.



## III) Details

### A) Versioning

| Version |    Date    |           Content           |
| :-----: | :--------: | :-------------------------: |
|   1.0   | 20/02/2025 | OTP support (HOTP and TOTP) |

### B) Contact

Author: [Jérémy DE COCK | LinkedIn](https://www.linkedin.com/in/jeremy-dc/)

Cyberzen: https://www.cyberzen.com/ | [contact@cyberzen.com](mailto:contact@cyberzen.com)

Project link: https://github.com/CyberzenFr/CyberzenFr/tree/main/Setup%20YubiKey

### C) License

Distributed under GPLv3 Licence. See `LICENSE.txt` for more information.