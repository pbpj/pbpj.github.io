# Malicious PowerShell Analysis

## Scenario

Recently the networks of a large company named GothamLegend were compromised after an employee opened a phishing email containing malware. The damage caused was critical and resulted in business-wide disruption. GothamLegend had to reach out to a third-party incident response team to assist with the investigation. You are a member of the IR team - all you have is an encoded Powershell script. Can you decode it and identify what malware is responsible for this attack?

Reading material

{% embed url="https://malware.news/t/deobfuscating-powershell-putting-the-toothpaste-back-in-the-tube/23509" %}

## Walktrough

The script is base64 encoded

<figure><img src="../../../.gitbook/assets/image (22) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Decoding the script

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

After some cyberchef magic I got a much cleaner script



<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Security protocol used is tls v1.2

<figure><img src="../../../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Directory created

```
# Construct a file path in the user's home directory
$Imd1yck = $HOME + '\Db_bh30\Yf5be5g\' + $Swrp6tc + '.dll';
```

List of RULs

<figure><img src="../../../.gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

It downloads the file A69S.dll and if the filesize is exactly 35,698 bytes it executes it using rundll32.

```
# Set $Swrp6tc to 'A69S'
$Swrp6tc = 'A69S';

<snip>

        If ((Get-Item $Imd1yck).Length -ge 35698) {
            # Execute the downloaded DLL using rundll32
            rundll32 $Imd1yck, 'Control_RunDLL';
```

Searching the IOCs on Virtustotal I've found references for the emotet malware.

<figure><img src="../../../.gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Questions

What security protocol is being used for the communication with a malicious domain?

```
TLS 1.2
```

What directory does the obfuscated PowerShell create? (Starting from \HOME)

```
\HOME\Db_bh30\Yf5be5g
```

What file is being downloaded (full name)?

```
A69S.dll
```

What is used to execute the downloaded file?

```
rundll
```

What is the domain name of the URI ending in ‘/6F2gd/’

```
wm.mcdevelop.net
```

Based on the analysis of the obfuscated code, what is the name of the malware?

```
emotet
```
