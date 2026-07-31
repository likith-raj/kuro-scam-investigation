# ?? Kuro Scam - Malware Investigation & Incident Response 
 
## ?? Overview 
This repository documents a real-world malware investigation where a scam application (Kuro) attempted to compromise a system. 
 
## ?? Incident Summary 
| Category | Details | 
|----------|---------| 
| Incident Date | 2026-07-29 | 
| Malware Name | Kuro Scam (Electron-based) | 
| Indicators | Domain: trykuro.app, IP: 216.150.1.193 | 
| Risk Level | HIGH | 
| Status | Neutralized | 
 
## ?? Investigation Steps 
### 1. Initial Discovery 
- App installed (Kuro) appeared suspicious 
- No visible activity initially 
- Scammers waiting for bank/login credentials 
 
### 2. Indicators Found 
- ? splunkd.exe process running (masquerading) 
- ? Python script executing (screen capture) 
- ? Registry persistence entries 
- ? Hidden folder in AppData 
 
### 3. Mitigation Actions 
- ? Network disconnected immediately 
- ? Admin CMD opened 
- ? Malicious processes terminated 
- ? Registry entries deleted 
- ? Folder removed 
 
## ??? IOCs (Indicators of Compromise) 
 
### Domains 
- trykuro.app 
- https://trykuro.app/dashboard?download=windows 
 
### IP Addresses 
- 216.150.1.193 
 
### File Paths 
- %C:\Users\hp\AppData\Roaming%\kuro\* 
- %C:\Users\hp\AppData\Roaming%\splunkd\* 
 
### Registry Keys 
- HKLM\Software\Microsoft\Windows\CurrentVersion\Run\kuro 
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run\kuro 
 
### Processes 
- splunkd.exe 
- python.exe (with -c flag) 
 
## ?? Screenshots 
![VirusTotal Report](screenshots/virustotal-report.png) 
 
## ?? Quick Start 
### IOC Scanner 
```bash 
python scripts/ioc-scanner.py 
``` 
 
### Detection Rules 
```yaml 
rule kuro_scam { 
    meta: 
        description = Detects Kuro scam malware indicators 
        author = Likith Raj 
        date = 2026-07-29 
    strings: 
        $domain = trykuro.app 
        $process = splunkd.exe 
        $registry = kuro 
    condition: 
        any of them 
} 
``` 
 
## ?? Lessons Learned 
1. Always verify applications before installation 
2. Monitor processes and network connections 
3. Regular registry checks for persistence 
4. Use multiple antivirus engines 
5. Report suspicious domains to threat intel platforms 
 
## ?? Connect With Me 
- **GitHub:** [likith-raj](https://github.com/likith-raj) 
- **LinkedIn:** [likith-sunny](https://linkedin.com/in/likith-sunny) 
- **Email:** snkth123@gmail.com 
 
## ?? Disclaimer 
This investigation was conducted for educational purposes. 
 
--- 
**Built with ?? by Likith Raj** 
"" 
"## ??? VirusTotal GUI" 
"A beautiful web-based GUI for analyzing URLs using VirusTotal API." 
"" 
"### Quick Start" 
"1. Install dependencies: \`pip install -r virustotal-gui/requirements.txt\`" 
"2. Replace API key in \`virustotal-gui/api/vt_api.py\`" 
"3. Run backend: \`python virustotal-gui/api/vt_api.py\`" 
"4. Open \`virustotal-gui/index.html\` in browser" 
