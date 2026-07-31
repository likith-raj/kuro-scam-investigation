# YARA Rule - Kuro Scam Detection 
rule kuro_scam { 
    meta: 
        description = "Detects Kuro scam malware indicators" 
        author = "Likith Raj" 
        date = "2026-07-29" 
    strings: 
        $domain = "trykuro.app" 
        $process = "splunkd.exe" 
        $registry = "kuro" 
    condition: 
        any of them 
} 
