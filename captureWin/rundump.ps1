.\WinDump.exe -l -i 4 | ForEach-Object {
    # Match the timestamp and the Base Protocol (IP, IP6, ARP, etc.)
    if ($_ -match '^(\d{2}:\d{2}:\d{2}\.\d+)\s+(IP|IP6|ARP)(.*?)$') {
        $time = $matches[1]
        $baseProto = $matches[2]
        $remainder = $matches[3]

        $src = ""
        $dst = ""
        $proto = $baseProto

        # Handle Standard Routed Traffic (IPv4 / IPv6)
        if ($baseProto -match "IP") {
            if ($remainder -match '^\s+([\w\.:-]+)\s+>\s+([\w\.:-]+):\s+(.*)$') {
                $rawSrc = $matches[1]
                $rawDst = $matches[2]
                $info = $matches[3]

                # Smart Port Stripping & Protocol Guessing
                if ($info -match '^Flags') { 
                    $proto = 'TCP' 
                    $src = $rawSrc -replace '\.[^\.]+$', '' # Strip port
                    $dst = $rawDst -replace '\.[^\.]+$', ''
                }
                elseif ($info -match '^UDP') { 
                    $proto = 'UDP' 
                    $src = $rawSrc -replace '\.[^\.]+$', '' # Strip port
                    $dst = $rawDst -replace '\.[^\.]+$', ''
                }
                elseif ($info -match '^ICMP') {
                    $proto = 'ICMP'
                    $src = $rawSrc # No ports in ICMP
                    $dst = $rawDst
                }
                else {
                    # For anything else (IGMP, ESP, GRE), grab the first word of the info string
                    $proto = ($info.Split(' ')[0]) -replace '[:,]', ''
                    $proto = $proto.ToUpper()
                    $src = $rawSrc -replace '\.[^\.]+$', '' # Try to strip port just in case
                    $dst = $rawDst -replace '\.[^\.]+$', ''
                }
            }
        }
        # Handle ARP Broadcasts
        elseif ($baseProto -eq "ARP") {
            if ($remainder -match 'who-has\s+([\w\.:-]+)\s+tell\s+([\w\.:-]+)') {
                $dst = $matches[1]
                $src = $matches[2]
                $proto = "ARP"
            }
        }
        
        # If we successfully grabbed a source and destination, log it
        if ($src -and $dst) {
            $line = "{""time"":""$time"",""src"":""$src"",""dst"":""$dst"",""proto"":""$proto""}"
            Add-Content -Path stream.ndjson -Value $line
        }
    }
}