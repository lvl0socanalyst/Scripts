$dir = 'C:\Users\donaldduck\hax\dontopen\malware' #Folder path
$fileFilter = '*.*' #*.exe, *.dll, or *.* to scan everything
$minStringLen = 8   #Minimum printable string length
$outTxt = 'C:\Users\donaldduck\hax\dontopen\secret_results.txt' #Output folder path
$stringsExe = 'C:\Users\donaldduck\Desktop\hax\strings64.exe' #Srings folder path

#Regex patterns
$patterns = @(
    @{ Name = 'IPv4'; Pattern = '\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{1,5})?\b' },
    @{ Name = 'Domain'; Pattern = '(?<![\\/])\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b(?!\.[a-z])' },
    @{ Name = 'URL'; Pattern = '\bhttps?://[^\s"''<>]+' },
    @{ Name = 'Email'; Pattern = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' },
    @{ Name = 'Base64Long'; Pattern = '[A-Za-z0-9+/]{80,}={0,2}' }
)

#Compile regex patterns
$patternObjs = $patterns | ForEach-Object {
    [PSCustomObject]@{
        Name  = $_.Name
        Regex = [regex]::new($_.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
}

#Create a structure to collect matches grouped by pattern
$results = @{}
foreach ($p in $patternObjs) {
    $results[$p.Name] = [System.Collections.Generic.List[string]]::new()
}

#Scan files with strings
Get-ChildItem -Path $dir -File -Filter $fileFilter -ErrorAction SilentlyContinue | ForEach-Object {
    $file = $_.FullName
    Write-Host "Scanning: $file"
    $lines = & $stringsExe -n $minStringLen $file 2>$null
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        foreach ($p in $patternObjs) {
            $matches = $p.Regex.Matches($line)
            foreach ($m in $matches) {
                $results[$p.Name].Add("$($m.Value) | $file")
            }
        }
    }
}

#Write results as pattern
if (Test-Path $outTxt) { Remove-Item $outTxt -Force }

"Scan results" | Out-File -FilePath $outTxt -Encoding UTF8
"Directory: $dir" | Out-File -FilePath $outTxt -Encoding UTF8 -Append
"------------------------------------------------------------" | Out-File -FilePath $outTxt -Encoding UTF8 -Append

foreach ($patternName in $results.Keys) {
    "" | Out-File -FilePath $outTxt -Encoding UTF8 -Append
    "=== Pattern: $patternName ===" | Out-File -FilePath $outTxt -Encoding UTF8 -Append
    if ($results[$patternName].Count -eq 0) {
        "  (no matches)" | Out-File -FilePath $outTxt -Encoding UTF8 -Append
    } else {
        $results[$patternName] | Sort-Object -Unique | Out-File -FilePath $outTxt -Encoding UTF8 -Append
    }
}

"------------------------------------------------------------" | Out-File -FilePath $outTxt -Encoding UTF8 -Append
"Scan finished: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $outTxt -Encoding UTF8 -Append
Write-Host "Results written to: $outTxt" -ForegroundColor Green
