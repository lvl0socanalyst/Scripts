Import-Module PSFalcon

Write-Host "`n=========================================================="
Write-Host "--==CrowdStrike Bulk Host Network Isolation Script==--"
Write-Host "============================================================"

#Requests user input for CS API Client and Secret ID
$client_id = Read-Host -Prompt "`nClient ID"
$client_secret = Read-Host -Prompt "Secret ID"
Request-FalconToken -ClientId $client_id -ClientSecret $client_secret

#Script options
Write-Host "`nChoose desired action:"
Write-Host "1. Isolate host(s)"
Write-Host "2. Revoke isolation on host(s)"
Write-Host "3. Query host(s) for details"

#Reads in users choice
$choice = Read-Host "`nEnter your choice (1, 2 or 3)"

#Input option
Write-Host "`nChoose data input method:"
Write-Host "1. Manually type hostname"
Write-Host "2. Provide path to .csv file"

#Reads in users choice
$input_method = Read-Host "`nEnter your choice (1 or 2)"

#Initialises $hosts
$hosts = @()
#First option (Manually type)
if ($input_method -eq "1") {
    $host_input = Read-Host -Prompt "Enter Hostname"
    $hosts += $host_input
}

#Second option (.csv file)
elseif ($input_method -eq "2") {
    Write-Host "`nRequirements for the .csv:"
    Write-Host "1. Hostnames must be in column A"
    Write-Host "2. The Hostname list should start at Row 1 (no column title)"
    $file_path = Read-Host -Prompt "`nEnter full path to .csv file"
    if (Test-Path $file_path) {
        $hosts = @()
        $raw_lines = Get-Content -Path $file_path | Select-Object  #-Skip 1
        foreach ($line in $raw_lines) {
            $cleaned = $line.Trim().Trim(',','"')
            if ($cleaned -ne "") {
                $hosts += $cleaned
            }
        }
    } else {
        Write-Host "File does not exist in dir"
        exit
    }
}

#Retrieves host id for each hostname
#Invoke-FalconHostAction requires a host id. Therefore, I have to pull the host ids from the hostname or else I cannot use the isolate/lift containment endpoint.
$host_ids = @()
foreach ($hostname in $hosts) {
    $result = Get-FalconHost -Filter "hostname:'$hostname'"
    if ($result) {
        $host_ids += $result
    } else {
        Write-Warning "Host ID not found for $hostname"
    }
}

Write-Host "`nHosts loaded from CSV:"
$hosts | ForEach-Object { Write-Host $_ }

#Switch statement for three options
#Isolate/Lift Containment and retrieve host details
switch ($choice) {
        "1"{
          foreach ($unique_host in $host_ids) {
            #Isolation
            Invoke-FalconHostAction -Name contain -Id $unique_host
            Write-Host "Host '$unique_host' has been network isolated"
        }
    }

        "2" {
            foreach ($unique_host in $host_ids) {
            #Lift containment
            Invoke-FalconHostAction -Name lift_containment -Id $unique_host
            Write-Host "Host '$unique_host' network connection reinstated"
        }
    }
        "3" {
            foreach ($unique_host in $host_ids) {
            #Displays all host details
            $host_details = Get-FalconHost -Id $unique_host
                if ($host_details) {
                $host_details | Format-List *
                } else {
                Write-Host "No host details found for '$unique_host'"
            }
        }
    }
}
