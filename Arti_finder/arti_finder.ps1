# It allows you to investigate a Windows machine and look for possible artifacts that may have been left behind after its infection.

# Copyright (C) 2022 Alguna, Cyberzen (https://www.cyberzen.com/)
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program; if not, see <https://www.gnu.org/licenses>.

$ascii_art = @"
                _   _ _  __ _           _           
     /\        | | (_| )/ _(_)         | |          
    /  \   _ __| |_ _|/| |_ _ _ __   __| | ___ _ __ 
   / /\ \ | '__| __| | |  _| | '_ \ / _` |/ _ \ '__|
  / ____ \| |  | |_| | | | | | | | | (_| |  __/ |   
 /_/    \_\_|   \__|_| |_| |_|_| |_|\__,_|\___|_|   
                                                    
                                                    by Alguna from Cyberzen
"@

# Array for blacklists
$global:blacklists2use = @()
$global:blacklistsUsed = @()

$global:date = ""

# Total of rules pointed (1 cell per driver)
$global:warnings = @{}

# [example : ? / X] Dictionary for total rules checked (1 cell per blacklist)
$global:rulesChecked = @{}

# [example : X / ?] Dictionaries for rules pointed (1 dictionary per driver and 1 cell per blacklist)
$global:rules4HKCU = @{}
$global:rules4HKLM  = @{}

# Know if the current user is an administrator or not
function Check-User {
    Write-Host "Are you an administrator ?" -ForegroundColor Blue
    Write-Host "--------------------------" -ForegroundColor Blue "`n"

    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "The script must be run as an administrator."
        Break
    } else {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "The script has been launched as administrator."
    }
    
    Write-Host ""
}

# Know if HKEY_CURRENT_USER and HKEY_LOCAL_MACHINE have been exposed as drivers
function Check-Drivers {
    $registers = Get-PSDrive

    Write-Host "Drivers present ?" -ForegroundColor Blue
    Write-Host "-----------------" -ForegroundColor Blue "`n"

    foreach ($register in $registers) {
        if ($register.ToString() -eq "HKCU") {
            $hkcu = $true
        }

        if ($register.ToString() -eq "HKLM") {
            $hklm = $true
        }
    }

    if ($hkcu) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "The driver HKEY_CURRENT_USER is present."
    } else {
        Write-Host "[!] " -ForegroundColor Red -NoNewline
        Write-Host "HKEY_CURRENT_USER has not been exposed as a driver by the Windows PowerShell registry provider."
    }

    if ($hklm) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "The driver HKEY_LOCAL_MACHINE is present."
    } else {
        Write-Host "[!] " -ForegroundColor Red -NoNewline
        Write-Host "HKEY_LOCAL_MACHINE has not been exposed as a driver by the Windows PowerShell registry provider."
    }

    Write-Host ""
}

# Get directory of blacklists
function Check-Blacklist {
    Write-Host "Blacklists present ?" -ForegroundColor Blue
    Write-Host "--------------------" -ForegroundColor Blue "`n"

    # Get the actual path
    $path = pwd

    $folder = $path.ToString() + "\Blacklists"

    if (Test-Path $folder) {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "The directory Blacklist is present."

        $items = Get-ChildItem $folder

        foreach ($item in $items) {
            # List all files
            if ($item.Mode -eq "-a----") {
                $itemname = $item.Name
                $fullpath = "$folder\$itemname"
                $global:blacklists2use += $fullpath

                Write-Host "[+] " -ForegroundColor Green -NoNewline
                Write-Host "The blacklist $itemname was found."
            }
        }
    } else {
        Write-Host "[!] " -ForegroundColor Red -NoNewline
        Write-Host "Need to have a directory with blacklists."

        Exit
    }

    Write-Host ""
}

# Prepare the environment
function Be-Prepared {
    Write-Host "Prepare the environment" -ForegroundColor Blue
    Write-Host "-----------------------" -ForegroundColor Blue "`n"

    # Get the actual path
    $path = pwd

    $folder = $path.ToString() + "\Outputs"

     # Create the old directory "Outputs"
    if (Test-Path $folder) {
        Remove-Item -Path $folder -Recurse

        Write-Host "[-] " -ForegroundColor Yellow -NoNewline
        Write-Host "The folder Outputs was delete."
    }

    # Create the directory "Outputs"
    try {
        New-Item -Path $folder -ItemType Directory -ErrorAction Stop | Out-null

        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "The folder Outputs was create."
    } catch {
        Write-Host "[!] " -ForegroundColor Red -NoNewline
        Write-Host "Impossible to create the folder Outputs."

        Exit
    }

    $folder = $path.ToString() + "\Reports"

    # Create the directory "Reports"
    if (-not (Test-Path $folder)) {
        $ErrorActionPreference = "stop"

        try {
            New-Item -Path $folder -ItemType Directory -ErrorAction Stop | Out-null

            Write-Host "[+] " -ForegroundColor Green -NoNewline
            Write-Host "The folder Reports was create."
        } catch {
            Write-Host "[!] " -ForegroundColor Red -NoNewline
            Write-Host "Impossible to create the folder Reports."

            Exit
        }
    }

    # Begin the timer of the analysis
    $watch = New-Object System.Diagnostics.Stopwatch
    $watch.Start()

    # Register the date
    $global:date = (Get-Date -format "MM-dd-yyyy_HH-mm-ss").ToString()
    Write-Host "[?] " -ForegroundColor Cyan -NoNewline
    Write-Host "Scan started: $global:date." "`n"

    return $watch
}

# Get keys of registers and their values
function Get-KeyValues {
    Param ($path)

    Write-Host "Let's search in $path" -ForegroundColor Blue
    $separator = "----------------" + '-' * $path.length
    Write-Host $separator -ForegroundColor Blue "`n"
    
    # Search all registers keys
    Get-ChildItem -path $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $name = $_.Name | Out-String
        $properties = $_.Property

        #Write-Host $name -ForegroundColor Yellow -NoNewline

        if ($properties.length -ne 0) {
            foreach ($property in $properties) {
                #Write-Host "--> " -NoNewline
                #Write-Host $property -ForegroundColor Blue -NoNewline ": "

                $path2property = "Registry::" + $name.ToString().Trim()

                # For registers with not ASCII name
                $ErrorActionPreference = "stop"

                try {
                    $value = Get-ItemPropertyValue -LiteralPath $path2property -Name $property
                } catch {
                    Continue
                }
                
                #Write-Host $value -ForegroundColor Green

                # Verify everything (register, property, value) possible
                if ($value -eq $null) {
                    $global:warnings.$path += Search_Blacklist $path $name $property $null
                } else {
                    $global:warnings.$path += Search_Blacklist $path $name $property $value
                }
            }
        } else {
            # Just verify the register
            $global:warnings.$path += Search_Blacklist $path $name $null $null
        }
    }

    if ($global:warnings.$path -ne 0) {
        Write-Host "`n[!] " -ForegroundColor Red -NoNewline

        if ($global:warnings.$path -eq 1) {
            Write-Host "$($global:warnings.$path) suspicious activity founded.`n"
        } else {
            Write-Host "$($global:warnings.$path) suspicious activities founded.`n"
        }
    } else {
        Write-Host "[+] " -ForegroundColor Green -NoNewline
        Write-Host "No suspicious activity founded.`n"
    }
}

# Compares values with those in the blacklist
function Search_Blacklist {
    Param ($driver, $name, $property, $value)

    $something = 0

    # Get the actual path
    $path = pwd

    # Search in all blacklist used by the scan (even the one who gave nothing)
    foreach ($list in $global:blacklists2use) {
        $file = New-Object System.IO.StreamReader($list)

        while (($line = $file.readline()) -ne $null) {
            # Title of the Ransomware or exploit
            if ($line -match "^\[title\]") {
                $title = $line.ToString().Trim().Replace("[title]", "")
                $offset = ' ' * ($title.length + 4)
                $folder = $path.ToString() + "\Outputs\" + $title + ".txt"
            }

            # Number of total rules
            if ($line -match "^\[rules\]") {
                $totalRules = $line.ToString().Trim().Replace("[rules]", "")

                if (-not ($global:rulesChecked.$title)) {
                    $global:rulesChecked += @{$title = $totalRules}
                }
                
                if ($driver.ToString() -match "^HKCU") {
                    if (-not ($global:rules4HKCU.$title)) {
                        $global:rules4HKCU += @{$title = 1}
                    }
                } elseif ($driver.ToString() -match "^HKLM") {
                    if (-not ($global:rules4HKLM.$title)) {
                        $global:rules4HKLM += @{$title = 1}
                    }
                }
            }

            # Remove comments
            if ($line -notmatch "^#") {
                if ($line -match "^\[name\]") {
                    $name2compare = $line.ToString().Trim().Replace("[name]", "")

                    # Registers without properties
                    if ($name2compare -eq $name.ToString().TrimEnd("`r?`n") -and $property -eq $null -and $value -eq $null) {
                        Write-Host "[" $title.ToString().ToUpper() "] " -ForegroundColor Magenta -NoNewline
                        Write-Host $name -ForegroundColor Yellow -NoNewline

                        $out = $name.ToString().TrimEnd("`r?`n") | Out-File -FilePath $folder -Append
                        $something += 1

                        if ($driver.ToString() -match "^HKCU") {
                            $global:rules4HKCU.$title++
                        } elseif ($driver.ToString() -match "^HKLM") {
                            $global:rules4HKLM.$title++
                        }

                        if (-not ($global:blacklistsUsed -contains $title)) {
                            $global:blacklistsUsed += $title
                        }
                    }
                } elseif ($line.ToString().Trim() -match "^\[property\]") {
                    $property2compare = $line.ToString().Trim().Replace("[property]", "")
                    
                    if ($property -ne $null) {
                    # Properties without values
                        if ($name2compare -eq $name.ToString().TrimEnd("`r?`n") -and $property2compare -eq $property.ToString().TrimEnd("`r?`n") -and ($value -eq $null -or $value.ToString().TrimEnd("`r?`n") -eq "")) {
                            Write-Host "[" $title.ToString().ToUpper() "] " -ForegroundColor Magenta -NoNewline
                            Write-Host $name -ForegroundColor Yellow -NoNewline
                            Write-Host $offset "--> " -NoNewline
                            Write-Host $property -ForegroundColor Blue -NoNewline ": "

                            $out = $name.ToString().TrimEnd("`r?`n") | Out-File -FilePath $folder -Append
                            $out = "`t--> $property" | Out-File -FilePath $folder -Append

                            if ($value -eq $null) {
                                Write-Host "(null)" -ForegroundColor Green
                                $out = "`t`t--> (null)" | Out-File -FilePath $folder -Append
                            } elseif ($value.ToString().TrimEnd("`r?`n") -eq "") {
                                Write-Host "(empty space)" -ForegroundColor Green
                                $out = "`t`t--> (empty space)" | Out-File -FilePath $folder -Append
                            }
                            
                            $something += 1
                            
                            if ($driver.ToString() -match "^HKCU") {
                                $global:rules4HKCU.$title++
                            } elseif ($driver.ToString() -match "^HKLM") {
                                $global:rules4HKLM.$title++
                            }

                            if (-not ($global:blacklistsUsed -contains $title)) {
                                $global:blacklistsUsed += $title
                            }
                        }
                    }
                } elseif ($line.ToString().Trim() -match "^\[value\]") {
                    $value2compare = $line.ToString().Trim().Replace("[value]", "")

                    if ($property -ne $null) {
                        if ($name2compare -eq $name.ToString().TrimEnd("`r?`n") -and $property2compare -eq $property.ToString().TrimEnd("`r?`n") -and $value2compare -eq $value) {
                            Write-Host "[" $title.ToString().ToUpper() "] " -ForegroundColor Magenta -NoNewline
                            Write-Host $name -ForegroundColor Yellow -NoNewline
                            Write-Host $offset "--> " -NoNewline
                            Write-Host $property -ForegroundColor Blue -NoNewline ": "
                            Write-Host $value -ForegroundColor Green

                            $out = $name.ToString().TrimEnd("`r?`n") | Out-File -FilePath $folder -Append
                            $out = "`t--> $property" | Out-File -FilePath $folder -Append
                            $out = "`t`t--> $value" | Out-File -FilePath $folder -Append
                            
                            $something += 1
                            
                            if ($driver.ToString() -match "^HKCU") {
                                $global:rules4HKCU.$title++
                            } elseif ($driver.ToString() -match "^HKLM") {
                                $global:rules4HKLM.$title++
                            }

                            if (-not ($global:blacklistsUsed -contains $title)) {
                                $global:blacklistsUsed += $title
                            }
                        }
                    }
                }
            }
        }

        $file.Close()
        $file.Dispose()
    }

    return $something
}

# Show a short report to the user
function Show-Report {
    Param($time)

    # Get the actual path
    $path = pwd

    Write-Host "Show a short report" -ForegroundColor Blue
    Write-Host "-------------------" -ForegroundColor Blue "`n"

    # Stop the timer of the analysis
    $time = $watch.Elapsed.TotalSeconds

    Write-Host "[+] " -ForegroundColor Green -NoNewline
    Write-Host "Analyses were performed in $time seconds."

    $file = $path.ToString() + "\Outputs\Table.txt"

    # Table
    Write-Host "[?] " -ForegroundColor Cyan -NoNewline
    Write-Host "Percent of rules pointed.`n"
    Write-Host "<------------------------------^---------------------------^--------------------------->"
    $out = "<------------------------------^---------------------------^--------------------------->" | Out-File -FilePath $file -Append
    Write-Host "|    Blacklist                 |    HKCU:\ [...]           |    HKLM:\ [...]           |"
    $out = "|    Blacklist                 |    HKCU:\ [...]           |    HKLM:\ [...]           |" | Out-File -FilePath $file -Append
    Write-Host "|------------------------------|---------------------------|---------------------------|"
    $out = "|------------------------------|---------------------------|---------------------------|" | Out-File -FilePath $file -Append
    
    $len = $global:blacklistsUsed.Count

    if ($len -eq 0) {
        Write-Host "|    NOTHING                   |    NOTHING                |    NOTHING                |"
        $out = "|    NOTHING                   |    NOTHING                |    NOTHING                |" | Out-File -FilePath $file -Append
    }

    for ($n=0; $n -ne $len; $n++) {
        # List all blacklist
        $blacklist = $global:blacklistsUsed[$n].ToString().Split("\")[-1]
        $offset = " " * (24 - $blacklist.length)

        Write-Host "|   " $blacklist $offset "|    " -NoNewline
        $out = "|    $blacklist $offset |    " | Out-File -FilePath $file -Append -NoNewline
        
        # Count the percent of rules pointed on a blacklist (HKCU column)
        if ($global:rules4HKCU.$blacklist -ne $null) {
            # Because we initialize the cell to 1 (defaut)
            $number = [int]::Parse($global:rules4HKCU.$blacklist) - 1
            
            if ($number -lt 10) {
                $offset = " " * 2
            } elseif ($number -lt 100) {
                $offset = " " * 1
            } else {
                $offset = ""
            }

            if ([int]::Parse($global:rulesChecked.$blacklist) -lt 10) {
                $offset += " " * 2
            } elseif ([int]::Parse($global:rulesChecked.$blacklist) -lt 100) {
                $offset += " " * 1
            }
            
            if ($number -gt 0) {
                $percent = [math]::Round((($number / $global:rulesChecked.$blacklist) * 100), 0)
            } else {
                $percent = 0
            }

            if ($percent -lt 10) {
                $offset += " " * 2
            } elseif ($percent -lt 100) {
                $offset += " " * 1
            }

            Write-Host $number "/" $global:rulesChecked.$blacklist " ( " -NoNewline
            $out = "$number / $($global:rulesChecked.$blacklist) ( " | Out-File -FilePath $file -Append -NoNewline

            if ($percent -eq 0) {
                Write-Host $percent "%" -ForegroundColor Green -NoNewline
            } elseif ($percent -lt 50) {
                Write-Host $percent "%" -ForegroundColor Yellow -NoNewline
            } elseif ($percent -lt 75) {
                Write-Host $percent "%" -ForegroundColor Red -NoNewline
            } else {
                Write-Host $percent "%" -ForegroundColor DarkRed -NoNewline
            }

            $out = "$percent %" | Out-File -FilePath $file -Append -NoNewline
            Write-Host " )" $offset " " -NoNewline
            $out = " ) $offset   " | Out-File -FilePath $file -Append -NoNewline
        }

        Write-Host "|    " -NoNewline
        $out = "|    " | Out-File -FilePath $file -Append -NoNewline
        
        # Count the percent of rules pointed on a blacklist (HKLM column)
        if ($global:rules4HKLM.$blacklist -ne $null) {
            # Because we initialize the cell to 1 (defaut)
            $number = [int]::Parse($global:rules4HKLM.$blacklist) - 1
            
            if ($number -lt 10) {
                $offset = " " * 2
            } elseif ($number -lt 100) {
                $offset = " " * 1
            } else {
                $offset = ""
            }

            if ([int]::Parse($global:rulesChecked.$blacklist) -lt 10) {
                $offset += " " * 2
            } elseif ([int]::Parse($global:rulesChecked.$blacklist) -lt 100) {
                $offset += " " * 1
            }

            if ($number -gt 0) {
                $percent = [math]::Round((($number / $global:rulesChecked.$blacklist) * 100), 0)
            } else {
                $percent = 0
            }

            if ($percent -lt 10) {
                $offset += " " * 2
            } elseif ($percent -lt 100) {
                $offset += " " * 1
            }

            Write-Host $number "/" $global:rulesChecked.$blacklist " ( " -NoNewline
            $out = "$number / $($global:rulesChecked.$blacklist) ( " | Out-File -FilePath $file -Append -NoNewline
            
            if ($percent -eq 0) {
                Write-Host $percent "%" -ForegroundColor Green -NoNewline
            } elseif ($percent -lt 50) {
                Write-Host $percent "%" -ForegroundColor Yellow -NoNewline
            } elseif ($percent -lt 75) {
                Write-Host $percent "%" -ForegroundColor Red -NoNewline
            } else {
                Write-Host $percent "%" -ForegroundColor DarkRed -NoNewline
            }
            
            $out = "$percent %" | Out-File -FilePath $file -Append -NoNewline
            Write-Host " )" $offset " |"
            $out = " ) $offset   |" | Out-File -FilePath $file -Append
        } 
    }

    Write-Host "<------------------------------u---------------------------u--------------------------->`n"
    $out = "<------------------------------u---------------------------u--------------------------->" | Out-File -FilePath $file -Append

    $len = $global:warnings.Count

    foreach ($value in $global:warnings.Keys) {
        if ($global:warnings.$value -gt 0) {
            Write-Host "[!] " -ForegroundColor Red -NoNewline
            Write-Host "Total for $($value):" $global:warnings.$value "rules founded."
        } else {
            Write-Host "[+] " -ForegroundColor Green -NoNewline
            Write-Host "Total for $($value): no rules founded."
        }
    }

    Write-Host ""
}

# Build the final report
function Build-Report {
    Write-Host "Build the report" -ForegroundColor Blue
    Write-Host "----------------" -ForegroundColor Blue "`n"

    # Get the actual path
    $path = pwd

    # Convert date to string
    $date_string = $global:date

    $folder = $path.ToString() + "\Outputs"
    $report = $path.ToString() + "\Reports\Report_" + $date_string + ".txt"

    $separator = '-' * 30

    if (Test-Path $folder) {
        $items = Get-ChildItem $folder

        if ($items.length -ne 0) {
            $out = "Report dated from: $global:date`n" | Out-File -FilePath $report -Append

            $fullpath = "$folder\Table.txt"
            $file = New-Object System.IO.StreamReader($fullpath) 

            while (($line = $file.readline()) -ne $null) {
                $out = $line | Out-File -FilePath $report -Append
            }

            $out = "" | Out-File -FilePath $report -Append

            foreach ($value in $global:warnings.Keys) {
                if ($global:warnings.$value -gt 0) {
                    $out = "Total for $($value): $($global:warnings.$value) rules founded." | Out-File -FilePath $report -Append
                } else {
                    $out = "Total for $($value): no rules founded." | Out-File -FilePath $report -Append
                }
            }

            $out = "" | Out-File -FilePath $report -Append

            foreach ($item in $items) {
                # List all files
                if ($item.Mode -eq "-a----" -and $item.Name -ne "Table.txt") {
                    $itemname = $item.Name
                    $fullpath = "$folder\$itemname"

                    $out = "$separator $itemname $separator" | Out-File -FilePath $report -Append

                    $file = New-Object System.IO.StreamReader($fullpath) 

                    while (($line = $file.readline()) -ne $null) {
                        $out = $line | Out-File -FilePath $report -Append
                    }

                    $file.Close()
                    $file.Dispose()             
                }
            }

            Write-Host "[+] " -ForegroundColor Green -NoNewline
            Write-Host "The report was create: Report_$global:date."
        } else {
            Write-Host "[+] " -ForegroundColor Green -NoNewline
            Write-Host "No output founded, no report created."
        }
    }

    Write-Host ""
}

Write-Host $ascii_art "`n"

Check-User
Check-Drivers
Check-Blacklist
$watch = Be-Prepared

#Get-KeyValues "HKCU:\"
#Get-KeyValues "HKCU:\"

# Faster for tests :
Get-KeyValues "HKCU:\AppEvents\"           # Not all rules pointed
Get-KeyValues "HKLM:\BCD00000000\Objects\" # All rules pointed

Show-Report $watch
Build-Report

Write-Host "--------------------------------------"
Write-Host "[+] " -ForegroundColor Green -NoNewline
Write-Host "Finished.`n"