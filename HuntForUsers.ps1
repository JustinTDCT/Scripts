# SearchUsersFromPaste.ps1
# Purpose: Accept a pasted list of usernames (one per line, quotes OK) and
#          search Local and AD accounts for exact OR wildcard (*like*) matches.
# Output :
#   - "WARN: Username match - <username>" for each match
#   - "No matches found." if there are none

param(
    # If you want wildcard matching, pass -Like (e.g., *adm*). Default is Exact.
    [switch]$Like,

    # Set this if the machine doesn't have AD tools and you want to skip AD search
    [switch]$SkipAD
)

# ── PASTE YOUR LIST BETWEEN THE LINES BELOW ────────────────────────────────────
# Example accepts lines like:
# "Administrator"
# "jdube"
# "SM_f491f43da8404939a"
# (Quotes and blank lines are fine.)
$PastedUsernames = @'

'@
# ───────────────────────────────────────────────────────────────────────────────

# Normalize pasted content → array of unique usernames (strip quotes/whitespace)
$Usernames =
    $PastedUsernames -split "`r?`n" |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne '' } |
    ForEach-Object { $_.Trim('"').Trim("'") } |
    Select-Object -Unique

if (-not $Usernames -or $Usernames.Count -eq 0) {
    Write-Host "No usernames provided in pasted block." ; exit 1
}

$matchesFound = $false

# ---- Local accounts search ----
try {
    $allLocal = Get-LocalUser -ErrorAction Stop
} catch {
    $allLocal = @()
    Write-Host "Note: Could not query local users (need Admin?). Skipping local search."
}

# ---- AD prep (optional) ----
$adAvailable = $false
if (-not $SkipAD) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adAvailable = $true
    } catch {
        Write-Host "Note: ActiveDirectory module not available; skipping AD search."
    }
}

foreach ($name in $Usernames) {
    # Local match
    if ($allLocal.Count -gt 0) {
        if ($Like) {
            $lm = $allLocal | Where-Object { $_.Name -like $name }
        } else {
            $lm = $allLocal | Where-Object { $_.Name -eq $name }
        }
        foreach ($m in $lm) {
            Write-Host "WARN: Username match - $($m.Name)"
            $matchesFound = $true
        }
    }

    # AD match
    if ($adAvailable) {
        try {
            if ($Like) {
                # supports wildcards in pasted names (e.g., *admin*)
                $ad = Get-ADUser -LDAPFilter "(sAMAccountName=$name)" -ErrorAction Stop
            } else {
                $safe = $name.Replace('\','\\').Replace('(','\28').Replace(')','\29').Replace('*','\2a')
                $ad  = Get-ADUser -LDAPFilter "(sAMAccountName=$safe)" -ErrorAction Stop
            }
            foreach ($m in $ad) {
                Write-Host "WARN: Username match - $($m.SamAccountName)"
                $matchesFound = $true
            }
        } catch {
            # ignore per-name errors to keep loop flowing
        }
    }
}

if (-not $matchesFound) {
    Write-Host "No matches found."
}
