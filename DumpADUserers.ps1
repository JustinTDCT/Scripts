# DumpAllADUsers.ps1
# Exports all AD usernames (sAMAccountName) to a CSV

# Ensure AD module is available
Import-Module ActiveDirectory

# Get all enabled and disabled users, selecting only the username
Get-ADUser -Filter * -Properties SamAccountName |
    Select-Object SamAccountName |
    Export-Csv -Path "C:\tab\AD_Usernames.csv" -NoTypeInformation

Write-Output "Export complete. File saved to C:\tab\AD_Usernames.csv"
