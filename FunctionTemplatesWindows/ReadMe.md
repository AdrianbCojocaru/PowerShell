# Function Templates for Windows

This module contains function for some of the most common opperations in Windows OS.

### Write-Log
Used to write a message to the log file and/or the console.

### Write-Header
Used to write the log file header.

### Set-RegistryKey
Used to create registry keys and/or write/update registry values.

### Get-RegistryKey
If the specified Key is empty ==> returns the key path [string]
If the specified Key not found ==> returns $false [bool]
If the Name parameter is specified ==> Returns the value of the registry specified by -Name. [string]
                                   ==>> Returns ValueNotFound if the registry does not exist. [string]
If no Name parameter is specified ==> Returns all the <Name - Value> pair under -Key.[PSCustomObject]

### Copy-Files
Used to copy one or more files.

### Remove-Folder
Used to delete a folder.

### Remove-File
Used to delete one or more files.

### Write-Error2
Used to dump errors to the log file. Parameters needed only for a collection.
