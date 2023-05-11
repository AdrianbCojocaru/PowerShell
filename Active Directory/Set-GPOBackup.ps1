<#

.SYNOPSIS
    Backup GPOs in a certain domain
.DESCRIPTION
    Used to backup all GPOs linked to an OU in a certain domain
.INPUTS
    N/A
.OUTPUTS
   a folder for each GPO; <OU-Path\GPO-DisplayName>
.EXAMPLE

  .\BackupGpo.ps1
#>



#$gpoNames = "GPOX_Name1_*" # ,"GPOX_Name2_*"
$OUPath = 'OU=Business,OU=Workstations,DC=xx,DC=xx,DC=com'
$backupPath = "D:\Backup\GPO Test" 

# build backup folder path
for ($ia=$OUPath.Split(',').length-1; $ia -ge 0; $ia--) {
     if ($OUPath.Split(',')[$ia] -like "*OU=*"){
         $backupPath += "\" + $OUPath.Split(',')[$ia].split('=')[1]
    }
}

(Get-GPInheritance -target $OUPath).GpoLinks | ForEach-Object {
      $gpoBackupPath = Join-Path $backupPath $_.DisplayName       
      if (!(Test-Path $gpoBackupPath)) {
             New-Item -ItemType Directory -Path "$gpoBackupPath" | Out-Null
      }
      Write-Host "Backup for $($_.DisplayName)"
      Backup-GPO -Name $_.DisplayName -Path "$gpoBackupPath" -Domain france.ad.airfrance.fr
}
<#
foreach ($gpoName in $gpoNames) {
    $gpo = Get-GPO -all -Domain france.ad.airfrance.fr | where {$_.displayname -like $gpoName}
    if ($gpo) {
        $gpo | foreach {
            $gpoBackupPath = Join-Path $backupPath $_.DisplayName       
    
             if (!(Test-Path $gpoBackupPath)) {
                    New-Item -ItemType Directory -Path "$gpoBackupPath" | Out-Null
             }
             Write-Host "Backup for $($_.DisplayName)"
             Backup-GPO -Name $_.DisplayName -Path "$gpoBackupPath" -Domain france.ad.airfrance.fr             
            }
    }
}
#>
