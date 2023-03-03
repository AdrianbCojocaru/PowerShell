$ImageName = "WinPE10-1903"
$ImageExtension = ".wim"
$ImageFullName = "$ImageName$ImageExtension"
$DirPath = "C:\Work\ClientDesign"

Get-WindowsImage -ImagePath "$DirPath\$ImageFullName"
New-Item -ItemType Directory -Path "$DirPath\$ImageName"
Mount-WindowsImage -ImagePath "$DirPath\$ImageFullName" -Index 1 -Path "$DirPath\$ImageName"

Get-WindowsDriver -Path "$DirPath\$ImageName"

#Get-WindowsDriver -Path "$DirPath\$ImageName" -all

#Get-WindowsDriver -Path "$DirPath\$ImageName" -all

Add-WindowsDriver -Path "$DirPath\$ImageName" -Driver "C:\Work\ClientDesign\25_5\PRO1000\Winx64\NDIS68\e1d68x64.inf" -ForceUnsigned


Dismount-WindowsImage -Path "$DirPath\$ImageName" -Save
#Dismount-WindowsImage -Path "$DirPath\$ImageName" -Discard