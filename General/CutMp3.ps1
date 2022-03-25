#replace the following with file names that you need

$shell = New-Object -COMObject Shell.Application
$i = 1 
$curDir = (get-item $PSScriptRoot).FullName
New-Item -Path "${curDir}OK" -ItemType Directory
Get-ChildItem $PSScriptRoot | Where-Object { $_.extension -eq '.mp3' } | ForEach-Object { 
 
	#	$output = $names[$i]+".mp3"
	# 
	#	$Time1 = $timelength[$i]
	#	$Time2 = $timelength[$i+1]
	# 
	#	$TimeDiff = New-TimeSpan $Time1 $Time2
	# 
	#	$Hrs = $TimeDiff.Hours * 3600
	#	$Mins = $TimeDiff.Minutes * 60
	#	$Secs = $TimeDiff.Seconds
	# 
	#	$tot = $Hrs+$Mins+$Secs
 
	#$folder = Split-Path $path
	#$file = Split-Path $path -Leaf
	#$shellfolder = $shell.Namespace($folder)
	#$shellfile = $shellfolder.ParseName($file)

	$folder = $PSScriptRoot
	$file = $_.name
	$basename = $_.BaseName
	$shellfolder = $shell.Namespace($folder)
	$shellfile = $shellfolder.ParseName($file)
	$tot = $shellfolder.GetDetailsOf($shellfile, 27)
	#replace input.mp3 with your audio file
	write-host "$PSScriptRoot\${basename}scr.mp3"
	#$parentDir = ((get-item $PSScriptRoot).parent).FullName
	ffmpeg -i "$PSScriptRoot\${file}" -ss 00:00:16 -acodec copy "${curDir}OK\${basename}.mp3"
	$i = $i++
	#if ($i -eq 25) {break}
}

#ffmpeg -i 'C:\Carti\Michel_Zevaco-Regele_Cersetorilor\Michel_Zevaco-Regele_Cersetorilor-Capitolul_50.mp3' -ss 00:00:15
#
#
#$shell = New-Object -COMObject Shell.Application
#
#
#$path = "C:\Carti\Michel_Zevaco-Regele_Cersetorilor\Michel_Zevaco-Regele_Cersetorilor-Capitolul_01.mp3"
#
#$folder = Split-Path $path
#$file = Split-Path $path -Leaf
#$shellfolder = $shell.Namespace($folder)
#$shellfile = $shellfolder.ParseName($file)
#
#$tot = $shellfolder.GetDetailsOf($shellfile, 27); 