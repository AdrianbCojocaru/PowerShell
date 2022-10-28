#************************************************
# DC_HotfixRollups.ps1
# Version 1.0.04.02.14: Created script to easily view what rollups are installed for W7/WS2008R2, W8/WS2012, and W8.1/WS2012R2
# Version 1.1.05.16.14: Added W8.1 Update1 (April2014 rollup);  Added OS Version below each heading.
# Version 1.6.10.16.14: Added Oct2014 updates for W8/W8.1
# Date: 2019,2020
# Author: Boyd Benson (bbenson@microsoft.com) +WalterE
# Description: Creates output to easily identify what rollups are installed on W7/WS2008R2 and later.
# Called from: Networking Diagnostics, and all psSDP
#  ToDo: read latest KB# from \xray\xray_WU.psm1 -or- KBonlyRollup_* from RFL
#*******************************************************

Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

Import-LocalizedData -BindingVariable ScriptVariable

$OutputFile = $Env:ComputerName + "_HotfixRollups.TXT"
$sectionDescription = "Hotfix Rollups"


function CheckForHotfix ($hotfixID, $title, $Warn="")
{
	$hotfixesWMIQuery = "SELECT * FROM Win32_QuickFixEngineering WHERE HotFixID='KB$hotfixID'"
	$hotfixesWMI = Get-CimInstance -query $hotfixesWMIQuery #_# or PS > Get-HotFix
	$link = "http://support.microsoft.com/kb/" + $hotfixID
	if ($null -eq $hotfixesWMI)
	{
		"No          $hotfixID - $title   ($link)" | Out-File -FilePath $OutputFile -append
		If ($Warn -match "Yes") {
			Write-Host "This system is not up-to-date. Many known issues are resolved by applying latest cumulative update!"
			Write-Host -ForegroundColor Red "*** [WARNING] latest OS cumulative KB $hotfixID is missing.`n Please update this machine with recommended Microsoft KB $hotfixID and verify if your issue is resolved."
			$Global:MissingCU = $hotfixID
		}
	}
	else
	{
		"Yes         $hotfixID - $title   ($link)" | Out-File -FilePath $OutputFile -append
	}
}

#----------detect OS version and SKU
	$wmiOSVersion = Get-WmiObject -Namespace "root\cimv2" -Class Win32_OperatingSystem
	[int]$bn = [int]$wmiOSVersion.BuildNumber
	#$sku = $((Get-WmiObject win32_operatingsystem).OperatingSystemSKU)

if ($bn -match 22621) # Win 11 22H2 = 22621
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 11 22H2" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5019509 -title "October 18, 2022-KB5019509 (OS Build 22621.675) Out-of-band" -Warn "Yes"
	CheckForHotfix -hotfixID 5018427 -title "October 11, 2022-KB5018427 (OS Build 22621.674)"
	CheckForHotfix -hotfixID 5017389 -title "September 30, 2022-KB5017389 (OS Build 22621.608) Preview"
}

elseif ($bn -match 2200) # Win 11 = 22000
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 11 " | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5020387 -title "October 17, 2022-KB5020387 (OS Build 22000.1100) Out-of-band)" -Warn "Yes"
	CheckForHotfix -hotfixID 5018418 -title "October 11, 2022-KB5018418 (OS Build 22000.1098)"
	CheckForHotfix -hotfixID 5017328 -title "September 13, 2022-KB5017328 (OS Build 22000.978)"
	CheckForHotfix -hotfixID 5016629 -title "August 9, 2022-KB5016629 (OS Build 22000.856)"
	CheckForHotfix -hotfixID 5015814 -title "July 12, 2022-KB5015814 (OS Build 22000.795)"
	CheckForHotfix -hotfixID 5014697 -title "June 14, 2022-KB5014697 (OS Build 22000.739)"
	CheckForHotfix -hotfixID 5013943 -title "May 10, 2022-KB5013943 (OS Build 22000.675)" 
	CheckForHotfix -hotfixID 5012592 -title "April 12, 2022-KB5012592 (OS Build 22000.613)"
	CheckForHotfix -hotfixID 5011493 -title "March 8, 2022-KB5011493 (OS Build 22000.556)"
	CheckForHotfix -hotfixID 5010386 -title "February 8, 2022-KB5010386 (OS Build 22000.493)"
	CheckForHotfix -hotfixID 5009566 -title "January 11, 2022-KB5009566 (OS Build 22000.434)"
	CheckForHotfix -hotfixID 5008215 -title "December 14, 2021-KB5008215 (OS Build 22000.376)"
	CheckForHotfix -hotfixID 5007215 -title "November 9, 2021-KB5007215 (OS Build 22000.318)"
	CheckForHotfix -hotfixID 5006674 -title "October 12, 2021-KB5006674 (OS Build 22000.258)"
}

elseif ($bn -match 20348) # Server 2022 = 20348
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows Server 2022 " | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5020436 -title "October 17, 2022-KB5020436 (OS Build 20348.1131) Out-of-band" -Warn "Yes"
	CheckForHotfix -hotfixID 5018421 -title "October 11, 2022-KB5018421 (OS Build 20348.1129)"
	CheckForHotfix -hotfixID 5017316 -title "September 13, 2022-KB5017316 (OS Build 20348.1006)"
	CheckForHotfix -hotfixID 5016627 -title "August 9, 2022-KB5016627 (OS Build 20348.887)"
	CheckForHotfix -hotfixID 5015827 -title "July 12, 2022-KB5015827 (OS Build 20348.825)"
	CheckForHotfix -hotfixID 5014678 -title "June 14, 2022-KB5014678 (OS Build 20348.768)"
	CheckForHotfix -hotfixID 5013944 -title "May 10, 2022-KB5013944 (OS Build 20348.707)"
	CheckForHotfix -hotfixID 5012604 -title "April 12, 2022-KB5012604 (OS Build 20348.643)"
	CheckForHotfix -hotfixID 5011497 -title "March 8, 2022-KB5011497 (OS Build 20348.587)"
	CheckForHotfix -hotfixID 5010354 -title "February 8, 2022-KB5010354 (OS Build 20348.524)"
	CheckForHotfix -hotfixID 5009555 -title "January 11, 2022-KB5009555 (OS Build 20348.469)"
	CheckForHotfix -hotfixID 5008223 -title "December 14, 2021-KB5008223 (OS Build 20348.405)"
	CheckForHotfix -hotfixID 5007205 -title "November 9, 2021-KB5007205 (OS Build 20348.350)"
	CheckForHotfix -hotfixID 5006699 -title "October 12, 2021-KB5006699 (OS Build 20348.288)"
}
elseif ($bn -match 1904) # 2004 = 19041, 20H2 = 19042, 21H1 = 19043, 21H2 = 19044, 22H2 = 19045
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 20H2/21H1/21H2/22H2 and Windows Server 2019 20H1/20H2/21H1/21H2 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5020435 -title "October 17, 2022-KB5020435 (OS Builds 19042.2132, 19043.2132, and 19044.2132) Out-of-band" -Warn "Yes"
	CheckForHotfix -hotfixID 5018410 -title "October 11, 2022-KB5018410 (OS Builds 19042.2130, 19043.2130, and 19044.2130)"
	CheckForHotfix -hotfixID 5017308 -title "September 13, 2022-KB5017308 (OS Builds 19042.2006, 19043.2006, and 19044.2006)" 
	CheckForHotfix -hotfixID 5016616 -title "August 9, 2022-KB5016616 (OS Builds 19042.1889, 19043.1889, and 19044.1889)"
	CheckForHotfix -hotfixID 5015807 -title "July 12, 2022-KB5015807 (OS Builds 19042.1826, 19043.1826, and 19044.1826)"
	CheckForHotfix -hotfixID 5014699 -title "June 14, 2022-KB5014699 (OS Builds 19042.1766, 19043.1766, and 19044.1766)"
	CheckForHotfix -hotfixID 5013942 -title "May 10, 2022-KB5013942 (OS Builds 19042.1706, 19043.1706, and 19044.1706)"
	CheckForHotfix -hotfixID 5012599 -title "April 12, 2022-KB5012599 (OS Builds 19042.1645, 19043.1645, and 19044.1645)" 
	CheckForHotfix -hotfixID 5011487 -title "March 8, 2022-KB5011487 (OS Builds 19042.1586, 19043.1586, and 19044.1586)"
	CheckForHotfix -hotfixID 5010342 -title "February 8, 2022-KB5010342 (OS Builds 19042.1526, 19043.1526, and 19044.1526)"
	CheckForHotfix -hotfixID 5009543 -title "January 11, 2022-KB5009543 (OS Builds 19042.1466, 19043.1466, and 19044.1466)"
	CheckForHotfix -hotfixID 5008212 -title "December 14, 2021-KB5008212 (OS Builds 19041.1415, 19042.1415, 19043.1415, and 19044.1415)"
	CheckForHotfix -hotfixID 5007186 -title "November 9, 2021-KB5007186 (OS Builds 19041.1348, 19042.1348, and 19043.1348)"
	CheckForHotfix -hotfixID 5006670 -title "October 12, 2021-KB5006670 (OS Builds 19041.1288, 19042.1288, and 19043.1288)"
	CheckForHotfix -hotfixID 5005611 -title "September 30, 2021-KB5005611 (OS Builds 19041.1266, 19042.1266, and 19043.1266) Preview"
	CheckForHotfix -hotfixID 5005565 -title "September 14, 2021-KB5005565 (OS Builds 19041.1237, 19042.1237, and 19043.1237)"
	CheckForHotfix -hotfixID 5005033 -title "August 10, 2021-KB5005033 (OS Builds 19041.1165, 19042.1165, and 19043.1165))"
	CheckForHotfix -hotfixID 5004237 -title "July 13, 2021-KB5004237 (OS Builds 19041.1110, 19042.1110, and 19043.1110)"
	CheckForHotfix -hotfixID 5003637 -title "June 8, 2021-KB5003637 (OS Builds 19041.1052, 19042.1052, and 19043.1052)"
	CheckForHotfix -hotfixID 5003173 -title "May 11, 2021-KB5003173 (OS Builds 19041.985 and 19042.985)"
	CheckForHotfix -hotfixID 5001330 -title "April 13, 2021-KB5001330 (OS Builds 19041.928 and 19042.928)"
	CheckForHotfix -hotfixID 5001649 -title "March 18, 2021-KB5001649 (OS Builds 19041.870 and 19042.870) Out-of-band"
	CheckForHotfix -hotfixID 4601319 -title "February 9, 2021-KB4601319 (OS Builds 19041.804 and 19042.804)"
	CheckForHotfix -hotfixID 4598481 -title "Servicing stack update for Windows 10, version 2004 and 20H2: January 12, 2021"
}
elseif ($bn -match  1836) # 1903 = 18362, 1909 = 18363
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 19H2 v1909 and Windows Server 2019 19H2 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5013945 -title "May 10, 2022-KB5013945 (OS Build 18363.2274)" -Warn "Yes"
	CheckForHotfix -hotfixID 5012591 -title "April 12, 2022-KB5012591 (OS Build 18363.2212)"
	CheckForHotfix -hotfixID 5011485 -title "March 8, 2022-KB5011485 (OS Build 18363.2158)"
	CheckForHotfix -hotfixID 5010345 -title "February 8, 2022-KB5010345 (OS Build 18363.2094)"
	CheckForHotfix -hotfixID 5009545 -title "January 11, 2022-KB5009545 (OS Build 18363.2037)"
	CheckForHotfix -hotfixID 5008206 -title "December 14, 2021-KB5008206 (OS Build 18363.1977)"
	CheckForHotfix -hotfixID 5007189 -title "November 9, 2021-KB5007189 (OS Build 18362.1916)"
	CheckForHotfix -hotfixID 5006667 -title "October 12, 2021-KB5006667 (OS Build 18363.1854)"
	CheckForHotfix -hotfixID 5005566 -title "September 14, 2021-KB5005566 (OS Build 18363.1801)"
	CheckForHotfix -hotfixID 5005031 -title "August 10, 2021-KB5005031 (OS Build 18363.1734)"
	CheckForHotfix -hotfixID 5004245 -title "July 13, 2021-KB5004245 (OS Build 18363.1679)"
	CheckForHotfix -hotfixID 5003635 -title "June 8, 2021-KB5003635 (OS Build 18363.1621)"
	CheckForHotfix -hotfixID 4601395 -title "KB4601395: Servicing stack update for Windows 10, version 1903: February 9, 2021"
}
elseif ($bn -eq 17763)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 RS5 v1809 and Windows Server 2019 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5020438 -title "October 17, 2022-KB5020438 (OS Build 17763.3534) Out-of-band" -Warn "Yes"
	CheckForHotfix -hotfixID 5018419 -title "October 11, 2022-KB5018419 (OS Build 17763.3532)"
	CheckForHotfix -hotfixID 5017315 -title "September 13, 2022-KB5017315 (OS Build 17763.3406)"
	CheckForHotfix -hotfixID 5016623 -title "August 9, 2022-KB5016623 (OS Build 17763.3287)"
	CheckForHotfix -hotfixID 5015811 -title "July 12, 2022-KB5015811 (OS Build 17763.3165)"
	CheckForHotfix -hotfixID 5014692 -title "June 14, 2022-KB5014692 (OS Build 17763.3046)"
	CheckForHotfix -hotfixID 5013941 -title "May 10, 2022-KB5013941 (OS Build 17763.2928)"
	CheckForHotfix -hotfixID 5012647 -title "April 12, 2022-KB5012647 (OS Build 17763.2803)"
	CheckForHotfix -hotfixID 5011503 -title "March 8, 2022-KB5011503 (OS Build 17763.2686)"
	CheckForHotfix -hotfixID 5010351 -title "February 8, 2022-KB5010351 (OS Build 17763.2565)"
	CheckForHotfix -hotfixID 5009557 -title "January 11, 2022-KB5009557 (OS Build 17763.2452)"
	CheckForHotfix -hotfixID 5008218 -title "December 14, 2021-KB5008218 (OS Build 17763.2366)"
	CheckForHotfix -hotfixID 5007206 -title "November 9, 2021-KB5007206 (OS Build 17763.2300)"
	CheckForHotfix -hotfixID 5006672 -title "October 12, 2021-KB5006672 (OS Build 17763.2237)"
	CheckForHotfix -hotfixID 5005568 -title "September 14, 2021-KB5005568 (OS Build 17763.2183)"
	CheckForHotfix -hotfixID 5005030 -title "August 10, 2021-KB5005030 (OS Build 17763.2114"
	CheckForHotfix -hotfixID 5004244 -title "July 13, 2021-KB5004244 (OS Build 17763.2061)"
	CheckForHotfix -hotfixID 5003646 -title "June 8, 2021-KB5003646 (OS Build 17763.1999)"
	CheckForHotfix -hotfixID 5003171 -title "May 11, 2021-KB5003171 (OS Build 17763.1935)"
	CheckForHotfix -hotfixID 5001342 -title "April 13, 2021-KB5001342 (OS Build 17763.1879)"
	CheckForHotfix -hotfixID 5001638 -title "March 18, 2021-KB5001638 (OS Build 17763.1823) Out-of-band"
	CheckForHotfix -hotfixID 4601345 -title "February 9, 2021-KB4601345 (OS Build 17763.1757)"
	CheckForHotfix -hotfixID 4601393 -title "KB4601393: Servicing stack update for Windows 10, version 1809: February 9, 2021"
}
elseif ($bn -eq 14393)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 RS1 v1607 and Windows Server 2016 RS1 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5020439 -title "October 18, 2022—KB5020439 (OS Build 14393.5429) Out-of-band" -Warn "Yes"
	CheckForHotfix -hotfixID 5018411 -title "October 11, 2022-KB5018411 (OS Build 14393.5427)"
	CheckForHotfix -hotfixID 5017305 -title "September 13, 2022-KB5017305 (OS Build 14393.5356)"
	CheckForHotfix -hotfixID 5016622 -title "August 9, 2022-KB5016622 (OS Build 14393.5291)"
	CheckForHotfix -hotfixID 5015808 -title "July 12, 2022-KB5015808 (OS Build 14393.5246)"
	CheckForHotfix -hotfixID 5014702 -title "June 14, 2022-KB5014702 (OS Build 14393.5192)"
	CheckForHotfix -hotfixID 5013952 -title "May 10, 2022-KB5013952 (OS Build 14393.5125)"
	CheckForHotfix -hotfixID 5012596 -title "April 12, 2022-KB5012596 (OS Build 14393.5066)"
	CheckForHotfix -hotfixID 5011495 -title "March 8, 2022-KB5011495 (OS Build 14393.5006)"
	CheckForHotfix -hotfixID 5010359 -title "February 8, 2022-KB5010359 (OS Build 14393.4946)"
	CheckForHotfix -hotfixID 5009546 -title "January 11, 2022-KB5009546 (OS Build 14393.4886)"
	CheckForHotfix -hotfixID 5008207 -title "December 14, 2021-KB5008207 (OS Build 14393.4825)"
	CheckForHotfix -hotfixID 5007192 -title "November 9, 2021-KB5007192 (OS Build 14393.4770)"
	CheckForHotfix -hotfixID 5006669 -title "October 12, 2021-KB5006669 (OS Build 14393.4704)"
	CheckForHotfix -hotfixID 5005573 -title "September 14, 2021-KB5005573 (OS Build 14393.4651)"
	CheckForHotfix -hotfixID 5005043 -title "August 10, 2021-KB5005043 (OS Build 14393.4583)"
	CheckForHotfix -hotfixID 5004238 -title "July 13, 2021-KB5004238 (OS Build 14393.4530)"
	CheckForHotfix -hotfixID 5003638 -title "June 8, 2021-KB5003638 (OS Build 14393.4467)"
	CheckForHotfix -hotfixID 5003197 -title "May 11, 2021-KB5003197 (OS Build 14393.4402)"
	CheckForHotfix -hotfixID 5001347 -title "April 13, 2021-KB5001347 (OS Build 14393.4350)"
	CheckForHotfix -hotfixID 5001633 -title "March 18 2021-KB5001633 (OS Build 14393.4288) Out-of-band"
	CheckForHotfix -hotfixID 4601318 -title "February 9, 2021-KB4601318 (OS Build 14393.4225)" 
	CheckForHotfix -hotfixID 4601392 -title "Servicing stack update for Windows 10, version 1607: Februar 9, 2021"
}	
elseif ($bn -eq 10240)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 10 and Windows Server 2016 RTM Rollups"	 | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5020440 -title "October 18, 2022-KB5020440 (OS Build 10240.19509) Out-of-band" -Warn "Yes"
	CheckForHotfix -hotfixID 5018425 -title "October 11, 2022-KB5018425 (OS Build 10240.19507)"
	CheckForHotfix -hotfixID 5017327 -title "September 13, 2022-KB5017327 (OS Build 10240.19444)" 
	CheckForHotfix -hotfixID 5016639 -title "August 9, 2022-KB5016639 (OS Build 10240.19387)"
	CheckForHotfix -hotfixID 5015832 -title "July 12, 2022-KB5015832 (OS Build 10240.19360)"
	CheckForHotfix -hotfixID 5014710 -title "June 14, 2022-KB5014710 (OS Build 10240.19325)"
	CheckForHotfix -hotfixID 5013963 -title "May 10, 2022-KB5013963 (OS Build 10240.19297)"
	CheckForHotfix -hotfixID 5012653 -title "April 12, 2022-KB5012653 (OS Build 10240.19265)"
	CheckForHotfix -hotfixID 5011491 -title "March 8, 2022-KB5011491 (OS Build 10240.19235)"
	CheckForHotfix -hotfixID 5010358 -title "February 8, 2022-KB5010358 (OS Build 10240.19204)"
	CheckForHotfix -hotfixID 5009585 -title "January 11, 2022-KB5009585 (OS Build 10240.19177)"
	CheckForHotfix -hotfixID 5008230 -title "December 14, 2021-KB5008230 (OS Build 10240.19145)"
	CheckForHotfix -hotfixID 5007207 -title "November 9, 2021-KB5007207 (OS Build 10240.19119)"
	CheckForHotfix -hotfixID 5006675 -title "October 12, 2021-KB5006675 (OS Build 10240.19086)"
	CheckForHotfix -hotfixID 5005569 -title "September 14, 2021-KB5005569 (OS Build 10240.19060)"
	CheckForHotfix -hotfixID 5005040 -title "August 10, 2021-KB5005040 (OS Build 10240.19022)"
	CheckForHotfix -hotfixID 5004249 -title "July 13, 2021-KB5004249 (OS Build 10240.19003)"
	CheckForHotfix -hotfixID 5003687 -title "June 8, 2021-KB5003687 (OS Build 10240.18967)"
	CheckForHotfix -hotfixID 5003172 -title "May 11, 2021-KB5003172 (OS Build 10240.18932)"
	CheckForHotfix -hotfixID 5001340 -title "April 13, 2021-KB5001340 (OS Build 10240.18906)"
	CheckForHotfix -hotfixID 5001631 -title "March 18, 2021-KB5001631 (OS Build 10240.18875) Out-of-band"
	CheckForHotfix -hotfixID 4601331 -title "February 9, 2021-KB4601331 (OS Build 10240.18842)"
	CheckForHotfix -hotfixID 4601390 -title "KB4601390: Servicing stack update for Windows 10: February 9, 2021"
}
elseif ($bn -eq 9600)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 8.1 and Windows Server 2012 R2 Rollups"	 | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5018474 -title "October 11, 2022-KB5018474 (Monthly Rollup)" -Warn "Yes"
	CheckForHotfix -hotfixID 5017367 -title "September 13, 2022-KB5017367 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5016681 -title "August 9, 2022-KB5016681 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5015874 -title "July 12, 2022-KB5015874 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014738 -title "June 14, 2022-KB5014738 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014011 -title "May 10, 2022-KB5014011 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5012670 -title "April 12, 2022-KB5012670 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5011564 -title "March 8, 2022-KB5011564 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5010419 -title "February 8, 2022-KB5010419 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5009624 -title "January 11, 2022-KB5009624 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5008263 -title "December 14, 2021-KB5008263 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5007247 -title "November 9, 2021-KB5007247 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5006714 -title "October 12, 2021-KB5006714 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005613 -title "September 14, 2021-KB5005613 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005076 -title "August 10, 2021-KB5005076 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5004298 -title "July 13, 2021-KB5004298 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003671 -title "June 8, 2021-KB5003671 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003209 -title "May 11, 2021-KB5003209 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5001382 -title "April 13, 2021-KB5001382 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5000848 -title "March 9, 2021-KB5000848 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4601384 -title "February 9, 2021-KB4601384 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4566425 -title "Servicing stack update for Windows 8.1, RT 8.1, and Server 2012 R2: July 14, 2020"
	CheckForHotfix -hotfixID 4541509 -title "March 10, 2020-KB4541509 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4537821 -title "February 11, 2020-KB4537821 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4534297 -title "January 14, 2020-KB4534297 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4530702 -title "December 10, 2019-KB4530702 (Monthly Rollup)"
	CheckForHotfix -hotfixID 3123245 -title "Update improves port exhaustion identification in Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3179574 -title "August 2016 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3172614 -title "July 2016 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3013769 -title "December 2014 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 3000850 -title "November 2014 update rollup for Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2"
	CheckForHotfix -hotfixID 2919355 -title "[Windows 8.1 Update 1] Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2 Update: April 2014"
	CheckForHotfix -hotfixID 2883200 -title "Windows 8.1 and Windows Server 2012 R2 General Availability Update Rollup"
}
elseif ($bn -eq 9200)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows Server 2012 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append
	
	CheckForHotfix -hotfixID 5018457 -title "October 11, 2022-KB5018457 (Monthly Rollup)" -Warn "Yes"
	CheckForHotfix -hotfixID 5017370 -title "September 13, 2022-KB5017370 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5016672 -title "August 9, 2022-KB5016672 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5015863 -title "July 12, 2022-KB5015863 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014747 -title "June 14, 2022-KB5014747 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014017 -title "May 10, 2022-KB5014017 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5012650 -title "April 12, 2022-KB5012650 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5011535 -title "March 8, 2022-KB5011535 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5009586 -title "January 11, 2022-KB5009586 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5008277 -title "December 14, 2021-KB5008277 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5007260 -title "November 9, 2021-KB5007260 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5006739 -title "October 12, 2021-KB5006739 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005623 -title "September 14, 2021-KB5005623 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005099 -title "August 10, 2021-KB5005099 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5004294 -title "July 13, 2021-KB5004294 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003697 -title "June 8, 2021-KB5003697 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003208 -title "May 11, 2021-KB5003208 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5001387 -title "April 13, 2021-KB5001387 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5000847 -title "March 9, 2021-KB5000847 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4601348 -title "February 9, 2021-KB4601348 (Monthly Rollup)"
	CheckForHotfix -hotfixID 3179575 -title "August 2016 update rollup for Windows Server 2012"
	CheckForHotfix -hotfixID 3172615 -title "July 2016 update rollup for Windows Server 2012"
	CheckForHotfix -hotfixID 3161609 -title "June 2016 update rollup for Windows Server 2012"
	CheckForHotfix -hotfixID 3156416 -title "May 2016 update rollup for Windows Server 2012"
	CheckForHotfix -hotfixID 3013767 -title "December 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012"
	CheckForHotfix -hotfixID 3000853 -title "November 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012"
	CheckForHotfix -hotfixID 2995388 -title "October 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012 "
	CheckForHotfix -hotfixID 2984005 -title "September 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012"
	CheckForHotfix -hotfixID 2975331 -title "August 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012"
	CheckForHotfix -hotfixID 2967916 -title "July 2014 update rollup for Windows RT, Windows 8, and Windows Server 2012" 
	CheckForHotfix -hotfixID 2962407 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: June 2014" 
	CheckForHotfix -hotfixID 2955163 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: May 2014"
	CheckForHotfix -hotfixID 2934016 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: April 2014" 	
	CheckForHotfix -hotfixID 2928678 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: March 2014" 	
	CheckForHotfix -hotfixID 2919393 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: February 2014"
	CheckForHotfix -hotfixID 2911101 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: January 2014"
	CheckForHotfix -hotfixID 2903938 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: December 2013"
	CheckForHotfix -hotfixID 2889784 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: November 2013"
	CheckForHotfix -hotfixID 2883201 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: October 2013"
	CheckForHotfix -hotfixID 2876415 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: September 2013"
	CheckForHotfix -hotfixID 2862768 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: August 2013"	
	CheckForHotfix -hotfixID 2855336 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: July 2013"	
	CheckForHotfix -hotfixID 2845533 -title "Windows RT, Windows 8, and Windows Server 2012 update rollup: June 2013"	
	CheckForHotfix -hotfixID 2836988 -title "Windows 8 and Windows Server 2012 Update Rollup: May 2013" 				
	CheckForHotfix -hotfixID 2822241 -title "Windows 8 and Windows Server 2012 Update Rollup: April 2013"				
	CheckForHotfix -hotfixID 2811660 -title "Windows 8 and Windows Server 2012 Update Rollup: March 2013"				
	CheckForHotfix -hotfixID 2795944 -title "Windows 8 and Windows Server 2012 Update Rollup: February 2013"			
	CheckForHotfix -hotfixID 2785094 -title "Windows 8 and Windows Server 2012 Update Rollup: January 2013"				
	CheckForHotfix -hotfixID 2779768 -title "Windows 8 and Windows Server 2012 Update Rollup: December 2012"			
	CheckForHotfix -hotfixID 2770917 -title "Windows 8 and Windows Server 2012 Update Rollup: November 2012"			
	CheckForHotfix -hotfixID 2756872 -title "Windows 8 Client and Windows Server 2012 General Availability Update Rollup"
}
elseif ($bn -eq 7601)
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows 7 and Windows Server 2008 R2 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn + "   (RTM=7600, SP1=7601)" | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5018454 -title "October 11, 2022-KB5018454 (Monthly Rollup)" -Warn "Yes"
	CheckForHotfix -hotfixID 5017361 -title "September 13, 2022-KB5017361 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5016676 -title "August 9, 2022-KB5016676 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5015861 -title "July 12, 2022-KB5015861 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014748 -title "June 14, 2022-KB5014748 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014012 -title "May 10, 2022-KB5014012 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5012626 -title "April 12, 2022-KB5012626 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5011552 -title "March 8, 2022-KB5011552 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5010404 -title "February 8, 2022-KB5010404 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5009610 -title "January 11, 2022-KB5009610 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5008244 -title "December 14, 2021-KB5008244 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5007236 -title "November 9, 2021-KB5007236 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5006743 -title "October 12, 2021-KB5006743 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005633 -title "September 14, 2021-KB5005633 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005088 -title "August 10, 2021-KB5005088 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5004289 -title "July 13, 2021-KB5004289 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003667 -title "June 8, 2021-KB5003667 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003233 -title "May 11, 2021-KB5003233 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5001335 -title "April 13, 2021-KB5001335 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5000841 -title "March 9, 2021-KB5000841 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4601347 -title "February 9, 2021-KB4601347 (Monthly Rollup)"
	CheckForHotfix -hotfixID 3125574 -title "Convenience roll-up update for Windows 7 SP1 and Windows Server 2008 R2 SP1" -Warn "Yes"
	CheckForHotfix -hotfixID 4490628 -title "Servicing stack update for Windows 7 SP1 and Windows Server 2008 R2 SP1: March 12, 2019"
	CheckForHotfix -hotfixID 4580970 -title "Servicing stack update for Windows 7 SP1 and Server 2008 R2 SP1: October 13, 2020"
	CheckForHotfix -hotfixID 4538483 -title "Extended Security Updates (ESU) Licensing Preparation Package for Windows 7 SP1 and Windows Server 2008 R2 SP1"
	CheckForHotfix -hotfixID 2775511 -title "An enterprise hotfix rollup is available for Windows 7 SP1 and Windows Server 2008 R2 SP1"
}
elseif (($bn -eq 6002) -or ($bn -eq 6003))
{
	"==================================================" | Out-File -FilePath $OutputFile -append
	"Windows Vista and Windows Server 2008 Rollups" | Out-File -FilePath $OutputFile -append
	"==================================================" | Out-File -FilePath $OutputFile -append
	"`n" | Out-File -FilePath $OutputFile -append
	"OS Version:  " + $bn + "   (RTM=6000, SP2=6002 or 6003)" | Out-File -FilePath $OutputFile -append
	"`n`n" | Out-File -FilePath $OutputFile -append
	"Installed   Rollup Title and Link" | Out-File -FilePath $OutputFile -append
	"---------   ---------------------" | Out-File -FilePath $OutputFile -append

	CheckForHotfix -hotfixID 5018450 -title "October 11, 2022-KB5018450 (Monthly Rollup)" -Warn "Yes"
	CheckForHotfix -hotfixID 5017358 -title "September 13, 2022-KB5017358 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5016669 -title "August 9, 2022-KB5016669 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5015866 -title "July 12, 2022-KB5015866 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014752 -title "June 14, 2022-KB5014752 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5014010 -title "May 10, 2022-KB5014010 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5012658 -title "April 12, 2022-KB5012658 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5011534 -title "March 8, 2022-KB5011534 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5010384 -title "February 8, 2022-KB5010384 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5009627 -title "January 11, 2022-KB5009627 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5008274 -title "December 14, 2021-KB5008274 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5007263 -title "November 9, 2021-KB5007263 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5006736 -title "October 12, 2021-KB5006736 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005606 -title "September 14, 2021-KB5005606 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5005090 -title "August 10, 2021-KB5005090 (Monthly Rollup)" 
	CheckForHotfix -hotfixID 5004305 -title "July 13, 2021-KB5004305 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003661 -title "June 8, 2021-KB5003661 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5003210 -title "May 11, 2021-KB5003210 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5001389 -title "April 13, 2021-KB5001389 (Monthly Rollup)"
	CheckForHotfix -hotfixID 5000844 -title "March 9, 2021-KB5000844 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4601360 -title "February 9, 2021-KB4601360 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4598288 -title "January 12, 2021-KB4598288 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4592498 -title "December 8, 2020-KB4592498 (Monthly Rollup)"
	CheckForHotfix -hotfixID 4517134 -title "Servicing stack update for Windows Server 2008 SP2: September 10, 2019"
	CheckForHotfix -hotfixID 4572374 -title "Servicing stack update for Windows Server 2008 SP2: August 11, 2020"
}

	CollectFiles -filesToCollect $OutputFile -fileDescription "Hotfix Rollups" -SectionDescription $sectionDescription


# SIG # Begin signature block
# MIInoAYJKoZIhvcNAQcCoIInkTCCJ40CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCy88typKJDvpm0
# jqt85aekwO2skznVuRamm4/alctF+aCCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZdTCCGXECAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBsDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgMRhtgIFl
# KPvEkSwh1PXP5uFA43E/f3UE19bQTEqfmZwwRAYKKwYBBAGCNwIBDDE2MDSgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20g
# MA0GCSqGSIb3DQEBAQUABIIBACZTZslu/42TI4F0apmWWOhN2+tpUfZttHLjvnaM
# d9JoDKhx3xHiR5F/g/rZi7dGSTWKS0hmcPGnr8m3tIjcWrT0Zpf3mGKs9o29166e
# dN4udtjc5wNn/VhKqEYrSmwUAlp08qfJZCFtGDJ1Gdvw9A684BKuNf4rrx0w+iYL
# HO4MLksKd0VVD9KFfj5PFnBNBeLoee1bF0W0ynMKlDrNfz0I0u5dS8p1lutrupyC
# pKaTHk4pD9GFXPvQbAPmwkRyiMsn1Tm19rKQB8gS2XBHNFt1zfzUCUAAJPkRBfG6
# wOsnFO9EKW0LLCohSVuH97wKQL6K4lhlc8mqJkT/GcWMv9yhghb9MIIW+QYKKwYB
# BAGCNwMDATGCFukwghblBgkqhkiG9w0BBwKgghbWMIIW0gIBAzEPMA0GCWCGSAFl
# AwQCAQUAMIIBUQYLKoZIhvcNAQkQAQSgggFABIIBPDCCATgCAQEGCisGAQQBhFkK
# AwEwMTANBglghkgBZQMEAgEFAAQgG4+1DJU/UYAXjjWwDouNG5MzpCovJkOauHmu
# ez+vwQYCBmNH94pm9hgTMjAyMjEwMTkxNTAwMTQuMTI5WjAEgAIB9KCB0KSBzTCB
# yjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMc
# TWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRT
# UyBFU046M0JCRC1FMzM4LUU5QTExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2WgghFUMIIHDDCCBPSgAwIBAgITMwAAAZ3+ieX5e7tMwAABAAAB
# nTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAe
# Fw0yMTEyMDIxOTA1MTlaFw0yMzAyMjgxOTA1MTlaMIHKMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjozQkJELUUzMzgt
# RTlBMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOARaHrQHEkW5H6aUW4UK0beZHZc
# c0J88xNdynTph7AC1LVtsbMruEMLUlEx62FyaIoz95t0Jwbq/qTiVDIuVJoeYeQh
# QLmk0S2W63OmxU36Oj41t3K73DQEyHgrN924t3Ft1rVXO0oNJeMTd4SXk5/7mFje
# keglf02H/mvi1zg2+q3229Vxh4jGlyFnzUArf5TOkD6FxHodLrtcDz5xBQHV8bJG
# hWHWwK7T6h91UNxY4b+1xIq0lyH55EBUN7shGbzh8+w9MXPZ0glEkD89RplH7fFb
# gV3Vlss1r/Axure9pi0qiBpJmKILJTFTubCgDfaLJNwYcLuEfwyBlZU4QG7sJ828
# zKuxHxC6+7eb3UOqxzmBkczG+B4A70suJppT6SViYVZC8temKVLWINdv/zb5OPAa
# 3ESdzzH8S8uSTtSSPi4pnonzKeWA+E9Gp6NygqUewqDFaYPfDMRdbVrT13UvYijT
# TjDTWLfVAAwH8YuGCaYwgTlnhUjYmWH2xfaeTKHlA6dg7OcQKTjNr1wh0wo/6x17
# aeG+9xJ2sZdDx9Y7/43WaNPRIiRfjVdmOb5AwZHTe1rrel+yPeDcTlrWvSj1oeBy
# 6mFbSXCtsED9MYyjnMLxnlYj5HCmvQwCINkbLmHb64zH/b78XhmLIpq4pep3usiX
# Wx4BhBjEpDhJ6YHRAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQU1t8QjeEq6MycXhGB
# 29rLitkbVeQwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0f
# BFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsG
# AQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
# MCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkq
# hkiG9w0BAQsFAAOCAgEAhsdynEu3aHQs0nffiII1liy1rYRqe30lR6KnB5sUjBAy
# KPtIhDzeInhjg4vljCWmnC8XnXoCFwd69gxJxjo0BdIAaGnnFi2QRyR5XqA1tync
# LgjfKi1a8N30pAKHst0iGmJgJ17RIXg3klFlQdcgxzO82F7z50S6IKdLWxaIY9QX
# M0l+wBw2zVoGQci1pLEzQBUeBl+ArxHaKFWS2KvHBgbRP2jWHQGREnc9+4kX6c6O
# 3X54VhiCr5s4tCz9J2BjgNtRV+u0t0SDZNtL6yJnDh2rMz60t3J7lcbImUoFftoi
# zjF/UeHXKYxfbhgmWby/Jf5bjHzLK0+bOI0e2yHF/uUp3U+bu37tRTOLxAGFvLS9
# it+uehbUrCz7Pfi6hzb4PZUXGsff3Gr/wpt54Gm4vn74KKmhlCx3lA7k2LzWcGXC
# L/vUmxkMSiayj+TgmKjK9UAzbzXwKCew0mcxllLEzmTJ5F1iH0huMZ09109Vy/SQ
# 8qs1qU+1E7iKHQZWQv9rgF8QG1cN4RQiwzgDTRB6EP4RJXcjRRtb5vg1OZtFyOdU
# WTm3qe4r8WgVBzk3he55gA7DaYwOECgUT7bG1MeTZ7B33EaRsUOXZvq78VuGxRvn
# 5eg/Q90ncVM0/ob/tWviwg7Fqvg+ljrvhpAKIxLLDC0hY6ipFL84/+tKMX0T/F8w
# ggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUA
# MIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0y
# MTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0
# ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveV
# U3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTI
# cVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36M
# EBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHI
# NSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxP
# LOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2l
# IH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDy
# t0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymei
# XtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1
# GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgV
# GD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQB
# gjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTu
# MB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsG
# AQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUH
# AwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQAD
# ggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/
# 2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvono
# aeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRW
# qveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8Atq
# gcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7
# hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkct
# wRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu
# +yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FB
# SX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/
# Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ
# 8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICyzCCAjQCAQEw
# gfihgdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjNCQkQtRTMzOC1FOUExMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQC36UNJFf3YoXKK
# PvUmfbQKhLLK4KCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MA0GCSqGSIb3DQEBBQUAAgUA5vpeeDAiGA8yMDIyMTAxOTE5MzEwNFoYDzIwMjIx
# MDIwMTkzMTA0WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDm+l54AgEAMAcCAQAC
# AhczMAcCAQACAhG4MAoCBQDm+6/4AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisG
# AQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQAD
# gYEACGMD5buPq9nzUBnTRw7sYWmDgjbF62O0N4k9YP1XNUBSUJMgWa2nWRvAAq5u
# /2pcnDDxkz9h/74RhIxgh18lo91kYSec0nl6awSl9YyQeYYfveL5JLnEYtmav9oO
# sOlvHNiJFMbeAER8ebBxx1gcVKWYNsyxv+OCixS6osMpOxwxggQNMIIECQIBATCB
# kzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAZ3+ieX5e7tMwAAB
# AAABnTANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
# EAEEMC8GCSqGSIb3DQEJBDEiBCACsCgHrhGJ4JTpZNEFnh2KxmmIhOvqa7HlItjp
# vUlDfjCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIPUeY63giqBPgDSfgluV
# f9/MUvIS7g4EM5v6akyVh0WhMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAAGd/onl+Xu7TMAAAQAAAZ0wIgQg4U1ytata97M3Sc6IlbIY
# /KgBVtxR8v9K5JhWJwtVsHswDQYJKoZIhvcNAQELBQAEggIASboTrRbtjyjxuACA
# kB+BO/2r2r7NX4IO+Q2cX5rmACVvOOwdCaon4HX3dz8vBgmufLg+vVkLrh9wZnfD
# w++T4EP3tb/vrXa4Q+mzWT2Nf7CxbfB3apF6AG3Y4twomaZihg0rpAZZkEDxT+e9
# hif0onO/guULkNiz3LtWgo8JihYjHFwCeBy6gNQLNQggy8Mb9daZ1Ttu5jdRU+Tz
# RxZr10R38V93wsxhpGtTlQvdCE8+wh8J6BvxuYb4cyXEi/YHSQMY8cTocNIncQ3p
# HoLCM/X21poYGDOcqlM/L9pWffNeMJ5GfN7xP0zwQEYATi2FANE2MYTeJ1i+11ja
# hLAht7JuB9CZeld0bEHbqBk/28q5fLeEsRZ5qNfW8trA7A+a8Mxw4IoXhc/6yvp2
# /V/UMnmYgKvyel8EgAJxCJJZ+6gZbG0EfegJmledVd3Fh+JXb9jJtc8ysgxQ+hmv
# 6gjp/kRO97sf4CVsQGelNC20nYL5z7S0j0+OePDJgUK3klpvpDbe+JPv1cfkEcso
# XnnCaJNP47cEGyKPAXbWOYKTJH0i/TxqZsQEf38P/oT1sXeVgIOkPYiEhbrpIWD/
# nKCVE4IrYZ5irvJ7ZFCn4zbPbQCyRxDgnBuNr9Z0aLXhV1VZRGrIcwqSZXU3gGsp
# ddYgSxW/LSdwA7a3l0Yh1uoxSmM=
# SIG # End signature block
