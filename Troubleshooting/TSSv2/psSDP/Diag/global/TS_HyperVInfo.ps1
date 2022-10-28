#************************************************
# Hyper-V Info Script
# Version 1.1.2
# Date: 03-23-2010
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script is used to obtain Hyper-V Information, saving output to {Computername}_HyperV-Info.HTM.
#              Script was based on Codeplex project PSHyperv from jamesone and mikekol
#************************************************

PARAM([switch] $SDP30)

# 2019-03-17 WalterE added Trap #_#
Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 WriteTo-ErrorDebugReport -ErrorRecord $_
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}

#bypass this data collector for Windows 2012/2012R2 due to breaking changes to WMI namespace
# detect OS version and SKU
$wmiOSVersion = Get-CimInstance -Namespace "root\cimv2" -Class Win32_OperatingSystem
[int]$bn = [int]$wmiOSVersion.BuildNumber
if ($bn -lt 9200)
{
	##########################################
	#                                        #  
	#Global variables:                       # 
	#                                        # 
	##########################################
	$VMState=       @{"Running"=2 ; "Stopped"=3 ; "Paused"=32768 ; "Suspended"=32769 ; "Starting"=32770 ; "Snapshotting"=32771 ; "Saving"=32773  ; "Stopping"=32774; "Pausing"=32776; "Resuming"=32777 }
	$ReturnCode=    @{"0"="OK" ; "4096"="Job Started" ; "32768"="Failed"; "32769"="Access Denied" ; "32770"="Not Supported"; "32771"="Unknown" ; "32772"="Timeout" ; "32773"="Invalid parameter" ;
					  "32774"="System is in use" ; "32775"="Invalid state for this operation" ; "32776"="Incorrect data type" ; "32777"="System is not available" ; "32778"="Out of memory" }
	$BootMedia=     @{"Floppy"=0 ; "CD"=1 ; "IDE"=2 ; "NET"=3 }
	$StartupAction =@{"None"=0 ; "RestartOnly"=1 ; "AlwaysStartup"=2}
	$ShutDownAction=@{"TurnOff"=0 ; "SaveState"=1 ; "ShutDown"=2}
	$Recoveryaction=@{"None"=0 ; "Restart"=1 ; "RevertToSnapShot"=2}
	$DiskType=      @{"Fixed"=2; "Dynamic"=3; "Differencing"=4; "PhysicalDrive"=5}

	$VGroupRunning = "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:10px;height:10px;vertical-align:middle`" coordsize=`"100,100`" title=`"Running`"><v:roundrect class=`"vmlimage`" arcsize=`"20`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#00D700`" strokecolor=`"#66665B`" /><v:shape class=`"vmlimage`" style=`"width:100; height:100; z-index:0`" fillcolor=`"white`" strokecolor=`"white`"><v:path v=`"m 40,25 l 75,50 40,75 x e`" /></v:shape></v:group>&#160;</span>";
	$VGroupStopped = "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:10px;height:10px;vertical-align:middle`" coordsize=`"100,100`" title=`"Stopped`"><v:roundrect class=`"vmlimage`" arcsize=`"20`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#EC0000`" strokecolor=`"#66665B`" /><v:line class=`"vmlimage`" style=`"z-index:2`" from=`"50,28`" to=`"50,75`" strokecolor=`"white`" strokeweight=`"6px`" /></v:group>&#160;</span>";
	$VGroupPaused = "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:10px;height:10px;vertical-align:middle`" coordsize=`"100,100`" title=`"Paused`"><v:roundrect class=`"vmlimage`" arcsize=`"20`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#FF8000`" strokecolor=`"##66665B`" /><v:line class=`"vmlimage`" style=`"z-index:2`" from=`"40,25`" to=`"40,75`" strokecolor=`"white`" strokeweight=`"2px`" /><v:line class=`"vmlimage`" style=`"z-index:2`" from=`"60,25`" to=`"60,75`" strokecolor=`"white`" strokeweight=`"2px`" /></v:group>&#160;</span>";
	$VGroupSuspended = "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:10px;height:10px;vertical-align:middle`" coordsize=`"100,100`"><v:roundrect class=`"vmlimage`" arcsize=`"20`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#A79C41`" strokecolor=`"#66665B`" /><v:shape class=`"vmlimage`" style=`"width:100; height:100; z-index:0`" fillcolor=`"white`" strokecolor=`"white`"><v:path v=`"m 50,75 l 75,35 25,35 x e`" /></v:shape></v:group>&#160;</span>";
	$VGroupStarting = "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:10px;height:10px;vertical-align:middle`" coordsize=`"100,100`" title=`"Starting`"><v:roundrect class=`"vmlimage`" arcsize=`"20`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#0080FF`" strokecolor=`"#66665B`" /><v:line class=`"vmlimage`" style=`"z-index:2`" from=`"50,50`" to=`"50,85`" strokecolor=`"white`" strokeweight=`"3px`" /><v:shape class=`"vmlimage`" style=`"width:100; height:100; z-index:0`" fillcolor=`"white`" strokecolor=`"white`"><v:path v=`"m 50,15 l 75,60 25,60 x e`" /></v:shape></v:group>&#160;</span>";
	$VGroupOtherState = "<span xmlns:v=`"urn:schemas-microsoft-com:vml`"><v:group class=`"vmlimage`" style=`"width:10px;height:10px;vertical-align:middle`" coordsize=`"100,100`"><v:roundrect class=`"vmlimage`" arcsize=`"20`" style=`"width:100;height:100;z-index:0`" fillcolor=`"#C0C0C0`" strokecolor=`"#66665B`" /><v:shape class=`"vmlimage`" style=`"width:100; height:100; z-index:0`" fillcolor=`"white`" strokecolor=`"white`"><v:path v=`"m 50,25 l 75,70 25,70 x e`" /></v:shape>&#160;</span>";

	$TroubleshootingModuleLoaded = $true
	$PowerShellV2 = $false
	$DynamicMemoryEnabled = $false

	Set-Variable -Name ALERT_INFORMATION -Value 1 -Option Constant
	Set-Variable -Name ALERT_WARNING -Value 2 -Option Constant
	Set-Variable -Name ALERT_ERROR -Value 3 -Option Constant

	Filter Convert-DiskIDtoDrive
	{Param ($diskIndex)
	 if ($null -eq $diskIndex) {$diskIndex = $_}
	 Get-CimInstance -Query "Select * From Win32_logicaldisktoPartition Where __PATH Like '%disk #$diskIndex%' " | ForEach-Object {$_.dependent.split("=")[1].replace('"','')}  
	}
	#Example: Convert-DiskIDtoDrive 2 
	#          Returns the Drive letters of the partions on Disk 2 (in the form D:, E: - with the colon, and no backslash)

	Function MillisecondsToDateDisplay ($Milliseconds) {
		$Date = (Get-Date).AddMilliseconds(($Milliseconds * -1))
		Return GetAgeDescription($Date)
	}

	function FormatBytes {
		param ($bytes,$precision='0')
		foreach ($i in ("Bytes","KB","MB","GB","TB")) {
			if (($bytes -lt 1000) -or ($i -eq "TB")){
				$bytes = ($bytes).tostring("F0" + "$precision")
				return $bytes + " $i"
			} else {
				$bytes /= 1KB
			}
		}
	}


	Function GetAgeDescription($Date) {
		$Age = New-TimeSpan $Date $(Get-Date) 

		if ($Age.Days -gt 0) {
			$AgeDisplay = $Age.Days.ToString() + " day"
			if ($Age.Days -gt 1) {$AgeDisplay += "s"}
		} else {
			if ($Age.Hours -gt 0) {
				$AgeDisplay = " " + $Age.Hours.ToString() + " hour"
				if ($Age.Hours -gt 1) {$AgeDisplay += "s"}
			}
			if ($Age.Minutes -gt 0) {
				if ($AgeDisplay.lenght -gt 0) {$AgeDisplay += " "}
				$AgeDisplay += " " + $Age.Minutes.ToString() + " minute"
				if ($Age.Minutes -gt 1) {$AgeDisplay += "s"}
			}		
			if ($Age.Seconds -gt 0) {
				if ($AgeDisplay.Length -gt 0) {$AgeDisplay += " "}
				$AgeDisplay += " " + $Age.Seconds.ToString() + " second"
				if ($Age.Seconds -gt 1) {$AgeDisplay += "s"}
			}		
		}
		Return $AgeDisplay
	}

	Function Write-ScriptProgress ($Activity = "", $Status = "") {
		if ($Activity -ne $LastActivity) {
			if (-not $TroubleShootingModuleLoaded -and ($Activity -ne "")) {
				$Activity | Out-Host
			}
			if ($Activity -ne "") {
				Set-variable -Name "LastActivity" -Value $Activity -Scope "global"
			} else {
				$Activity = $LastActivity
			}	
		}
		if ($TroubleShootingModuleLoaded) {
				Write-DiagProgress -activity $Activity -status $Status
		
		} else {
			"    [" + (Get-Date) + "] " + $Status | Out-Host
		}
	}

	#########################################################
	#                                                       #
	# Functions for Managing Output XML and HTM file        #
	#                                                       #
	#########################################################

	Function OpenSection ([string] $name="", $xpath="/Root", $title="")
	{
		[System.Xml.XmlElement] $rootElement=$xmlDoc.SelectNodes($xpath).Item(0)
		[System.Xml.XmlElement] $section = $xmlDoc.CreateElement("Section")
		$section.SetAttribute("name",$name)
		$Null = $rootElement.AppendChild($section)
		AddXMLElement -ElementName "SectionTitle" -value $title -xpath "/Root/Section[@name=`'$name`']"
	}

	Function AddXMLElement ([string] $ElementName="Item", 
							[string] $Value,
							[string] $AttributeName="name", 
							[string] $attributeValue,
							[string] $xpath="/Root")
	{
		[System.Xml.XmlElement] $rootElement=$xmlDoc.SelectNodes($xpath).Item(0)
		if ($null -ne $rootElement) { 
			[System.Xml.XmlElement] $element = $xmlDoc.CreateElement($ElementName)
			if ($attributeValue.lenght -ne 0) {$element.SetAttribute($AttributeName, $attributeValue)}
			if ($Value.lenght -ne 0) { 
				if ($PowerShellV2) {
					$element.innerXML = $Value
				} else {
					$element.set_InnerXml($Value)
				}
			}
			$Null = $rootElement.AppendChild($element)
		} else {
			"Error. Path $xpath returned a null value. Current XML document: `n" + $xmlDoc.OuterXml
		}
	}

	Function AddXMLAlert([int] $AlertType = $ALERT_INFORMATION, 
						[string] $AlertCategory="",
						[string] $AlertMessage="",
						[string] $AlertRecommendation="",
						[int] $AlertPriority=50)
	{
		switch ($AlertType)	{
			$ALERT_INFORMATION {$strAlertType = "Information"}
			$ALERT_WARNING {$strAlertType = "Warning"}
			$ALERT_ERROR {$strAlertType = "Error"}
		}
		# Try to find the <Alerts> node. Create it if does not exist.	
		[System.Xml.XmlElement] $alertsElement=$xmlDoc.SelectNodes("/Root/Alerts").Item(0)
		if ($null -eq $alertsElement) {
			AddXMLElement -ElementName "Alerts"
		}
	
		$XMLAlert =   "<AlertType>$strAlertType</AlertType>" +
					  "<AlertCategory>$AlertCategory</AlertCategory>" +
					  "<AlertMessage>$AlertMessage</AlertMessage>" +
					  "<AlertPriority>$AlertPriority</AlertPriority>"
		if ($AlertRecommendation.Length -ne 0) {
			$XMLAlert += "<AlertRecommendation>$AlertRecommendation</AlertRecommendation>"
		}
    	
		AddXMLElement -ElementName "Alert" -xpath "/Root/Alerts" -value $XMLAlert 
	}

	Function GenerateHTMLFile()
	{
		trap [Exception] 
		{
			WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText ("Generating HTML Report")
			if (Test-Path $XMLFilename)
			{
				CollectFiles -filesToCollect $XMLFilename -fileDescription "Hyper-V Info XML" -sectionDescription "Hyper-V Info" -Verbosity "Debug"
			}
			continue
		}
	
		$HTMLFilename = $PWD.Path + "\" + $Env:COMPUTERNAME + "_HyperV-Info.HTM"
		$XMLFilename = $Env:TEMP + "\HyperVInfo.XML"
		"Creating HyperVInfo.XML..." | WriteTo-StdOut -ShortFormat
		$xmlDoc.Save($XMLFilename)
	
		[xml] $XSLContent = EmbeddedXSL
		$XSLObject = New-Object System.Xml.Xsl.XslTransform
		$XSLObject.Load($XSLContent)
		$XSLObject.Transform($XMLFilename, $HTMLFilename)
    
		Remove-Item $XMLFilename
	
		"Output saved to $HTMLFilename" | WriteTo-StdOut -ShortFormat
		return $HTMLFilename
	}

	#########################################################
	#                                                       #
	# Functions for Managing Virtual Hard disk (VHD) files  #
	#                                                       #
	#########################################################
	Function Get-VhdDefaultPath
	{ param ($server=".") 
	 (Get-CimInstance -computerName $server -NameSpace "root\virtualization" -Class "MsVM_VirtualSystemManagementServiceSettingData").DefaultVirtualHardDiskPath
	}

	Function Get-HyperVHostInfo
	{ param ($server=".") 
	 (Get-CimInstance -computerName $server -NameSpace "root\virtualization" -Class "MsVM_VirtualSystemManagementServiceSettingData")
	}


	Filter Test-WMIJob 
	{  param  ($JobID, [Switch]$Wait, $Description="Job")   
	   if ($null -eq $jobID) {$jobID = $_}  
	   $Job = [WMI]$JobID
	   if ($null -ne $job) {
		while (($job.jobstate -eq 4) -and $wait) { 
				Write-ScriptProgress -activity ("$Description $($Job.Caption)") -Status "% complete" -PercentComplete $Job.PercentComplete 
				Start-Sleep -seconds 1 
				$Job.PSBase.Get() }  
		$Description +": " + @{2="New"; 3="Starting"; 4="Running $($job.PercentComplete)%"; 5="Suspended"; 6="Shutting Down"; 7="Completed"; 8="Terminated"; 9="Killed"; 10="Exception: $($job.ErrorDescription)"; 11="Service"}[[int]$Job.JobState] | out-host
			$Job.Status
	}}

	Filter Get-VHDInfo 
	{param ($vhdPath, $server=".")
	   if ($null -eq $vhdPath) {$vhdPath = $_}
	   if ($vhdPath -is [Array]) {$vhdPath | foreach-Object { Get-VHDInfo  -VHDPath $_ -Server $Server} }
	   if ($vhdPath -is [System.IO.FileInfo]) {$vhdPath = $vhdpath.fullname}   
	   if ($VhdPath -is [String]) 
	   { 
			 if ($vhdpath.StartsWith(".\")) {$VhDpath= join-path $PWD $vhdPath.Substring(2)  }
			 else                           { if ((split-path $VHDPath)  -eq "" ) {$vhdPath  = join-path (Get-VhdDefaultPath ) $vhdPath } }
			 if (-not $vhdpath.toUpper().endswith("VHD")) {$vhdPath = $vhdPath + ".vhd"}
	 		$ImgMgtSvc=Get-CimInstance -computerName $server -NameSpace  "root\virtualization" -Class "MsVM_ImageManagementService"
			 $ARGUMENTS =@($VHDPath,$NULL)
			 "arguments: " + $ARGUMENTS
			 $Result=$ImgMgtSvc.Psbase.InvokeMethod("GetVirtualHardDiskInfo",$arguments)
			 if ($null -ne $ARGUMENTS[1])
			 {
        		 ([xml]$ARGUMENTS[1]).SelectNodes("/INSTANCE/PROPERTY")  | ForEach-Object -begin {$KVPObj = New-Object -TypeName System.Object 
												   Add-Member -inputObject $KvpObj -MemberType NoteProperty -Name "Path"  -Value $VHDPath} `
																			 -process {Add-Member -inputObject $KvpObj -MemberType NoteProperty -Name $_.Name -Value $_.value} `
																				 -end {$KvpObj} 
				}
		}
   		$vhdPath=$null
	}	
	#Example 1  cd (Get-VhdDefaultPath) ; dir *.vhd | get-vhdinfo
	#           Changes Location to the Default folder for VHD files, and then gets information about all the VHD files. 
	#Example 2  (Get-VHDInfo 'C:\Users\Public\Documents\Microsoft Hyper-V\Virtual Hard Disks\Core.vhd').parentPath
	#           Returns the parent path of core.vhd e.g. C:\Users\Public\Documents\Microsoft Hyper-V\Virtual Hard Disks\Brand-new-core.vhd
	#Example 3  Get-VMDisk core% | forEach {Get-VHDInfo $_.Diskpath} | measure-object -Sum filesize
	#           Gets the disks on VMs with names begining Core , gets the their details and sums the file size. 


	####################################################
	#                                                  #
	# Functions for managing VM information / status   #
	#                                                  #
	####################################################

	Function Get-VM 
	{Param ([String]$Name="%", $Server=".", [Switch]$suspended, [switch]$running, [Switch]$stopped) 
	 $Name=$Name.replace("*","%")
	 $WQL="Select * From MsVM_ComputerSystem Where ElementName Like '$Name' and ElementName != '" + $Env:COMPUTERNAME + "'"
	 if ($running -or $stopped -or $suspended) {
		[String]$state = ""
		if ($running)  {$State +="or enabledState=" +  $VMState["running"]  }
		if ($Stopped)  {$State +="or enabledState=" +  $VMState["Stopped"]  }
		if ($suspended){$State +="or enabledState=" +  $VMState["suspended"]}
		$WQL += "AND (" + $state.substring(3) +")" }
	 Get-CimInstance -computername $Server -NameSpace "root\virtualization" -Query $WQL
	}
	#Example 1: Get-VM
	#           Returns WMI MsVM_ComputerSystem objects for all Virtual Machines on the local server(n.b. Parent Partition is filtered out)
	#Example 2: Get-VM "Windows 2008 Ent Full TS"   
	#	    Returns a single WMI MsVM_ComputerSystem object for the VM named "Server 2008 ENT Full TS"
	#Example 3: Get-VM "%2008%"  -Server James-2088
	#       or: Get-VM "*2008*" 
	#	    Returns WMI MsVM_ComputerSystem objects for VMs containing 2008 in their name on the server James-2008 (n.b. WQL Wild card is %, function converts * to %) 

	Filter Test-VMHeartBeat
	{param($vm, $timeOut=0, $Server=".") 
	 $Endtime=(get-date).addSeconds($TimeOut)
	 if ($null -eq $VM) {$VM=$_}
	 if (($null -eq $VM) -and ($null -eq $timeOut)) {$VM="%"}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $Server) }
	 if ($VM -is [Array]) {$VM | foreach-Object {Test-VmHeartbeat -VM $_ -timeout $timeout -Server $Server} }
	 if ($VM -is [System.Management.ManagementObject]) {
		$Status="No Heartbeat component found" 
		Do {
			 $hb=(Get-CimInstance -Namespace "root\virtualization" -query "associators of {$vm} where resultclass=Msvm_HeartbeatComponent")
			 if ($hb -is [System.Management.ManagementObject]) {$status=@{2="OK";6="Error";12="No Contact";13="Lost Communication"}.[int]($hb.OperationalStatus[0])}
			 $pending = ((get-date) -lt $endTime) -and ($status -ne "OK") 
			 if ($pending) {Write-ScriptProgress -activity "waiting for heartbeat" -Status $vm.elementname -Current $status; start-sleep 5} 
		} while ($Pending)         
		$vm | select-object elementName, @{Name="Status"; expression={$status}}  }
	 $vm=$null
	}
	#Example start-vm "London DC" ; Test-vmheartBeat "London DC" -Timeout 300; start-vm "London SQL"
	#        Starts the VM named London DC and waits up to 5 minutes for its heartbeat, then starts VM "London SQL"

	Function Convert-VMState
	{Param ($ID) 
	 ($vmState.GetEnumerator() | where-object {$_.value -eq $ID}).name 
	}
	#Example Convert-VMState 2 
	#        Returns "Running"

	Function Convert-DiskType
	{Param ($Type) 
	 ($DiskType.GetEnumerator() | Where-Object {$_.Value -eq $Type}).name
	}

	Filter Get-VMKVP
	{param($vm, $Server=".") 
	 if ($null -eq $VM) {$VM=$_}
	 if ($null -eq $vm) {$vm = "%"}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $Server) }
	 if ($VM -is [Array]) {$VM | foreach-Object {get-VMKVP -VM $_ -Server $Server} }
	 if ($VM -is [System.Management.ManagementObject]) { 
		 $KVPComponent=(Get-CimInstance -computername $VM.__Server -Namespace root\virtualization -query "select * from Msvm_KvpExchangeComponent where systemName = '$($vm.name)'")
		 if ($KVPComponent.GuestIntrinsicExchangeItems  ) {
			 ($KVPComponent.GuestIntrinsicExchangeItems + $KVPComponent.GuestExchangeItems )| 
			 ForEach-Object -begin {$KVPObj = New-Object -TypeName System.Object 
							Add-Member -inputObject $KvpObj -MemberType NoteProperty -Name "VMElementName" -Value $vm.elementName} `
					 -process {([xml]$_).SelectNodes("/INSTANCE/PROPERTY") | ForEach-Object -process {if ($_.name -eq "Name") {$propName=$_.value}; if  ($_.name -eq "Data") {$Propdata=$_.value} } -end {Add-Member -inputObject $KvpObj -MemberType NoteProperty -Name $PropName -Value $PropData}}  `
					 -end {[string[]]$Descriptions=@()
						   if ($KvpObj.ProcessorArchitecture -eq 0)  {$ProcArchTxt += "x86" }
						   if ($KvpObj.ProcessorArchitecture -eq 9)  {$ProcArchTxt += "x64" }
						   if ($KvpObj.ProductType -eq 1 )  {$ProductType += "Workstation" }
						   if ($KvpObj.ProductType -eq 2 )  {$ProductType += "Domain Controller" }
						   if ($KvpObj.ProductType -eq 3 )  {$ProductType += "Server" } 
						   $suites=@{1="Small Business";2="Enterprise";4="BackOffice";8="Communications";16="Terminal";32="Small Business Restricted";64="Embedded NT";128="Data Center";256="Single User";512="Personal";1024="Blade"}
						   foreach  ($Key in $suites.keys) {
								if ($KvpObj.suiteMask -band $key){
									$descriptions += $suites.$key
									} 
						   }
						   Add-Member -inputObject $KvpObj -MemberType NoteProperty -Name "Descriptions" -Value $descriptions
						   Add-Member -inputObject $KvpObj -MemberType NoteProperty -Name "ProcessorArchitectureText" -Value $ProcArchTxt
						   Add-Member -inputObject $KvpObj -MemberType NoteProperty -Name "ProductTypeText" -Value $ProductType
						   $KvpObj}
		  }}
	 $vm=$null
	}
	#Example 1: (Get-VMKVP  "Windows 2008 Ent Full TS").OSName 
	#            Returns "Windows Server (R) 2008 Enterprise" - the OS that server is running
	#Example 2: Get-vmkvp % -server james-2008
	#            Returns the Key Value pairs sent back by all the VMs on the Server James-2009
	#Example 3: Get-Vm -running | get-VMKVP
	#            Returns the Key Value pairs for running VMs on the local Server 
	# Note. The values sent Automatically to the the child VM can be found in HKLM:\SOFTWARE\Microsoft\Virtual Machine\guest\Parameters 
	#       The values sent Programaticaly to the the child VM can be found in HKLM:\SOFTWARE\Microsoft\Virtual Machine\External    
	#       Those sent by the Child VM are in HKLM:\SOFTWARE\Microsoft\Virtual Machine\auto
	#       If the VM isn't running its Key/Value Pair Exchange Service does NOT persist the values. So stopped VMs won't return anything !



	Filter Ping-VM
	{Param ($vm, $Server=".")
	 $PingStatusCode=@{0="Success" ; 11001="Buffer Too Small" ; 11002="Destination Net Unreachable" ; 11003="Destination Host Unreachable" ; 11004="Destination Protocol Unreachable"
					   11005="Destination Port Unreachable";11006="No Resources";11007="Bad Option";11008="Hardware Error";11009="Packet Too Big"; 11010="Request Timed Out";
					   11011="Bad Request"; 11012="Bad Route"; 11013="TimeToLive Expired Transit"; 11014="TimeToLive Expired Reassembly"; 11015="Parameter Problem";
					   11016="Source Quench"; 11017="Option Too Big"; 11018="Bad Destination"; 11032="Negotiating IPSEC"; 11050="General Failure" }
	 if ($null -eq $VM)    {$VM=$_}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $Server) }
	 if ($VM -is [Array])  {$VM | foreach-Object {Ping-VM $_ -Server $Server} }
	 if ($VM -is [System.Management.ManagementObject]) { 
		 if ($VM.EnabledState -ne $vmstate["running"]) {
				$vm | Select-object -property @{Name="VMName"; expression={$_.ElementName}}, 
											  @{Name="FullyQualifiedDomainName"; expression={$null}} , 
											  @{name="NetworkAddress"; expression={$null}} ,
											  @{Name="Status"; expression={"VM $(Convert-VmState -ID $_.EnabledState)"}} }            
		 else {
				$vmFQDN=(Get-VMKVP $VM).fullyQualifiedDomainName
				if ($null -eq $vmFQDN) {
				$vm | Select-object -property @{Name="VMName"; expression={$vm.ElementName}},
											  @{Name="FullyQualifiedDomainName"; expression={$null}} , 
											  @{name="NetworkAddress"; expression={$null}} ,
											  @{Name="Status"; expression={"Could not discover VM's FQDN"}} }           
				else {
					   Get-CimInstance -query "Select * from  Win32_PingStatus where Address='$VmFQDN' and ResolveAddressNames = True and recordRoute=1" |
					   Select-object -property @{Name="VMName"; expression={$vm.ElementName}},
											   @{Name="FullyQualifiedDomainName"; expression={$vmFqdn}} , 
											   @{name="NetworkAddress"; expression={$_.ProtocolAddressResolved}} , ResponseTime , ResponseTimeToLive , StatusCode , 
											   @{Name="Status"; expression={if ($_.PrimaryAddressResolutionStatus -eq 0) {$PingStatusCode[[int]$_.statusCode]} else {"Address not resolved"}}}
					 }
			   }
		}
	 $vm=$null
	}
	#Example 1: Ping-VM "Tenby" -server james2008
	#           Attempts to ping from the local machine to the VM named "Tenby" on the server James-2008. T
	#           This relies on the integration components being present and the FQDN they return being resolvable on the local machine. 
	#Example 2: get-vm -r | foreach-object {if ((Ping-VM $_).statusCode -ne 0) {"$($_.elementname) is inaccessible"} }
	#           Gets-the running VMs, and pings them and outputs a message for any which are running but can't be pinged. 
 

	Filter Get-VMSummary
	{param ($vm , $Server=".")
	 if ($null -eq $vm) {$VM=$_}
	 if ($null -eq $vm) {$VM="%"}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $Server) }
	 if ($VM -is [Array]) {$VM | foreach-Object {Get-VMSummary -VM $_ -Server $Server} }
	 if ($VM -is [System.Management.ManagementObject]) { 
			   $vssd=Get-VMSettingData $vm 
			   $settingPath=@($Vssd.__Path)
			   $arguments=@($SettingPath, @(0,1,2,3,4,100,101,102,103,104,105,106,107,108), $null)
			   $VSMgtSvc=Get-CimInstance -computerName $Vssd.__Server -NameSpace "root\virtualization" -Class "MsVM_virtualSystemManagementService" 
			   $result=$VSMgtSvc.psbase.InvokeMethod("GetSummaryInformation",$arguments)
			   if ($Result -eq 0) {$arguments[2] | foreach-object {
					 $SiObj = New-Object -TypeName System.Object
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "Host"             -Value $_.__server
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "VMElementName"    -Value $_.elementname
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "Name"             -Value $_.name
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "CreationTime"     -Value $_.CreationTime
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "EnabledState"     -Value $_.EnabledState
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "EnabledStateText" -Value (convert-vmState($_.EnabledState))
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "Notes"            -Value $_.Notes
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "CPUCount"         -Value $_.NumberOfProcessors
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "CPULoad"          -Value $_.ProcessorLoad
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "CPULoadHistory"   -Value $_.ProcessorLoadHistory
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "MemoryUsage"      -Value $_.MemoryUsage
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "Heartbeat"        -Value $_.Heartbeat
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "HeartbeatText"    -Value @{2="OK"; 6="Error"; 12="No Contact";13="Lost Communication"}[[int]$_.Heartbeat]
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "Uptime"           -Value $_.UpTime
					 Add-Member -inputObject $siObj -MemberType ScriptProperty -Name "UptimeFormatted"  -Value {if ($This.uptime -gt 0) {([datetime]0).addmilliseconds($This.UpTime).tostring("hh:mm:ss")} else {0} }
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "GuestOS"          -Value $_.GuestOperatingSystem;
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "Snapshots"        -Value $_.Snapshots.count
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "Jobs"             -Value $_.AsynchronousTasks
					 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "FQDN"             -value ((get-vmkvp -vm $vm).FullyQualifiedDomainName)
        		 Add-Member -inputObject $siObj -MemberType NoteProperty -Name   "IpAddress"        -Value ((Ping-VM $vm).NetworkAddress)
					 $siObj } }
			 else  {"Get Summary info :" + $ReturnCode[[string]$result] | Out-host }
			 }
	}
	#Example 1: Get-VMSummary -server james-2008,jackie-2008 | ft -a 
	#           Outputs formatted status for all VMs on the servers named "James-2008" and "Jackie-2008"
	#Example 2: Get-VMSmmary "Windows 2008 Ent Full TS"  
	#   Outputs status for all for the VM named "Server 2008 ENT Full TS" on the local server

	set-alias -Name list-vmState -value get-vmSummary
	set-alias -Name Get-vmState -value get-vmSummary
	#This function has been called by other names

	Filter Get-VMSettingData
	{Param ($VM, $Server=".")
	 if ($null -eq $VM) {$VM=$_}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $Server) }
	 if ($VM -is [Array]) {$VM | ForEach-Object {Get-VMSettingData -VM $_ -Server $Server} }
	 if ($VM -is [System.Management.ManagementObject]) {
	  if ($vm.__Class -eq "Msvm_VirtualSystemSettingData") {$VM}
	  if ($vm.__Class -eq "Msvm_ComputerSystem") {Get-CimInstance -ComputerName $vm.__Server -NameSpace "root\virtualization" -Query "ASSOCIATORS OF {$VM} Where ResultClass = MsVM_VirtualSystemSettingData"  | where-object {$_.instanceID -eq "Microsoft:$($vm.name)"}} }
	 $vm=$Null
	}

	Filter Get-VMMemory
	{Param ($VM , $server=".")
	 if ($null -eq $VM) {$VM=$_}
	 if ($null -eq $VM) {$VM="%"}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $Server) }
	 if ($VM -is [Array]) {$VM | ForEach-Object {Get-VMMemory -VM $_ -Server $Server} }
	 if ($VM -is [System.Management.ManagementObject]) {$vssd = Get-vmSettingData $vm
				 Get-CimInstance -computerName $vm.__server -NameSpace  "root\virtualization" -Query "associators of {$vssd} where resultclass=Msvm_MemorySettingData" }
	 $vm=$null
	}
	#Example Get-VMMemory core
	#        Returns the memory settings for the VM named core on the local server. 

	Filter Get-VMCPUCount
	{Param ($VM , $server=".")
	 if ($null -eq $VM) {$VM=$_}
	 if ($null -eq $VM) {$VM="%"}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $Server) }
	 if ($VM -is [Array]) {$VM | ForEach-Object {Get-VMCpuCount -VM $_ -Server $Server} }
	 if ($VM -is [System.Management.ManagementObject]) {$vssd = Get-vmSettingData $vm
		 Get-CimInstance -computerName $vm.__server -NameSpace  "root\virtualization" -query "associators of {$vssd} where resultclass=MsVM_ProcessorSettingData"}
	 $vm=$null
	}
	#Example Get-VMCPUCount core
	#        Returns the CPU settings for the VM named core on the local server. 

	Filter Get-VMProcessor {
	Param ($vm, $server=".")
	 if ($null -eq $VM) {$VM=$_}
	 if ($null -eq $vm) {$VM="%"}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $Server) }
	 if ($VM -is [Array]) {$VM | ForEach-Object {Get-VMProcessor -VM $_ -Server $Server} }
	 if ($VM -is [System.Management.ManagementObject]) {
			Get-CimInstance -namespace root\virtualization -computerName $server -query "associators of {$vm} where ResultClass= MSVM_Processor" 
		}
	 }

	#Example Get-VMProccessor core
	#        Returns the CPU settings for the VM named core on the local server. 
	############################################################################
	#                                                                          #
	# Functions for working with disk objects , SCSI Controller, Driver, Disk  #
	#                                                                          #
	############################################################################

	Filter Get-VMDiskController
	{Param ($VM , $ControllerID, $server=".", [Switch]$SCSI, [Switch]$IDE )
	 if ($null -eq $VM) {$VM=$_}
	 if ($null -eq $VM) {$VM="%"}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -server $Server) }
	 if ($VM -is [Array]) {if ($SCSI) {$VM | ForEach-Object {Get-VMDiskController -VM $_ -ControllerID  $ControllerID -SCSI} }
						   if ($IDE)  {$VM | ForEach-Object {Get-VMDiskController -VM $_ -ControllerID  $ControllerID -IDE } } 
						   if ((-not $scsi) -and (-not $IDE) -and ($null -eq $contollerID)) {$VM | ForEach-Object {Get-VMDiskController -VM $_ } } }
	 if ($VM -is [System.Management.ManagementObject]) {
		 if ((-not $scsi) -and (-not $IDE) -and ($null -eq $contollerID)) {
			 if ($vm.__class -eq "Msvm_ComputerSystem") {$vm=(get-vmsettingData $vm)} 
	   #notice this uses the Associators of , and select where instanceID syntaxes
			 Get-CimInstance -Query "ASSOCIATORS OF {$vm} where resultclass= Msvm_ResourceAllocationSettingData " -computerName $vm.__server -NameSpace "root\virtualization"  | 
					Where-Object {($_.resourcesubtype -eq 'Microsoft Emulated IDE Controller')  -or ($_.resourceSubtype -eq 'Microsoft Synthetic SCSI Controller')}  }
		 Else {
			 if ($scsi) { $controllers=Get-CimInstance -Query "Select * From MsVM_ResourceAllocationSettingData
												Where instanceId Like 'Microsoft:$($vm.name)%'and resourceSubtype = 'Microsoft Synthetic SCSI Controller' " `
											   -NameSpace "root\virtualization" -computerName $vm.__server
				  if ($null -eq $controllerID) {$controllers}
						  else  {$controllers | Select-Object -first ($controllerID + 1)  | Select-Object -last 1  }    }
			 if ($IDE)  { Get-CimInstance -Query "Select * From MsVM_ResourceAllocationSettingData 
												Where instanceId Like 'Microsoft:$($vm.name)%\\$ControllerID%'
												and resourceSubtype = 'Microsoft Emulated IDE Controller' " -NameSpace "root\virtualization" -computerName $vm.__server } } }
	 $vm=$null
	}
	#Example 1: Get-VM -server James-2008| Get-VMDiskController -IDE -SCSI
	#           Returns all the DiskControllers for all the VMs on Server James-2008      
	#Example 2: Get-VMDiskController $Tenby -SCSI -ContollerID 0
	#           Returns SCSI controller 0 in the VM pointed to by $Tenby


	Filter Get-VMDriveByController
	{Param ($Controller, $LUN="%" )
	 if ($null -eq $Controller) {$Controller=$_}
	 if ($Controller -is [Array]) {$Controller | ForEach-Object {Get-VMDriveByController -Controller  $Controller -LUN $Lun} }
	 if ($Controller -is [System.Management.ManagementObject]) {
		$CtrlPath=$Controller.__Path.replace("\","\\")
		Get-CimInstance -computerName $controller.__server -Query "Select * From MsVM_ResourceAllocationSettingData Where PARENT='$ctrlPath' and Address Like '$Lun' " -NameSpace "root\virtualization" }
	 $Controller = $null
	}
	#Example 1: Get-VMDiskController "Tenby" -server "James-2008" -IDE -ContollerID 0 | Get-VMDriveByController
	#           Gets the drives attached to IDE controller 0 in the VM named Tenby on Server James-2008
	#Example 2: Get-VMDriveByController $controller 0
	#           Gets the first drive attached tothe controller pointed to by $controller. 


	Filter Get-VMDiskByDrive
	{Param ($Drive)
	 if ($null -eq $Drive) {$Drive=$_}
	 if ($Drive -is [Array]) {$Controller | ForEach-Object {get-vmdiskByDrive -Drive $Drive} }
	 if ($Drive -is [System.Management.ManagementObject]) {
 		if (($Drive.ResourceType -eq 22) -and ($Drive.ResourceSubType -eq "Microsoft Physical Disk Drive")) {
			$DrivePath=$Drive.HostResource[0].replace("\","\\")
			Get-CimInstance -computerName $drive.__server -Query "Select * From Msvm_DiskDrive Where __PATH='$DrivePath' " -NameSpace "root\virtualization" 
		} else {
			$DrivePath=$Drive.__Path.replace("\","\\")
			Get-CimInstance -computerName $drive.__server -Query "Select * From MsVM_ResourceAllocationSettingData Where PARENT='$DrivePath' " -NameSpace "root\virtualization" 
		}
	 $Drive = $null
	 }
	}
	#Example 1: Get-VMDiskController "Tenby" -server "James-2008" -IDE -ContollerID 0 | Get-VMDriveByController | get-vmdiskByDrive
	#           Gets the disks in the drives attached to IDE controller 0 in the VM named Tenby on Server James-2008
	#Example 2: get-vmdiskByDrive $drive
	#           Gets the disk in the drive pointed to by $drive


	Filter Get-VMDisk
	{Param ($vm, [switch]$snapshot)
	 if ($null -eq $vm) {$vm = $_}
	 if ($null -eq $vm) {$vm = "%"} 
	 if ($vm -is [String]) {$vm = get-vm -Name $vm}
	 if ($vm -isnot [array]) {$vm=@($vm)}
	 if ($snapshot) {$VM= ($VM + (get-vmsnapshot $vm)  | Sort-Object elementname) }
	 foreach ($v in $vm) {
			 if ($v -is [String]) {$v = get-vm -Name $v}
			 foreach ($dc in (get-vmdiskcontroller -vm $v)) {
					 foreach ($drive in (Get-VMDriveByController -controller $dc)) {
							 get-vmdiskByDrive -drive $drive | Select-Object -property `
														   @{name="VMElementName"; expression={$v.elementName}},
														   @{name="VMGUID"; expression={$v.Name}},
														   @{name="ControllerName"; expression={$dc.elementName}},
														   @{name="ControllerInstanceID"; expression={$dc.InstanceId}},
														   @{name="ControllerID"; expression={$dc.instanceID.split("\")[-1]}},
														   @{name="DriveName"; expression={$drive.caption}} ,
														   @{name="DriveInstanceID"; expression={$drive.instanceID}},
														   @{name="DriveLUN"; expression={$drive.address}},
														   @{name="DiskPath"; expression={$_.Connection}},
														   @{name="DiskName"; expression={$_.ElementName}},
														   @{name="DiskImage"; expression={if ($null -ne $_.Connection) {$p=$_.Connection[0] ; while ($p.toupper().EndsWith(".AVHD")) { $p=(Get-VHDInfo -vhdpath $p -Server $_.__server ).parentPath } ; $p}}},
														   @{name="DiskInstanceID"; expression={$_.InstanceID}}
														   }}}
	 $vm=$null
	}
	#Example 1: Get-VMDisk (choose-vm -server "James-2008" -multi) | format-table -autosize -property VMname, DriveName,  @{Label="Conected to"; expression={"{0,5} {1}:{2}" -f $_.Controllername.split(" ")[0], $_.ControllerID, $_.DriveLun }} , DiskPath
	#           Displays the disks connected to the chosen VMs, giving the VM Name, Hard drive/DVD Drive , Controller:LUN and VHD/ISO file
	#Example 2: Get-VMDisk * | foreach {$_.diskpath}
	#           Returns a list of all the disk paths used on all the VMs on the Local server 
	#Example 3: Get-VMDisk * | where {$_.diskpath -match "^IDE"} 
	#           Finds which VMs are connected to the Physical CD/DVD drive.  


	Filter Get-VMFloppyDisk
	{Param ($VM , $server="."  )
	 if ($null -eq $VM) {$VM=$_}
	 if ($null -eq $VM) {$VM="%"}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $Server) }
	 if ($VM -is [Array]) {$VM | ForEach-Object {Get-VMFloppyDisk -VM $_  }}
	 if ($VM -is [System.Management.ManagementObject]) {
	 Get-CimInstance -computerName $vm.__server -NameSpace "root\virtualization" -Query "Select * From MsVM_ResourceAllocationSettingData Where instanceId Like 'Microsoft:$($vm.name)%' and resourceSubtype = 'Microsoft Virtual Floppy Disk'"}
	 $vm = $null
	}

	######################################################################################################
	#                                                                                                    #
	# Functions for working with Networking, (NICS, switches and ports on switches that nics connect to) #
	#                                                                                                    #
	######################################################################################################

	Function Get-VMSwitch
	{Param ($name="%",$server=".")
	 $Name=$Name.replace("*","%")
	  Get-CimInstance -computerName $server -NameSpace  "root\virtualization" -query "Select * From MsVM_VirtualSwitch Where elementname like '$name' "
	}

	Filter Get-VMNic
	{Param ($VM, $server="." ,  [switch]$Legacy, [switch]$VMBus)
	 if ((-not ($legacy)) -and (-not ($VmBus)) ) {$vmbus = $legacy=$True}
	 if ($null -eq $VM) {$VM=$_}
	 if ($null -eq $VM) {$VM="%"}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $Server) }
	 if ($VM -is [Array]) {if ($legacy) {$VM | ForEach-Object {Get-VmNic -VM $_ -legacy} }
						   if ($vmbus)  {$VM | ForEach-Object {Get-VmNic -VM $_ -VMbus } } }
	 if ($VM -is [System.Management.ManagementObject]) {$vssd = Get-VMSettingData $vm 
		if ($legacy) {Get-CimInstance -computerName $vm.__server -NameSpace "root\virtualization" -Query "Associators of {$vssd} where resultClass=MsVM_EmulatedEthernetPortSettingData" }
		if ($vmbus)  {Get-CimInstance -computerName $vm.__server -NameSpace "root\virtualization" -Query "Associators of {$vssd} where resultClass=MsVM_SyntheticEthernetPortSettingData"}}
	 $vm = $null
	}
	#Example: Get-VMNic $core -legacy -vmbus
	#         Returns both Legacy and VMbus NICs found on the VM pointed to by $core


	Filter Get-VMNicport
	{Param ($nic) 
	 if ($null -eq $nic) {$nic=$_}
	 if ($nic -is [System.Management.ManagementObject]) {
	   Get-CimInstance -computerName $nic.__server -NameSpace "root\virtualization" -Query "Select * From Msvm_SwitchPort  where __Path='$( $nic.connection[0].replace('\','\\') )'" }
	 $nic=$null
	}
	#Example: Get-VMNic $core -legacy -vmbus | get-vmNicPort
	#         Returns the SwitchPorts on the NICs of the VM pointed to by $core 


	Filter Get-VMnicSwitch
	{Param ($nic)
	 if ($null -eq $nic) {$nic=$_}
	 if ($nic -is [System.Management.ManagementObject]) {
		 $NicPort=Get-VMNicPort $nic
		if ($nicPort) {Get-CimInstance -computerName $nic.__server  -NameSpace "root\virtualization" -Query "ASSOCIATORS OF {$nicPort} where resultclass = Msvm_VirtualSwitch" }
			else {"Not Connected"}}
	 $nic = $null
	}
	#Example:  (Get-VMNic $vm -legacy -vmbus | get-vmNicSwitch) | foreach-object {$_.elementName}
	#         Returns the Switches used by the VM pointed to by $core 


	Filter Get-VMSerialPort
	{Param ($VM, $portNo, $server=".")
		if ($null -eq $VM)    {$VM = $_}
		if ($null -eq $vm)    {$vm = "%"}
		if ($VM -is [String]) {$VM = (Get-VM -Name $VM -server $Server)}
		if ($VM -is [Array])  {$VM | ForEach-Object {Get-VMSerialPort -VM $_ -Server $Server -portNo $PortNo} }
		if ($VM -is [System.Management.ManagementObject]) {
			 $VSSD = (get-vmsettingData $VM)
			 $comPort = Get-CimInstance -namespace "root\virtualization" -computerName $VSSD.__Server -Query "ASSOCIATORS OF {$VSSD} where ResultClass=Msvm_ResourceAllocationSettingData" | Where-Object {$_.ResourceSubType -eq 'Microsoft Serial Port'}         
			 if ($PortNo) {$ComPort | Where-Object {$_.Caption -like "*$PortNo"} }
			 Else {$comPort}}
	}
	#Example Get-VMSerialPort "core"

	############################################################# 
	#                                                           # 
	# Functions for managing VM State (Snapshots and VM Export) #
	#                                                           #
	#############################################################

	Filter Get-VMSnapshot
	{Param ($VM, $Name="%", $Server=".", [Switch]$newest)
	 if ($null -eq $VM) {$VM=$_ }
	 if ($null -eq $VM) {$VM="%"}
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $server) }
	 if ($VM -is [Array]) {$VM | ForEach-Object {Get-VMSnapshot -VM $_ -Server $server} }
	 if ($VM -is [System.Management.ManagementObject]) {
		$Snaps=Get-CimInstance -computerName $vm.__server -NameSpace root\virtualization -Query "Select * From MsVM_VirtualSystemSettingData Where systemName='$($VM.name)' and instanceID <> 'Microsoft:$($VM.name)' and elementName like '$name' " }
		if ($newest) {$Snaps | Sort-Object creationTime | Select-Object -last 1 } else {$snaps}
	 $vm=$null
	}
	#Example: Get-Vmsnapshot $Core
	#         Returns the snapshots on the VM pointed to by $core


	Function Out-MultiLevelObject
	{Param ($items, $startAt, $path=("Path"), $parent=("Parent"), $label=("Label"), $indent=0, $Attributes="")
  	
		$children = $items | where-object {$_.$parent -eq $startAt.$path} 
 
  		$AttributesText = ""
 
		if ($null -ne $children) {
				foreach ($Attribute in $Attributes) {
					$AttributesText += " " + $Attribute + "=`"" + $startAt.$Attribute + "`""
				}
			if ($null -ne $startAt.$label) {
			("<Object level=`"$indent`"" + $AttributesText + ">") + "$($startAt.$label)"  + "</Object>" 
			}
			$children | ForEach-Object {Out-MultiLevelObject $items $_ $path $parent $label ($indent + 1) $Attributes} 
		} else {
			foreach ($Attribute in $Attributes) {
				$AttributesText += " " + $Attribute + "=`"" + $_.$Attribute + "`""
			}
			("<Object level=`"" + ($indent) + "`"" + $AttributesText + ">" + "$($startAt.$label)" + "</Object>")
		}
	}

	Function Get-VMDiskSnapthotTree {Param ($vmName)
		$Disks = get-vmdisk -snapshot -vm $vmName | Where-Object {$_.DiskName -eq "Hard Disk Image"} | Select-Object DiskPath, Diskimage, VMElementName, @{Name="ParentPath"; expression={ (get-vhdInfo -vhdPath $_.DiskPath)[1].ParentPath}}, @{Name="VHDSize"; expression={(FormatBytes -bytes ((get-vhdInfo -vhdPath $_.DiskPath)[1].FileSize) -precision 2)}}
	
		if ($null -ne $Disks) {
			Out-MultiLevelObject -items $Disks -start ($Disks | Where-Object {$_.diskImage -eq $_.diskPath}) -parent "ParentPath" -path "DiskPath" -label "VMElementName" -Attributes @("DiskPath", "VHDSize")
		}
	}

	Function Get-VMSnapshotTree
	{Param ($VM , $Server=".")
	 if ($VM -is [String]) {$VM=(Get-VM -Name $VM -Server $server) }
	 if ($VM -is [System.Management.ManagementObject]) {
	   $snapshots=(Get-VMSnapshot -VM $VM -Server $Server) 
	   #need to check for 0 or 1 snapshots
	   if ($snapshots -is [array]) {(Out-MultiLevelObject -items $snapshots -startAt ($snapshots | Where-Object{$null -eq $_.parent}) -path "__Path" -Parent "Parent" -label "elementname")} }
	}
	#Example: Get-VmsnapshotTree $Core
	#         Returns the snapshots on the VM pointed to by $core and displays them as a tree

	Function ObtainVersionInfoFromString([string] $VersionString)
	{
		$ReturnValue = @{}
		$VersionArray = $VersionString.Split('.')
		if ($VersionArray.Count -le 1)
		{
			$VersionArray = $VersionString.Split(',')
		}
		if ($VersionArray.Count -gt 0)
		{
			$ReturnValue += @{"FileMajorPart" = $VersionArray[0]}
		}
		if ($VersionArray.Count -gt 1)
		{
			$ReturnValue += @{"FileMinorPart" = $VersionArray[1]}
		}
		if ($VersionArray.Count -gt 2)
		{
			$ReturnValue += @{"FileBuildPart" = $VersionArray[2]}
		}
		if ($VersionArray.Count -gt 3)
		{
			$ReturnValue += @{"FilePrivatePart" = $VersionArray[3]}
		}
		return $ReturnValue
	}

	Function CheckMinimalVersion([string] $HostVersion, $GuestICVersion)
	{
		$HostVersionInfo = ObtainVersionInfoFromString $HostVersion
		$GuestICVersion = ObtainVersionInfoFromString $GuestICVersion

		if ($GuestICVersion.FileMajorPart -ge $HostVersionInfo.FileMajorPart)
		{
			if ($GuestICVersion.FileMinorPart -eq $HostVersionInfo.FileMinorPart)
			{
				if ($GuestICVersion.FileBuildPart -ge $HostVersionInfo.FileBuildPart)	
				{
					if ($GuestICVersion.FilePrivatePart -ge $HostVersionInfo.FilePrivatePart) 
					{
						return $true
					}
					else 
					{
						return $false
					}
				} 
				else 
				{
					return $false
				}
			}
			else
			{
				return ($GuestICVersion.FileMinorPart -gt $HostVersionInfo.FileMinorPart)
			}
		} 
		else 
		{
			return $false
		}	
	}

	Function EmbeddedXSL(){
	@'
	<?xml version="1.0"?>
	<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
	<xsl:output method="html" />
	<xsl:template match="/Root">
	<html dir="ltr" xmlns:v="urn:schemas-microsoft-com:vml" reportInitialized="false">
	  <head>
		<meta http-equiv="X-UA-Compatible" content="IE=EmulateIE8" />
	  </head>
  
	  <!-- Styles -->
	  <style type="text/css">
		body    { background-color:#FFFFFF; border:1px solid #666666; color:#000000; font-size:68%; font-family:Segoe UI, MS Shell Dlg; margin:0,0,10px,0; word-break:normal; word-wrap:break-word; }

		table   { font-size:100%; table-layout:fixed; width:100%; }

		td,th   { overflow:visible; text-align:left; vertical-align:top; white-space:normal; }

		.title  { background:#FFFFFF; border:none; color:#333333; display:block; height:24px; margin:0px,0px,-1px,0px; padding-top:4px; position:relative; table-layout:fixed; width:100%; z-index:5; }

		.he0    { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Segoe UI, Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:20px; padding-right:5em; padding-top:4px; position:relative; width:100%;
		filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}

		.he0_expanded   { background-color:#FEF7D6; border:1px solid #BBBBBB; color:#3333CC; cursor:hand; display:block; font-family:Segoe UI, Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:20px; padding-right:5em; padding-top:4px; position:relative; width:100%;
		filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#FEF7D6',EndColorStr='white');}

		.hev    { background-color:#CCDFFF; border:1px solid #BBBBBB; color:#3333CC; display:block; font-family:Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:23px; padding-right:5em; padding-top:4px; position:relative; width:100%;
		filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=1,StartColorStr='#CCDFFF',EndColorStr='white');}

		.he3_expanded { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:23px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

		.he4_expanded { background-color:#E9EFF3; border:1px solid #BBBBBB; color:#000000; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; height:2.25em; margin-bottom:-1px; font-weight:bold; margin-left:0px; margin-right:0px; padding-left:23px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

		.he1    { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, Verdana; font-size:110%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:0px; margin-right:0px; padding-left:23px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

		.he2    { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:23px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

		.he2b    { background-color:#C0D2DE; border:1px solid #BBBBBB; color:#000000; cursor:hand; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; font-weight:bold; height:2.25em; margin-bottom:-1px; margin-left:10px; margin-right:0px; padding-left:8px; padding-right:5em; padding-top:4px; position:relative; width:100%; }

		.he4i   { background-color:#F9F9F9; border:1px solid #BBBBBB; color:#000000; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:15px; margin-right:0px; padding-bottom:5px; padding-left:12px; padding-top:4px; position:relative; width:100%; }

		.he5i   { background-color:#E9EFF3; border:1px solid #BBBBBB; color:#000000; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; margin-bottom:-1px; margin-left:8px; margin-right:0px; padding-bottom:5px; padding-left:12px; padding-top:4px; position:relative; width:100%; }

		DIV .expando { color:#000000; text-decoration:none; display:block; font-family:Segoe UI, MS Shell Dlg; font-size:100%; font-weight:normal; position:absolute; right:10px; text-decoration:underline; z-index: 0; }

		.info4 TD, .info4 TH              { padding-right:10px; width:25%;}

		.infoFirstCol                     { padding-right:10px; width:20%; }
		.infoSecondCol                     { padding-right:10px; width:80%; }

		.lines0                           {background-color: #F5F5F5;}
		.lines1                           {background-color: #F9F9F9;}

		.explainlink:hover      { color:#0000FF; text-decoration:underline; }

		.filler { background:transparent; border:none; color:#FFFFFF; display:block; font:100% MS Shell Dlg; line-height:8px; margin-bottom:-1px; margin-left:43px; margin-right:0px; padding-top:4px; position:relative; }

		.container { display:block; position:relative; }

		.rsopheader { background-color:#A0BACB; border-bottom:1px solid black; color:#333333; font-family:Segoe UI, MS Shell Dlg; font-size:130%; font-weight:bold; padding-bottom:5px; text-align:center;
		filter:progid:DXImageTransform.Microsoft.Gradient(GradientType=0,StartColorStr='#FFFFFF',EndColorStr='#A0BACB')}

		.rsopname { color:#333333; font-family:Segoe UI, MS Shell Dlg; font-size:130%; font-weight:bold; padding-left:11px; }

		#uri    { color:#333333; font-family:Segoe UI, MS Shell Dlg; font-size:100%; padding-left:11px; }

		#dtstamp{ color:#333333; font-family:Segoe UI, MS Shell Dlg; font-size:100%; padding-left:11px; text-align:left; width:30%; }

		#objshowhide { color:#000000; cursor:hand; font-family:Segoe UI, MS Shell Dlg; font-size:100%; font-weight:bold; margin-right:0px; padding-right:10px; text-align:right; text-decoration:underline; z-index:2; word-wrap:normal; }

		v\:* {behavior:url(#default#VML);}

	  </style>
	<!-- Script 1 -->

	<script language="vbscript" type="text/vbscript">
	<![CDATA[
	<!--
	'================================================================================
	' String "strShowHide(0/1)"
	' 0 = Hide all mode.
	' 1 = Show all mode.
	strShowHide = 1

	'Localized strings
	strShow = "show"
	strHide = "hide"
	strShowAll = "show all"
	strHideAll = "hide all"
	strShown = "shown"
	strHidden = "hidden"
	strExpandoNumPixelsFromEdge = "10px"


	Function IsSectionHeader(obj)
		IsSectionHeader = (obj.className = "he0_expanded") Or (obj.className = "he1_expanded") Or (obj.className = "he1") Or (obj.className = "he0") Or (obj.className = "he2") Or (obj.className = "he2g") Or (obj.className = "he2c") or (obj.className = "he3") Or (obj.className = "he4") Or (obj.className = "he4h") Or (obj.className = "he5") Or (obj.className = "he5h")  or (obj.className = "he4_expanded")
	End Function


	Function IsSectionExpandedByDefault(objHeader)
		IsSectionExpandedByDefault = (Right(objHeader.className, Len("_expanded")) = "_expanded")
	End Function


	Sub SetSectionState(objHeader, strState)
		' Get the container object for the section.  It's the first one after the header obj.

		i = objHeader.sourceIndex
		Set all = objHeader.parentElement.document.all
		While (all(i).className <> "container")
			i = i + 1
		Wend

		Set objContainer = all(i)

		If strState = "toggle" Then
			If objContainer.style.display = "none" Then
				SetSectionState objHeader, "show"
			Else
				SetSectionState objHeader, "hide"
			End If

		Else
			x = 0
			bFound = false
			while ((not bFound) and (x < objHeader.children.length))
			  x = x + 1
			  if x < objHeader.children.length then
				Set objExpando = objHeader.children(x)
				if objExpando.className = "expando" then bFound = true
				rem msgbox objExpando.outerHTML + vbCrLf + "bFound: " + cstr(bFound) + vbCrLf + "x: " + cstr(x)
			  end if
			wend

			If strState = "show" Then
				objContainer.style.display = "block"
				objExpando.innerHTML =  "<v:group class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:5px;height:5px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " title=" & chr(34) & "Collapse" & chr(34) & ">" &_
										"  <v:shape class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:100; height:100; z-index:0" & chr(34) & " fillcolor=" & chr(34) & "#808080" & chr(34) & " strokecolor=" & chr(34) & "#303030" & chr(34) & ">" &_
										"    <v:path v=" & chr(34) & "m 100,0 l 0,99 99,99 x e" & chr(34) & " />" &_
										"  </v:shape>" &_
										"</v:group>"
			ElseIf strState = "hide" Then
				objContainer.style.display = "none"
				objExpando.innerHTML = "<v:group class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:9px;height:9px;vertical-align:middle" & chr(34) & " coordsize=" & chr(34) & "100,100" & chr(34) & " title=" & chr(34) & "Expand" & chr(34) & ">" &_
									   "  <v:shape class=" & chr(34) & "vmlimage" & chr(34) & " style=" & chr(34) & "width:100; height:100; z-index:0" & chr(34) & " fillcolor=" & chr(34) & "white" & chr(34) & " strokecolor=" & chr(34) & "#A0A0A0" & chr(34) & " name='Test'>" &_
									   "    <v:path v=" & chr(34) & "m 0,0 l 0,99 50,50 x e" & chr(34) & " />" &_
									   "  </v:shape>" &_
									   "</v:group>"
			end if
		End If
	End Sub


	Sub ShowSection(objHeader)
		SetSectionState objHeader, "show"
	End Sub


	Sub HideSection(objHeader)
		SetSectionState objHeader, "hide"
	End Sub


	Sub ToggleSection(objHeader)
		SetSectionState objHeader, "toggle"
	End Sub


	'================================================================================
	' When user clicks anywhere in the document body, determine if user is clicking
	' on a header element.
	'================================================================================
	Function document_onclick()
		Set strsrc    = window.event.srcElement

		While (strsrc.className = "sectionTitle" Or strsrc.className = "expando" Or strsrc.className = "vmlimage")
			Set strsrc = strsrc.parentElement
		Wend

		' Only handle clicks on headers.
		If Not IsSectionHeader(strsrc) Then Exit Function

		ToggleSection strsrc

		window.event.returnValue = False
	End Function

	'================================================================================
	' link at the top of the page to collapse/expand all collapsable elements
	'================================================================================
	Function objshowhide_onClick()
		Set objBody = document.body.all
		Select Case strShowHide
			Case 0
				strShowHide = 1
				objshowhide.innerText = strShowAll
				For Each obji In objBody
					If IsSectionHeader(obji) Then
						HideSection obji
					End If
				Next
			Case 1
				strShowHide = 0
				objshowhide.innerText = strHideAll
				For Each obji In objBody
					If IsSectionHeader(obji) Then
						ShowSection obji
					End If
				Next
		End Select
	End Function

	'================================================================================
	' onload collapse all except the first two levels of headers (he0, he1)
	'================================================================================
	Function window_onload()
		' Only initialize once.  The UI may reinsert a report into the webbrowser control,
		' firing onLoad multiple times.
		If UCase(document.documentElement.getAttribute("reportInitialized")) <> "TRUE" Then

			' Set text direction
			Call fDetDir(UCase(document.dir))

			' Initialize sections to default expanded/collapsed state.
			Set objBody = document.body.all

			For Each obji in objBody
				If IsSectionHeader(obji) Then
					If IsSectionExpandedByDefault(obji) Then
						ShowSection obji
					Else
						HideSection obji
					End If
				End If
			Next

			objshowhide.innerText = strShowAll

			document.documentElement.setAttribute "reportInitialized", "TRUE"
		End If
	End Function




	'================================================================================
	' When direction (LTR/RTL) changes, change adjust for readability
	'================================================================================
	Function document_onPropertyChange()
		If window.event.propertyName = "dir" Then
			Call fDetDir(UCase(document.dir))
		End If
	End Function
	Function fDetDir(strDir)
		strDir = UCase(strDir)
		Select Case strDir
			Case "LTR"
				Set colRules = document.styleSheets(0).rules
				For i = 0 To colRules.length -1
					Set nug = colRules.item(i)
					strClass = nug.selectorText
					If nug.style.textAlign = "right" Then
						nug.style.textAlign = "left"
					End If
					Select Case strClass
						Case "DIV .expando"
							nug.style.Left = strExpandoNumPixelsFromEdge
							nug.style.right = ""
						Case "#objshowhide"
							nug.style.textAlign = "right"
					End Select
				Next
			Case "RTL"
				Set colRules = document.styleSheets(0).rules
				For i = 0 To colRules.length -1
					Set nug = colRules.item(i)
					strClass = nug.selectorText
					If nug.style.textAlign = "left" Then
						nug.style.textAlign = "right"
					End If
					Select Case strClass
						Case "DIV .expando"
							nug.style.Left = strExpandoNumPixelsFromEdge
							nug.style.right = ""
						Case "#objshowhide"
							nug.style.textAlign = "right"
					End Select
				Next
		End Select
	End Function


	-->
	]]>
	</script>

	  <body>

		<table class="title" cellpadding="0" cellspacing="0">
		<tr><td colspan="2" class="rsopheader">Hyper-V Information</td></tr>
		<tr><td colspan="2" class="rsopname">Machine name: <xsl:value-of select="Title"/></td></tr>
		<tr><td id="dtstamp">Data collected on: <xsl:value-of select="TimeField"/></td><td><div id="objshowhide" tabindex="0"></div></td></tr>
		</table>
		<div class="filler"></div>
	  <xsl:if test="./Alerts/Alert">
		<div class="container">
		  <div class="he0_expanded">
			<span class="sectionTitle" tabindex="0">Alerts</span>
			<a class="expando" href="#"></a>
		  </div>
		  <div class="container">
			<xsl:for-each select="./Alerts/Alert">
			  <xsl:sort select="AlertPriority" order="descending" data-type="number"/>
			  <div class="he2b">
				<span class="sectionTitle" tabindex="0">
				  <xsl:choose>
					<xsl:when test="AlertType = 'Information'">
					  <v:group id="Inf1" class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Information">
						<v:oval class="vmlimage" style="width:100;height:100;z-index:0" fillcolor="white" strokecolor="#336699" />
						<v:line class="vmlimage" style="z-index:1" from="50,15" to="50,25" strokecolor="#336699" strokeweight="3px" />
						<v:line class="vmlimage" style="z-index:2" from="50,35" to="50,80" strokecolor="#336699" strokeweight="3px" />
					  </v:group>
					</xsl:when>
					<xsl:when test="AlertType = 'Warning'">
					  <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Warning">
						<v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="yellow" strokecolor="#C0C0C0">
						  <v:path v="m 50,0 l 0,99 99,99 x e" />
						</v:shape>
						<v:rect class="vmlimage" style="top:35; left:45; width:10; height:35; z-index:1" fillcolor="black" strokecolor="black">
						</v:rect>
						<v:rect class="vmlimage" style="top:85; left:45; width:10; height:5; z-index:1" fillcolor="black" strokecolor="black">
						</v:rect>
					  </v:group>
					</xsl:when>
					<xsl:when test="AlertType = 'Error'">
					  <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Error">
						<v:oval class="vmlimage" style='width:100;height:100;z-index:0' fillcolor="red" strokecolor="red">
						</v:oval>
						<v:line class="vmlimage" style="z-index:1" from="25,25" to="75,75" strokecolor="white" strokeweight="3px">
						</v:line>
						<v:line class="vmlimage" style="z-index:2" from="75,25" to="25,75" strokecolor="white" strokeweight="3px">
						</v:line>
					  </v:group>
					</xsl:when>
					<xsl:when test="AlertType = 'Memory Dump'">
					  <v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100" title="Memory Dump">
						<v:roundrect class="vmlimage" arcsize="0.3" style="width:100;height:100;z-index:0" fillcolor="#008000" strokecolor="#66665B" />
						<v:line class="vmlimage" style="z-index:2" from="50,15" to="50,60" strokecolor="white" strokeweight="3px" />
						<v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="white" strokecolor="white">
						  <v:path v="m 50,85 l 75,60 25,60 x e" />
						</v:shape>
					  </v:group>
					  <xsl:text>&#160;</xsl:text>
					</xsl:when>
				  </xsl:choose>
				  <xsl:value-of select="AlertType"/>
				</span>
				<a class="expando" href="#"></a>
			  </div>
			  <div class="container">
				<div class="he4i">
				  <table cellpadding="0" class="info0">
					<tr>
					  <td class="infoFirstCol">Category: </td>
					  <td class="infoSecondCol">
						<xsl:value-of disable-output-escaping="yes" select="AlertCategory"/>
					  </td>
					  <td></td>
					</tr>
					<tr>
					  <td class="infoFirstCol">Message: </td>
					  <td class="infoSecondCol">
						<xsl:copy-of select="AlertMessage"/>
					  </td>
					  <td></td>
					</tr>
					<xsl:if test="AlertRecommendation">
					  <tr>
						<td class="infoFirstCol">Recommendation: </td>
						<td class="infoSecondCol">
						  <xsl:copy-of select="AlertRecommendation"/>
						</td>
						<td></td>
					  </tr>
					</xsl:if>
				  </table>
				</div>
			  </div>
			</xsl:for-each>
		  </div>
		</div>
	  </xsl:if>
		<div class="filler"></div>

	  <div class="hev">
		<span class="sectionTitle" tabindex="0">
		  Hyper-V Information
		</span>
	  </div>
	  <div class="filler"></div>


	  <xsl:for-each select="./Section">
		<xsl:if test="position() = 3">
		  <div class="hev">
			<span class="sectionTitle" tabindex="0">
			  Virtual Machines
			</span>
		  </div>
		  <div class="filler"></div>
		</xsl:if> 
		<div class="he0"><span class="sectionTitle" tabindex="0"> 
		<xsl:choose>
		  <xsl:when test="./Item[@name='Status'] = 'Running'">
			<v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100" title="Running">
			  <v:roundrect class="vmlimage" arcsize="20" style="width:100;height:100;z-index:0" fillcolor="#00D700" strokecolor="#66665B" />
			  <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="white" strokecolor="white">
				<v:path v="m 40,25 l 75,50 40,75 x e" />
			  </v:shape>
			</v:group>
			<xsl:text>&#160;</xsl:text>
		  </xsl:when>
		  <xsl:when test="./Item[@name='Status'] = 'Starting'">
			<v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100" title="Starting">
			  <v:roundrect class="vmlimage" arcsize="20" style="width:100;height:100;z-index:0" fillcolor="#0080FF" strokecolor="#66665B" />
			  <v:line class="vmlimage" style="z-index:2" from="50,50" to="50,85" strokecolor="white" strokeweight="3px" />
			  <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="white" strokecolor="white">
				<v:path v="m 50,15 l 75,60 25,60 x e" />
			  </v:shape>
			</v:group>
			<xsl:text>&#160;</xsl:text>
		  </xsl:when>
		  <xsl:when test="./Item[@name='Status'] = 'Stopped'">
			<v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100" title="Stopped">
			  <v:roundrect class="vmlimage" arcsize="20" style="width:100;height:100;z-index:0" fillcolor="#EC0000" strokecolor="#66665B" />
			  <v:line class="vmlimage" style="z-index:2" from="50,28" to="50,75" strokecolor="white" strokeweight="6px" />
			</v:group>
			<xsl:text>&#160;</xsl:text>
		  </xsl:when>
		  <xsl:when test="./Item[@name='Status'] = 'Paused'">
			<v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100" title="Paused">
			  <v:roundrect class="vmlimage" arcsize="20" style="width:100;height:100;z-index:0" fillcolor="#FF8000" strokecolor="##66665B" />
			  <v:line class="vmlimage" style="z-index:2" from="40,25" to="40,75" strokecolor="white" strokeweight="2px" />
			  <v:line class="vmlimage" style="z-index:2" from="60,25" to="60,75" strokecolor="white" strokeweight="2px" />
			</v:group>
			<xsl:text>&#160;</xsl:text>
		  </xsl:when>
		  <xsl:when test="./Item[@name='Status'] = 'Suspended'">
			<v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100">
			  <v:roundrect class="vmlimage" arcsize="20" style="width:100;height:100;z-index:0" fillcolor="#A79C41" strokecolor="#66665B" />
			  <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="white" strokecolor="white">
				<v:path v="m 50,75 l 75,35 25,35 x e" />
			  </v:shape>
			</v:group>
			<xsl:text>&#160;</xsl:text>
		  </xsl:when>
		  <xsl:when test="./Item[@name='Status']">
			<v:group class="vmlimage" style="width:14px;height:14px;vertical-align:middle" coordsize="100,100">
			  <v:roundrect class="vmlimage" arcsize="20" style="width:100;height:100;z-index:0" fillcolor="#C0C0C0" strokecolor="#66665B" />
			  <v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="white" strokecolor="white">
				<v:path v="m 50,25 l 75,70 25,70 x e" />
			  </v:shape>
			</v:group>
			<xsl:text>&#160;</xsl:text>
		  </xsl:when>
		</xsl:choose>
		<xsl:value-of select="SectionTitle"/></span><a class="expando" href="#"></a></div>
	
			<div class="container"><div class="he4i"><table cellpadding="0" class="info4" >
			<tr><td></td><td></td><td></td><td></td><td></td></tr>
			<xsl:for-each select="./Item">
			<xsl:variable name="pos" select="position()" />
			<xsl:variable name="mod" select="($pos mod 2)" />
			<tr><td class="lines{$mod}"><xsl:value-of select="@name"/></td><td colspan="4" class="lines{$mod}"><xsl:value-of select="."/></td></tr>
			</xsl:for-each>
			</table>
			<xsl:for-each select="./SubSection">
				<div class="container">
				<div class="he1"><span class="sectionTitle" tabindex="0"><xsl:value-of select="SectionTitle/@name"/><xsl:text> </xsl:text><a name="{SectionTitle}"><xsl:value-of select="SectionTitle"/></a></span><a class="expando" href="#"></a></div>
				<div class="container"><div class="he4i"><table cellpadding="0" class="info4">
					<tr><td></td><td></td><td></td><td></td><td></td></tr>
					<xsl:for-each select="./Item">
					<xsl:variable name="pos" select="position()" />
					<xsl:variable name="mod" select="($pos mod 2)" />
			  <xsl:choose>
				<xsl:when test="@name='State'">
				  <tr>
					<td>
					  <xsl:value-of select="@name"/>
					</td>
					<td colspan="4">
					  <xsl:value-of disable-output-escaping="yes" select="."/>
					</td>
					<td></td>
				  </tr>
				</xsl:when>
				<xsl:otherwise>
				  <tr>
					<td class="lines{$mod}">
					  <xsl:value-of select="@name"/>
					</td>
					<td colspan="4" class="lines{$mod}">
					  <xsl:copy-of select="."/>
					</td>
					<td></td>
				  </tr>
				</xsl:otherwise>
			  </xsl:choose>
					</xsl:for-each>
					</table>
			
		  <!-- Sub Sub section-->

			<xsl:for-each select="./SubSection">
			  <div class="container">
				<div class="he5i">
				  <span class="sectionTitle" tabindex="0">
					<xsl:value-of select="SectionTitle/@name"/>
					<xsl:text> </xsl:text>
					<a name="{SectionTitle}">
					  <xsl:value-of select="SectionTitle"/>
					</a>
				  </span>
				  <a class="expando" href="#"></a>
				</div>
				<div class="container">
				  <div class="he4i">
					<table cellpadding="0" class="info4">
					  <tr>
						<td></td>
						<td></td>
						<td></td>
						<td></td>
						<td></td>
					  </tr>
					  <xsl:for-each select="./Item">
						<xsl:variable name="pos" select="position()" />
						<xsl:variable name="mod" select="($pos mod 2)" />
						<tr class="lines{$mod}">
						  <td>
							<xsl:value-of select="@name"/>
						  </td>
						  <td colspan="4">
							<xsl:value-of disable-output-escaping="yes" select="."/>
						  </td>
						  <td></td>
						</tr>
					  </xsl:for-each>
					</table>
				  </div>
				</div>
			  </div>
			</xsl:for-each>
		  <!-- Snapshots Obj -->
			<xsl:if test="./SnapshotObject">
				<xsl:for-each select="./SnapshotObject/Object">
				  <xsl:variable name="level" select="(@level * 40)" />
				  <xsl:variable name="leveltable" select="(@level * 40) + 5" />
				  <div class="he4i" style="margin-left:{$level}; background-color:#E9EFF3">
					<table cellpadding="0">
					  <tr>
						<td>
						  <xsl:choose>
							<xsl:when test=". = ../../../SectionTitle">
							  <v:group class="vmlimage" style="width:15px;height:15px;vertical-align:middle" coordsize="100,100" title="Now">
								<v:shape class="vmlimage" style="width:100; height:100; z-index:0" fillcolor="green" strokecolor="#C0C0C0">
								  <v:path v="m 40,10 l 100,50 40,90 x e" />
								</v:shape>
							  </v:group>
							  <xsl:text>&#160;</xsl:text>
							  Now
							</xsl:when>
							<xsl:otherwise>
							  <xsl:value-of select="."/>
							</xsl:otherwise>
						  </xsl:choose>
						</td>
					  </tr>
					</table>
				  </div>
				  <div class="container">
					<div class="he4i" style="margin-left:{$leveltable}">
					  <table cellpadding="0" autosize="1">
						<tr class="lines1">
						  <td class="infoFirstCol">
							VHD Path
						  </td>
						  <td class="infoSecondCol">
							<xsl:value-of select="@DiskPath"/>
						  </td>
						</tr>
						<tr class="lines0">
						  <td class="infoFirstCol">
							Size
						  </td>
						  <td class="infoSecondCol">
							<xsl:value-of select="@VHDSize"/>
						  </td>
						</tr>
					  </table>
					</div>
				  </div>
				</xsl:for-each>
			</xsl:if>
		</div>
		</div>
		  </div>

		</xsl:for-each>

		</div></div>
		<div class="filler"></div>

		</xsl:for-each>

	</body>
	</html>
	</xsl:template>
	</xsl:stylesheet>
'@
	}


	############################################################# 
	#                                                           # 
	# Script Starts Here                                        #
	#                                                           #
	#############################################################

	$Error.Clear()

	#Removed code below once this version will always be running on WTP
	#if (((Get-Host).Name -ne "Default Host") -and ($SDP30.IsPresent -eq $false)) {
	#	"Windows Troubleshooting Platform not loaded."
	#	$TroubleshootingModuleLoaded = $false
	#} else {
	#    $TroubleshootingModuleLoaded = $true
	#}

	$HyperVKey = "HKLM:\SYSTEM\CurrentControlSet\services\vmms"

	$512eDrivesXMLPath = Join-Path -Path $PWD.Path -ChildPath "512eDrives.xml"
	$512eDrives = @()

	if (Test-Path $HyperVKey) 
	{
		$PowerShellV2 = (((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine").PowerShellVersion).Substring(0,1) -ge 2)
	
		if (Test-Path $512eDrivesXMLPath)
		{
			$512eDrives = Import-Clixml -Path $512eDrivesXML
		}
	
		$VM_Summary = new-object PSObject

		$xmlDoc = [xml] "<?xml version=""1.0""?><Root/>"

		Import-LocalizedData -BindingVariable HyperVStrings
		Write-ScriptProgress -activity $HyperVStrings.ID_HyperVInfo -status $HyperVStrings.ID_HyperVInfoDesc

		#********************
		# General Info
		#********************
	
		AddXMLElement -ElementName "Title" -Value $Env:COMPUTERNAME
		$CurrentDate = Get-Date
		AddXMLElement -ElementName "TimeField" -Value $CurrentDate 

		Write-ScriptProgress -activity $HyperVStrings.ID_HyperVInfo -status $HyperVStrings.ID_HyperVInfoParent
		OpenSection -name "HostInfo" -title "Host Information"
		
		$HostInfo = Get-HyperVHostInfo
		$HyperVVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization").Version
	
		$HostIntegrationOS6 = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestInstaller\Version")."Microsoft-Hyper-V-Guest-Installer-Win60-Package"
		$HostIntegrationOS5 = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestInstaller\Version")."Microsoft-Hyper-V-Guest-Installer-Win60-Package"
	
		AddXMLElement -attributeValue "Name" -Value ($HostInfo.InstanceID.Substring(10)) -xpath "/Root/Section[@name=`'HostInfo`']"
		if ($null -ne $HyperVVersion) {AddXMLElement -attributeValue "Version" -Value $HyperVVersion -xpath "/Root/Section[@name=`'HostInfo`']"}
		AddXMLElement -attributeValue "Default VM Configuration Folder" -Value $HostInfo.DefaultExternalDataRoot -xpath "/Root/Section[@name=`'HostInfo`']"
		AddXMLElement -attributeValue "Default VHD Folder" -Value $HostInfo.DefaultVirtualHardDiskPath -xpath "/Root/Section[@name=`'HostInfo`']"
		AddXMLElement -attributeValue "MAC Address range" -Value ($HostInfo.MinimumMacAddress + " - " + $HostInfo.MaximumMacAddress) -xpath "/Root/Section[@name=`'HostInfo`']"
	
		Write-ScriptProgress -activity $HyperVStrings.ID_HyperVInfo -status $HyperVStrings.ID_HyperVInfoSwitches
		OpenSection -name "Switches" -title "Virtual Switches"

		#********************
		# Network Switches
		#********************
	
		$VMSwitches = Get-VMSwitch
		$LineCount =0
		if ($null -ne $VMSwitches) {
			foreach ($VMSwitch in $VMSwitches) 
			{
				$LineCount += 1
				$VMSwitchID = $VMSwitch.Name
				$VMElementName = $VMSwitch.ElementName
				AddXMLElement -ElementName "SubSection" -attributeValue $VMSwitchID -xpath "/Root/Section[@name=`'Switches`']"
				AddXMLElement -ElementName "SectionTitle" -attributeValue $VMElementName -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"
			
				$InternalEthernetPort = Get-CimInstance Msvm_InternalEthernetPort -Namespace root\virtualization -Filter "ElementName = `'$VMElementName`'"
				$Filter = "SettingID = `'" + $InternalEthernetPort.DeviceID + "`'"
				$NetworkAdapterConfiguration = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter $Filter
			
				$Filter = "Index = `'" + $NetworkAdapterConfiguration.Index + "`'"
				$NetworkAdapter = Get-CimInstance Win32_NetworkAdapter -Filter $Filter
			
				AddXMLElement -attributeValue "Network Connection ID" -value $NetworkAdapter.NetConnectionID -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"
				AddXMLElement -attributeValue "Name" -value $NetworkAdapter.Name -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"
				AddXMLElement -attributeValue "Enabled" -value $NetworkAdapter.NetEnabled -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"
			
				switch ($NetworkAdapter.NetConnectionStatus)	
				{
					0 {$NICStatusDisplay = "Disconnected"}
					1 {$NICStatusDisplay = "Connecting"}
					2 {$NICStatusDisplay = "Connected"}
					3 {$NICStatusDisplay = "Disconnecting"}
					7 {$NICStatusDisplay = "Media disconnected"}
					11 {$NICStatusDisplay = "Invalid address"}
					Default {$NICStatusDisplay = "Other state ("+ $NetworkAdapter.NetConnectionStatus + ")"}
				}
	
				AddXMLElement -attributeValue "Status" -value $NICStatusDisplay -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"
					
				AddXMLElement -attributeValue "MAC Address" -value $NetworkAdapter.MACAddress -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"
			
				$IPAddressDisplay = ""
				foreach ($IPAddress in $NetworkAdapterConfiguration.IPAddress) {
					if ($IPAddressDisplay -ne "") {$IPAddressDisplay += "<br/>"}
					$IPAddressDisplay += $IPAddress
				}
	
				AddXMLElement -attributeValue "IP Address" -value $IPAddressDisplay -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"
	
				$SubnetDisplay = ""
				foreach ($Subnet in $NetworkAdapterConfiguration.IPSubnet) {
					if ($SubnetDisplay -ne "") {$SubnetDisplay += "/ "}
					$SubnetDisplay += $Subnet
				}
	
				AddXMLElement -attributeValue "Subnet Mask" -value $SubnetDisplay -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"
			
				if ($null -ne $NetworkAdapterConfiguration.DHCPEnabled) {
					AddXMLElement -attributeValue "DHCP Enabled" -value $NetworkAdapterConfiguration.DHCPEnabled -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"	
					if ($null -ne $NetworkAdapterConfiguration.DHCPServer) {AddXMLElement -attributeValue "DHCP Server" -value $NetworkAdapterConfiguration.DHCPServer -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"}	
				} else {
					AddXMLElement -attributeValue "DHCP Enabled" -value "No" -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"	
				}
			
				if ($null -ne $NetworkAdapterConfiguration.DNSDomain) {
					AddXMLElement -attributeValue "DNS Domain" -value $NetworkAdapterConfiguration.DNSDomain -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"	
				}
			} #VMSwitches
		} else {
			$VMSwitchID = "VMSwitchNone"
			AddXMLElement -ElementName "SubSection" -attributeValue $VMSwitchID -xpath "/Root/Section[@name=`'Switches`']"
			AddXMLElement -ElementName "SectionTitle" -attributeValue "(There are no networks configured)" -xpath "/Root/Section[@name=`'Switches`']/SubSection[@name=`'$VMSwitchID`']"
		}
	
		#********************
		# Virtual Machines
		#********************

		$VirtualMachines = Get-VM
	
		Write-ScriptProgress -activity $HyperVStrings.ID_HyperVInfo -status $HyperVStrings.ID_HyperVInfoGuests
	
		Foreach ($VirtualMachine in $VirtualMachines)
		{
	
			#***************************
			# Virtual Machines - General
			#***************************
	
			$VMGUID = $VirtualMachine.Name
			OpenSection -name $VMGUID -title $VirtualMachine.ElementName		
			Write-ScriptProgress -activity $HyperVStrings.ID_HyperVInfoGuest -status ($VirtualMachine.ElementName)
		
			$VMStateDisplay = Convert-VMState $VirtualMachine.EnabledState
		
			AddXMLElement -attributeValue "Status" -value $VMStateDisplay -xpath "/Root/Section[@name=`'$VMGUID`']"
		
			if (($null -ne $VirtualMachine.OnTimeInMilliseconds) -and ($VirtualMachine.OnTimeInMilliseconds -ne 0)) 
			{
				$Uptime = MillisecondsToDateDisplay($VirtualMachine.OnTimeInMilliseconds)
				AddXMLElement -attributeValue "Up Time" -value $Uptime -xpath "/Root/Section[@name=`'$VMGUID`']"
			}
			AddXMLElement -attributeValue "Install Date" -value ([System.Management.ManagementDateTimeConverter]::ToDateTime($VirtualMachine.InstallDate).ToString()) -xpath "/Root/Section[@name=`'$VMGUID`']"
		
			AddXMLElement -attributeValue "Last Configuration change" -value ([System.Management.ManagementDateTimeConverter]::ToDateTime($VirtualMachine.TimeOfLastConfigurationChange).ToString()) -xpath "/Root/Section[@name=`'$VMGUID`']"
		
			AddXMLElement -attributeValue "Last State change" -value ([System.Management.ManagementDateTimeConverter]::ToDateTime($VirtualMachine.TimeOfLastStateChange).ToString()) -xpath "/Root/Section[@name=`'$VMGUID`']"

			switch ($VirtualMachine.HealthState)	
			{
				5 {$HealthStateDisplay = "OK"}
				20 {$HealthStateDisplay = "Major Failure"}
				25 {$HealthStateDisplay = "Critical failure"}
				Default {$HealthStateDisplay = "Other state ("+ $VirtualMachine.HealthState.ToString() + ")"}
			}	
			AddXMLElement -attributeValue "Health State" -value $HealthStateDisplay -xpath "/Root/Section[@name=`'$VMGUID`']"

			switch ($VirtualMachine.OperationalStatus[0])	{
				2 {$OperationalStatusDisplay = "Operating Normally"}
				3 {$OperationalStatusDisplay = "Degraded"}
				5 {$OperationalStatusDisplay = "Predictive Failure"}
				10 {$OperationalStatusDisplay = "Stopped"}
				11 {$OperationalStatusDisplay = "In Service (VM is processing a request)"}
				15 {$OperationalStatusDisplay = "Suspended or Paused"}
				Default {$OperationalStatusDisplay = "Other state ("+ $VirtualMachine.OperationalStatus[0] + ")"}
			}	
		
			AddXMLElement -attributeValue "Operational Status" -value $OperationalStatusDisplay -xpath "/Root/Section[@name=`'$VMGUID`']"

			if ($null -ne $VirtualMachine.OperationalStatus[1]) {
				switch ($VirtualMachine.OperationalStatus[1])	{
					32768 {$OperationDisplay = "Creating Snapshot"}
					32769 {$OperationDisplay = "Applying Snapshot"}
					32770 {$OperationDisplay = "Deleting Snapshot"}
					32771 {$OperationDisplay = "Waiting to Start"}
					32772 {$OperationDisplay = "Merging Disks"}
					32773 {$OperationDisplay = "Exporting Virtual Machine"}
					32774 {$OperationDisplay = "Migrating Virtual Machine"}
					Default {$OperationDisplay = "Other operation ("+ $VirtualMachine.OperationalStatus[1] + ")"}
				}	
				AddXMLElement -attributeValue "Current Operation" -value $OperationDisplay -xpath "/Root/Section[@name=`'$VMGUID`']"
			}
		
			AddXMLElement -attributeValue "GUID" -value $VMGUID -xpath "/Root/Section[@name=`'$VMGUID`']"

			if ($VirtualMachine.EnabledState -eq $VMState["running"]) 
			{

				#***********************************
				# Virtual Machines - Guest OS
				#***********************************
	
				Write-ScriptProgress -activity $HyperVStrings.ID_HyperVInfo -status (($VirtualMachine.ElementName) + " - " + $HyperVStrings.ID_HyperVInfoGuest)
	
				$VMStateSummary = $VirtualMachine | Get-VMKVP
	
				AddXMLElement -ElementName "SubSection" -attributeValue "CurrentState" -xpath "/Root/Section[@name=`'$VMGUID`']"
				AddXMLElement -ElementName "SectionTitle" -attributeValue "Guest Operating System Information" -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'CurrentState`']"
			
				if ($null -ne $VMStateSummary.FullyQualifiedDomainName) {AddXMLElement -attributeValue "FQDN" -value $VMStateSummary.FullyQualifiedDomainName -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'CurrentState`']"}
				if ($null -ne $VMStateSummary.OSName) {AddXMLElement -attributeValue "Guest Operating System" -value $VMStateSummary.OSName -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'CurrentState`']"}
				if ($null -ne $VMStateSummary.CSDVersion) {
					if ($VMStateSummary.CSDVersion.Length -eq 0) 
					{
						$CSDVersion = "(None)"
					} else {
						$CSDVersion = $VMStateSummary.CSDVersion
					}
					AddXMLElement -attributeValue "Service Pack" -value $CSDVersion -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'CurrentState`']"
					}			
				if ($null -ne $VMStateSummary.OSVersion) {AddXMLElement -attributeValue "Operating System Version" -value $VMStateSummary.OSVersion -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'CurrentState`']"}
				if ($null -ne $VMStateSummary.ProcessorArchitectureText) {AddXMLElement -attributeValue "Operating System Processor Architecture" -value $VMStateSummary.ProcessorArchitectureText -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'CurrentState`']"}
				if ($null -ne $VMStateSummary.ProductTypeText) {AddXMLElement -attributeValue "Type" -value $VMStateSummary.ProductTypeText -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'CurrentState`']"}
				if ($null -ne $VMStateSummary.Descriptions) {
					$OSDescriptionHTM  = ""
					foreach ($OSDescription in $VMStateSummary.Descriptions) {
						if ($OSDescriptionHTM -ne "") {$OSDescriptionHTM += "<br/>"}
						$OSDescriptionHTM += $OSDescription
					}
					#AddXMLElement -attributeValue "Product Suites" -value $OSDescriptionHTM -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'CurrentState`']"
				}
				if ($null -ne $VMStateSummary.IntegrationServicesVersion) 
				{
					if ($VMStateSummary.IntegrationServicesVersion -ne $HyperVVersion) {[Array]$IntServicesOldVersions += $VirtualMachine.ElementName}
					$DisplayPrefix = ""
					if ((CheckMinimalVersion $HostIntegrationOS6 $VMStateSummary.IntegrationServicesVersion) -eq $false)
					{
						$InformationCollected = @{"Guest Name" = $VirtualMachine.ElementName}
						$InformationCollected += @{"Guest OS" = $VMStateSummary.OSName}
						$InformationCollected += @{"Guest OS IC Version" = $VMStateSummary.IntegrationServicesVersion}
						$InformationCollected += @{"Host OS IC Version" = $HostIntegrationOS6}
					
						if ($VMMemory.DynamicMemoryEnabled)
						{
							$InformationCollected += @{"Dynamic Memory Enabled" = $true.ToString()}
							$RC_DynamicMemoryOldIntegrationDetected = $true
							Write-GenericMessage -RootCauseID "RC_DynamicMemoryOldIntegration" -Component "Hyper-V" -Verbosity "Error" -InformationCollected $InformationCollected -PublicContentURL "http://technet.microsoft.com/en-us/library/ff817651(WS.10).aspx" -SDPFileReference ($ComputerName + "_HyperV-Info.HTM") -SupportTopicsID 8142 -MessageVersion 2 -Visibility 4
							$DisplayPrefix = "<font face=`"Webdings`" color=`"Red`">n</font> "
						}
						else
						{
							$RC_MismatchedICDetected = $true
							Write-GenericMessage -RootCauseID "RC_MismatchedIC" -Component "Hyper-V" -Verbosity "Warning" -InformationCollected $InformationCollected -PublicContentURL "http://technet.microsoft.com/en-us/library/ee207413(WS.10).aspx" -SDPFileReference ($ComputerName + "_HyperV-Info.HTM")  -SupportTopicsID 8142 -MessageVersion 2 -Visibility 4
							$DisplayPrefix = "<font face=`"Webdings`" color=`"Orange`">n</font> "
						}
					}
					else
					{
						$DisplayPrefix = "<font face=`"Webdings`" color=`"Green`">n</font> "
					}
					AddXMLElement -attributeValue "Integration Services Version" -value ($DisplayPrefix + $VMStateSummary.IntegrationServicesVersion) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'CurrentState`']"
				} 
				else 
				{			
					[array] $IntServicesUnknownVersions += $VirtualMachine.ElementName
				}			
				if ($null -ne $VMStateSummary.NetworkAddressIPv4) {AddXMLElement -attributeValue "IPv4 Address" -value $VMStateSummary.NetworkAddressIPv4.Replace(";", "<br/>") -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'CurrentState`']"}
				if ($null -ne $VMStateSummary.NetworkAddressIPv6 -and $VMStateSummary.NetworkAddressIPv6.Length -ne 0) {AddXMLElement -attributeValue "IPv6 Address" -value $VMStateSummary.NetworkAddressIPv6.Replace(";", "<br/>") -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'CurrentState`']"}			
			}
		
			#****************
			#  Add basic VM Info on SDP 3.0 Report
			#**************
			if ($TroubleshootingModuleLoaded -eq $true)
			{
				Switch ($VirtualMachine.EnabledState)
				{
					$VMState["Running"] 
					{
						$VMStateSDPDisplay = $VGroupRunning + " Running" 
						$VMOS = ""
						if ($null -ne $VMStateSummary.OSName) 
						{ 
							$VMOS += $VMStateSummary.OSName
							if ($null -ne $CSDVersion)
							{
								if ($CSDVersion -ne "(None)") {$VMOS += " $CSDVersion"}
							}
							$VMStateSDPDisplay += " [" + $VMOS + "]"
						}
					}
					$VMState["Stopped"] {$VMStateSDPDisplay = $VGroupStopped + " Stopped" }
					$VMState["Suspended"] {$VMStateSDPDisplay = $VGroupSuspended + " Suspended" }
					$VMState["Starting"] {$VMStateSDPDisplay = $VGroupStarting + " Starting" }				
					Default { $VMStateSDPDisplay = $VGroupOtherState + " " + $VMStateDisplay }
				}
					
				add-member -inputobject $VM_Summary -membertype noteproperty -name ($VirtualMachine.ElementName) -value $VMStateSDPDisplay

			}
		
		
			Write-ScriptProgress -activity $HyperVStrings.ID_HyperVInfo -status (($VirtualMachine.ElementName) + " - " + $HyperVStrings.ID_HyperVInfoGuestGeneral)
		
			#***********************************
			# Virtual Machines - Memory
			#***********************************
		
			$VMMemory = $VirtualMachine | Get-VMMemory

			AddXMLElement -ElementName "SubSection" -attributeValue "Memory" -xpath "/Root/Section[@name=`'$VMGUID`']"
			AddXMLElement -ElementName "SectionTitle" -attributeValue "Memory" -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Memory`']"

			if ($VMMemory.DynamicMemoryEnabled)
			{
				AddXMLElement -attributeValue "Dynamic Memory" -value "Enabled" -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Memory`']"
				AddXMLElement -attributeValue "Startup Memory" -value ($VMMemory.VirtualQuantity.ToString() + " " + $VMMemory.AllocationUnits) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Memory`']"
				AddXMLElement -attributeValue "Maximum Memory" -value ($VMMemory.Limit.ToString() + " " + $VMMemory.AllocationUnits) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Memory`']"
				AddXMLElement -attributeValue "Memory Buffer" -value ($VMMemory.TargetMemoryBuffer) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Memory`']"
				AddXMLElement -attributeValue "Weight" -value ($VMMemory.Weight) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Memory`']"
			
				$InformationCollected = @{"Guest Name"=$VirtualMachine.ElementName}
				$InformationCollected += @{"Startup Memory"=($VMMemory.VirtualQuantity.ToString() + " " + $VMMemory.AllocationUnits)}
				$InformationCollected += @{"Maximum Memory"=($VMMemory.Limit.ToString() + " " + $VMMemory.AllocationUnits)}
				$InformationCollected += @{"Memory Buffer"=($VMMemory.TargetMemoryBuffer)}
				$InformationCollected += @{"Weight"=($VMMemory.Weight)}
			
				# Disabling this rule to minimize the noise
				# Write-GenericMessage -RootCauseID "RC_DynamicMemoryEnabled" -Component "Hyper-V" -Verbosity "Informational" -InformationCollected $InformationCollected -PublicContentURL "http://technet.microsoft.com/en-us/library/ff817651(WS.10).aspx"
				$DynamicMemoryEnabled = $true
				AddXmlAlert -alertType $ALERT_INFORMATION -AlertCategory "Dynamic Memory" -AlertPriority 300 -AlertMessage ("Virtual Machine <b>" + $VirtualMachine.ElementName + "</b> is currently configured to use using Dynamic Memory.") -AlertRecommendation "The following <a href=`"http://technet.microsoft.com/en-us/library/ff817651(WS.10).aspx`">Technet article</a> contains a guide for Dynamic Memory configuration for Hyper-V Guests"
			}
			else
			{
				AddXMLElement -attributeValue "Memory" -value ($VMMemory.VirtualQuantity.ToString() + " " + $VMMemory.AllocationUnits) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Memory`']"
			}

			#***********************************
			# Virtual Machines - Processors     
			#***********************************
		
			$VMProcessor = $VirtualMachine | Get-VMCPUCount

			AddXMLElement -ElementName "SubSection" -attributeValue "Processor" -xpath "/Root/Section[@name=`'$VMGUID`']"
			AddXMLElement -ElementName "SectionTitle" -attributeValue "Processor" -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Processor`']"

			if ($null -ne $VMProcessor.VirtualQuantity) {AddXMLElement -attributeValue "Cores" -value ($VMProcessor.VirtualQuantity.ToString()) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Processor`']"}
			if ($null -ne $VMProcessor.DataWidth) {AddXMLElement -attributeValue "Type" -value ($VMProcessor.DataWidth.ToString() + "-bit") -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Processor`']"}
			if ($null -ne $VMProcessor.LimitProcessorFeatures) {AddXMLElement -attributeValue "Migrate to a physical computer with different processor version" -value $VMProcessor.LimitProcessorFeatures.ToString() -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Processor`']"}
			if ($null -ne $VMProcessor.LimitCPUID) {AddXMLElement -attributeValue "Run an older OS - such as WinNT" -value $VMProcessor.LimitCPUID.ToString() -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Processor`']"}
			if ($null -ne $VMProcessor.Reservation) {AddXMLElement -attributeValue "Virtual Machine Reserve" -value $VMProcessor.Reservation.ToString() -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Processor`']"}
			if ($null -ne $VMProcessor.Limit) {AddXMLElement -attributeValue "Virtual Machine Limit" -value $VMProcessor.Limit.ToString() -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Processor`']"}
			if ($null -ne $VMProcessor.Weight) {AddXMLElement -attributeValue "Relative Weight" -value $VMProcessor.Weight.ToString() -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Processor`']"}
		
			$VMProcessorLoad = $VirtualMachine | Get-VMProcessor
		
			if ($null -ne $VMProcessorLoad.LoadPercentage) {
				AddXMLElement -attributeValue "Current CPU Load" -value ($VMProcessorLoad.LoadPercentage.ToString() + "%") -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Processor`']"
				if ($VMProcessorLoad.LoadPercentage -gt 70) 
				{
					AddXmlAlert -alertType $ALERT_WARNING -AlertCategory "Guest Virtual Machine High CPU usage" -AlertPriority 20 -AlertMessage ("Virtual Machine <b>" + $VirtualMachine.ElementName + "</b> is currently using <font color=`"red`"><b>" + $VMProcessorLoad.LoadPercentage.ToString() + "%</b></font> of CPU.") -AlertRecommendation "You may need to monitor the performance of this virtual machine. The following <a href=`"http://msdn.microsoft.com/en-us/library/cc768535(BTS.10).aspx`">Technet article</a> contains a guide for measuring performance on Hyper-V."
					$VMHighCPUDisplay = $VirtualMachine.ElementName
					if ($null -ne $VMStateSummary.OSName) 
					{
						$VMHighCPUDisplay += " (" + $VMStateSummary.OSName + ")"
					}
					[Array] $HighCPUMachinesArray += $VMHighCPUDisplay
				
					$InformationCollected = @{"Virtual Machine"=$VMHighCPUDisplay}
					$InformationCollected += @{"Current CPU Usage"=($VMProcessorLoad.LoadPercentage.ToString() + "%")}
				
					Write-GenericMessage -RootCauseID "RC_HyperVVMHighCPU" -Verbosity "Warning" -SDPFileReference ($ComputerName + "_HyperV-Info.HTM") -PublicContentURL "http://msdn.microsoft.com/en-us/library/cc768535(BTS.10).aspx" -InformationCollected $InformationCollected  -Visibility 4 -SupportTopicsID 8139 -MessageVersion 2

				}
			}
		
			#***********************************
			# Virtual Machines - Controllers     
			#***********************************

		

			Write-ScriptProgress -status (($VirtualMachine.ElementName) + " - " + $HyperVStrings.ID_HyperVInfoGuestDisk)

			$VMDiskControllers = $VirtualMachine | Get-VMDiskController
		
			foreach ($VMDiskController in $VMDiskControllers) 
			{
		
				$VMControllerName = $VMDiskController.ElementName
		
				AddXMLElement -ElementName "SubSection" -attributeValue $VMControllerName -xpath "/Root/Section[@name=`'$VMGUID`']"
				AddXMLElement -ElementName "SectionTitle" -attributeValue $VMControllerName -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']"
			
				#************************************
				# Virtual Machine Controller - Drives
				#************************************
			
				$VMDiskDrives = $VirtualMachine | Get-VMDisk | Where-Object {$_.ControllerName -eq $VMDiskController.ElementName }
				$512eDriveVHDFilePath = $null
			
				foreach ($VMDiskDrive in $VMDiskDrives) 
				{
					$diskDriveInstanceID = $VMDiskDrive.DiskInstanceID
				
					if ($null -eq $diskDriveInstanceID) {$diskDriveInstanceID = $VMDiskDrive.DriveInstanceID}

					if ($null -ne $VMDiskDrive.DiskPath) 
					{ 
						AddXMLElement -ElementName "SubSection" -attributeValue $diskDriveInstanceID -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']"
						AddXMLElement -ElementName "SectionTitle" -attributeValue $VMDiskDrive.DriveName -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']"
						AddXMLElement -attributeValue "Type" -value $VMDiskDrive.DriveName -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']"
						AddXMLElement -attributeValue "Path" -value ($VMDiskDrive.DiskPath.Replace("&", "&amp;")) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']"
					
						if ($512eDrives.Count -gt 0)
						{
							if ($512eDrives -contains (Split-Path $VMDiskDrive.DiskPath -Qualifier))
							{
								#Error: VHD being stored on 4KB drives. Get the first match.
								if (($null -eq $512eDriveVHDFilePath) -or ($VMDiskDrive.DiskPath.EndsWith("vhd")))
								{
									$512eDriveVHDFilePath = $VMDiskDrive.DiskPath
								}
							}
						}
					
						if ($VMDiskDrive.DiskPath.EndsWith("vhd")) 
						{
							$VHDFiles = $VMDiskDrive.DiskPath | Get-VHDInfo
							foreach ($VHDFile in $VHDFiles) 
							{
								if ($null -ne $VHDFile.Type) {AddXMLElement -attributeValue "Type" -value (Convert-DiskType $VHDFile.Type) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']" }
								if (($VHDFile.Type -eq 3) -or ($VHDFile.Type -eq 4)) {AddXMLElement -attributeValue "Maximum Disk Size" -value (FormatBytes -bytes $VHDFile.MaxInternalSize -precision 2) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']" }
								if ($null -ne $VHDFile.FileSize) {AddXMLElement -attributeValue "Current size" -value (FormatBytes -bytes $VHDFile.FileSize -precision 2) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']" }
								if (($null -ne $VHDFile.ParentPath) -and ($VHDFile.ParentPath.EndsWith(".vhd"))) 
								{
									AddXMLElement -attributeValue "Parent" -value $VHDFile.ParentPath -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']" 
									$ParentVHD = (Get-VHDInfo -vhdPath $VHDFile.ParentPath)[1]
									AddXMLElement -attributeValue "Parent file size" -value (FormatBytes -bytes $ParentVHD.FileSize -precision 2) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']" 
								}
							}
						}
						else 
						{
							if ($VMDiskDrive.DriveName -eq "Settings for the Microsoft Physical Hard Drive.") 
							{
								AddXMLElement -ElementName "SubSection" -attributeValue $diskDriveInstanceID -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']"
								AddXMLElement -ElementName "SectionTitle" -attributeValue "Physical Hard Disk" -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']"
								AddXMLElement -attributeValue "Type" -value "Physical Hard Disk" -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']"
								AddXMLElement -attributeValue "Disk" -value $VMDiskDrive.DiskName -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']"
								#AddXMLElement -attributeValue "Size" -value (FormatBytes -bytes $VMDiskDrive.MaxMediaSize -precision 2) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$VMControllerName`']/SubSection[@name=`'$diskDriveInstanceID`']"
							}
						}
					}
				}
			}
						
			#***********************************
			# Virtual Machines - Network Adapters
			#***********************************

			Write-ScriptProgress -status (($VirtualMachine.ElementName) + " - " + $HyperVStrings.ID_HyperVInfoGuestNetwork)

			$VMNICs = $VirtualMachine | Get-VMNic
		
			foreach ($VMNIC in $VMNICs) 
			{
				$NICInstance = $VMNIC.InstanceID
				AddXMLElement -ElementName "SubSection" -attributeValue $NICInstance -xpath "/Root/Section[@name=`'$VMGUID`']"
				$VMnicSwitch = $VMNIC | Get-VMnicSwitch
				if ($VMnicSwitch -eq "Not Connected") {
					$VMnicSwitchDisplay = $VMnicSwitch
				} else {
					$VMnicSwitchDisplay = $VMnicSwitch.ElementName
				}
				AddXMLElement -ElementName "SectionTitle" -attributeValue ($VMNIC.ElementName + " - " + $VMnicSwitchDisplay) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$NICInstance`']"
	
				AddXMLElement -attributeValue "MAC Address" -value $VMNIC.Address -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$NICInstance`']"
			
				#AddXMLElement -attributeValue "Network" -value ($VMNIC | Get-VMnicSwitch).ElementName -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$NICInstance`']"
			
				$VMPort = $VMNIC | Get-VMNicport
			
				if ($null -ne $VMPort.AllowMacSpoofing) {AddXMLElement -attributeValue "Allow Mac Sproofing" -value $VMPort.AllowMacSpoofing.ToString() -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$NICInstance`']"}
				if ($null -ne $VMPort.ChimneyOffloadLimit) {AddXMLElement -attributeValue "Chimney Offload Limit" -value $VMPort.ChimneyOffloadLimit.ToString() -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$NICInstance`']"}
				if ($null -ne $VMPort.ChimneyOffloadUsage) {AddXMLElement -attributeValue "Chimney Offload Usage" -value $VMPort.ChimneyOffloadUsage.ToString() -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$NICInstance`']"}
				if ($null -ne $VMPort.ChimneyOffloadWeight) {AddXMLElement -attributeValue "Chimney Offload Weight" -value $VMPort.ChimneyOffloadWeight.ToString() -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$NICInstance`']"}
				if ($null -ne $VMPort.VMQOffloadUsage) {AddXMLElement -attributeValue "VMQ Offload Usage" -value $VMPort.VMQOffloadUsage.ToString() -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$NICInstance`']"}
			
			}
	
			#***********************************
			# Virtual Machines - Serial Ports
			#***********************************
		
			$VMSerialPorts = $VirtualMachine | Get-VMSerialPort

			foreach ($VMSerialPort in $VMSerialPorts) 
			{
				$SerialPortName = $VMSerialPort.ElementName
				AddXMLElement -ElementName "SubSection" -attributeValue $SerialPortName -xpath "/Root/Section[@name=`'$VMGUID`']"
				AddXMLElement -ElementName "SectionTitle" -attributeValue ("Serial Port: " + $SerialPortName) -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$SerialPortName`']"
			
				if ($VMSerialPort.Connection.Count -gt 0 ) { 
					if ($VMSerialPort.Connection[0].Lenght -gt 0) {
						AddXMLElement -attributeValue "Attachment" -value $VMSerialPort.Connection[0] -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$SerialPortName`']"
					}
					else 
					{
						AddXMLElement -attributeValue "Attachment" -value "None" -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$SerialPortName`']"
					}
				} 
				else 
				{
					AddXMLElement -attributeValue "Attachment" -value "None" -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'$SerialPortName`']"
				}
			}
	
			#***********************************
			# Virtual Machines - Floppy - Skipped on this version
			#***********************************
		
			# $VMFloppy = $VirtualMachine | Get-VMFloppyDisk
	
			#***********************************
			# Virtual Machines - Snapshots
			#***********************************

			Write-ScriptProgress -status (($VirtualMachine.ElementName) + " - " + $HyperVStrings.ID_HyperVInfoGuestSnapshot)

			$VMSnapshots =  Get-VMSnapshot $VirtualMachine.ElementName
		
			if ($null -ne $VMSnapshots) 
			{
			
				$VMSnapshotDisks = Get-VMDiskSnapthotTree $VirtualMachine.ElementName
			
				AddXMLElement -ElementName "SubSection" -attributeValue "Snapshots" -xpath "/Root/Section[@name=`'$VMGUID`']"
				AddXMLElement -ElementName "SectionTitle" -attributeValue "Virtual Machine Snapshots" -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Snapshots`']"
				AddXMLElement -ElementName "SnapshotObject" -value $VMSnapshotDisks -xpath "/Root/Section[@name=`'$VMGUID`']/SubSection[@name=`'Snapshots`']"
			
				$XMLSnapshots = [xml] ("<Objects>" + $VMSnapshotDisks + "</Objects>") 
			
				$XMLSnapshots.Objects.Object | ForEach-Object -Process {
					if ($512eDrives.Count -gt 0)
					{
						if ($512eDrives -contains (Split-Path $_.DiskPath -Qualifier))
						{
							#Error: VHD being stored on 4KB drives. Get the first match.
							if (($512eDriveVHDFilePath -eq $null) -or ($_.DiskPath.DiskPath.EndsWith("vhd")))
							{
								$512eDriveVHDFilePath = $_.DiskPath.DiskPath
							}
						}
					}
				}
			
			
			}
	
			#Test if a VHD is located in a 512e Drive. If so, generate an alert
			if ($null -ne $512eDriveVHDFilePath)
			{
				$InformationCollectedObject = new-object PSObject
			
				add-member -inputobject $InformationCollectedObject -membertype noteproperty -name "Virtual Machine Name" -value $VirtualMachine.ElementName
				add-member -inputobject $InformationCollectedObject -membertype noteproperty -name "Drive Letter" -value (Split-Path $VMDiskDrive.DiskPath -Qualifier)
				add-member -inputobject $InformationCollectedObject -membertype noteproperty -name "Virtual Hard Disk Path" -value $512eDriveVHDFilePath
				$RC_VHDDetected512eDetected = $true
			
				Write-GenericMessage -RootCauseID "RC_VHDDetected512e" -Component "Hyper-V" -Verbosity "Warning" -InformationCollected $InformationCollectedObject -PublicContentURL "http://support.microsoft.com/kb/2515143" -Visibility 4 -SupportTopicsID 8146 -MessageVersion 2
			}
		}
		


		Write-ScriptProgress -Activity "Hyper-V Information" -status "Generating Report."
		$fileToCollect = GenerateHTMLFile
	
		if ($TroubleshootingModuleLoaded -eq $true) 
		{
			CollectFiles -filesToCollect $fileToCollect -fileDescription "Hyper-V Report" -sectionDescription "Hyper-V Information Report"
			$VM_Summary | ConvertTo-Xml2 | update-diagreport -id "HyperVAVirtualMachines" -name ($Env:COMPUTERNAME + " - Hyper-V Virtual Machines State Summary") -verbosity informational
		
			if ($null -ne $HighCPUMachinesArray) 
			{
				Update-DiagRootCause -Id RC_HyperVVMHighCPU -Detected $true 
			}
			else
			{
				Update-DiagRootCause -Id RC_HyperVVMHighCPU -Detected $false
			}
		
			if ($DynamicMemoryEnabled)
			{
				#Update-DiagRootCause -Id "RC_DynamicMemoryEnabled" -Detected $true
			}
			else
			{
				#
			}
		
			if ($RC_DynamicMemoryOldIntegrationDetected)
			{
				Update-DiagRootCause -Id "RC_DynamicMemoryOldIntegration" -Detected $true
			}
			else
			{
				Update-DiagRootCause -Id "RC_DynamicMemoryOldIntegration" -Detected $false
			}
		
			if ($RC_MismatchedICDetected)
			{
				Update-DiagRootCause -Id "RC_MismatchedIC" -Detected $true
			}
			else
			{
				Update-DiagRootCause -Id "RC_MismatchedIC" -Detected $false
			}
		
			if ($RC_VHDDetected512eDetected)
			{
				Update-DiagRootCause -Id "RC_VHDDetected512e" -Detected $true
			}
			else
			{
				Update-DiagRootCause -Id "RC_VHDDetected512e" -Detected $false
			}
		}
	
		Write-ScriptProgress -Status "Done"
	}
}


# SIG # Begin signature block
# MIInrgYJKoZIhvcNAQcCoIInnzCCJ5sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDXHGt3bXEr63Z/
# i0rQm5LFQTk/AWRpcCWOnIsacsZy66CCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEII/kvhUzTOd477MYkqjjtcym
# x+D8YmfCthNj3kooairWMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAiLl2GzVpxsCLJYH3uIQJ7/Al3wxpR22dhwsp9WryNFqI17W6WYgm1
# A2TuaW6JYaFM7LnKJcdXWvjt7/7PoOjRIL2t+GilFYWwBQEUlZKiHjCQzknK7tR3
# bHCfsfMdOc2nQj7ccB/rvqxbTKmxasY5Q9AB9X+qkMCcEMK5h76OiOIFBQ1dtFzJ
# r/PaXfOZskshIU0c+0tQLZ68ZobfswK06YodyO7yjgL+CUKgqqYdJsWvX0Jo/zYh
# OF8TeRnvv9UMG0BZWEwecyqumgCijFXUafLy6Q36yKBu5/abIMc1BjJFLvm3cVIl
# CMQgsWdUrP4U/HwQPBfNjoIAlMdk+nl7oYIXFjCCFxIGCisGAQQBgjcDAwExghcC
# MIIW/gYJKoZIhvcNAQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIA9VhJOrInLnAyBFutKluxKw/ZceggiIBGtNY6ikLHj9AgZi3ohP
# /UIYEzIwMjIwODAxMDgwMTU1Ljk2NFowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RDA4Mi00QkZELUVFQkExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghFlMIIHFDCCBPygAwIBAgITMwAAAY/zUajrWnLdzAABAAABjzAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MTEwMjgxOTI3NDZaFw0yMzAxMjYxOTI3NDZaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkQwODIt
# NEJGRC1FRUJBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmVc+/rXPFx6Fk4+CpLru
# bDrLTa3QuAHRVXuy+zsxXwkogkT0a+XWuBabwHyqj8RRiZQQvdvbOq5NRExOeHia
# CtkUsQ02ESAe9Cz+loBNtsfCq846u3otWHCJlqkvDrSr7mMBqwcRY7cfhAGfLvlp
# MSojoAnk7Rej+jcJnYxIeN34F3h9JwANY360oGYCIS7pLOosWV+bxug9uiTZYE/X
# clyYNF6XdzZ/zD/4U5pxT4MZQmzBGvDs+8cDdA/stZfj/ry+i0XUYNFPhuqc+UKk
# wm/XNHB+CDsGQl+ZS0GcbUUun4VPThHJm6mRAwL5y8zptWEIocbTeRSTmZnUa2iY
# H2EOBV7eCjx0Sdb6kLc1xdFRckDeQGR4J1yFyybuZsUP8x0dOsEEoLQuOhuKlDLQ
# Eg7D6ZxmZJnS8B03ewk/SpVLqsb66U2qyF4BwDt1uZkjEZ7finIoUgSz4B7fWLYI
# eO2OCYxIE0XvwsVop9PvTXTZtGPzzmHU753GarKyuM6oa/qaTzYvrAfUb7KYhvVQ
# KxGUPkL9+eKiM7G0qenJCFrXzZPwRWoccAR33PhNEuuzzKZFJ4DeaTCLg/8uK0Q4
# QjFRef5n4H+2KQIEibZ7zIeBX3jgsrICbzzSm0QX3SRVmZH//Aqp8YxkwcoI1WCB
# izv84z9eqwRBdQ4HYcNbQMMCAwEAAaOCATYwggEyMB0GA1UdDgQWBBTzBuZ0a65J
# zuKhzoWb25f7NyNxvDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MA0GCSqGSIb3DQEBCwUAA4ICAQDNf9Oo9zyhC5n1jC8iU7NJY39FizjhxZwJbJY/
# Ytwn63plMlTSaBperan566fuRojGJSv3EwZs+RruOU2T/ZRDx4VHesLHtclE8GmM
# M1qTMaZPL8I2FrRmf5Oop4GqcxNdNECBClVZmn0KzFdPMqRa5/0R6CmgqJh0muvI
# mikgHubvohsavPEyyHQa94HD4/LNKd/YIaCKKPz9SA5fAa4phQ4Evz2auY9SUluI
# d5MK9H5cjWVwBxCvYAD+1CW9z7GshJlNjqBvWtKO6J0Aemfg6z28g7qc7G/tCtrl
# H4/y27y+stuwWXNvwdsSd1lvB4M63AuMl9Yp6au/XFknGzJPF6n/uWR6JhQvzh40
# ILgeThLmYhf8z+aDb4r2OBLG1P2B6aCTW2YQkt7TpUnzI0cKGr213CbKtGk/OOIH
# SsDOxasmeGJ+FiUJCiV15wh3aZT/VT/PkL9E4hDBAwGt49G88gSCO0x9jfdDZWdW
# GbELXlSmA3EP4eTYq7RrolY04G8fGtF0pzuZu43A29zaI9lIr5ulKRz8EoQHU6cu
# 0PxUw0B9H8cAkvQxaMumRZ/4fCbqNb4TcPkPcWOI24QYlvpbtT9p31flYElmc5wj
# GplAky/nkJcT0HZENXenxWtPvt4gcoqppeJPA3S/1D57KL3667epIr0yV290E2ot
# ZbAW8DCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcN
# AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAw
# BgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEw
# MB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk
# 4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9c
# T8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWG
# UNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6Gnsz
# rYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2
# LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLV
# wIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTd
# EonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0
# gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFph
# AXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJ
# YfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXb
# GjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJ
# KwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnP
# EP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMw
# UQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggr
# BgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoY
# xDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
# L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYB
# BQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U5
# 18JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgAD
# sAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo
# 32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZ
# iefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZK
# PmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RI
# LLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgk
# ujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9
# af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzba
# ukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/
# OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIIC
# PQIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RDA4Mi00QkZELUVFQkExJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMC
# GgMVAD5NL4IEdudIBwdGoCaV0WBbQZpqoIGDMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDmkZg6MCIYDzIwMjIwODAx
# MDgwOTMwWhgPMjAyMjA4MDIwODA5MzBaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIF
# AOaRmDoCAQAwBwIBAAICEbAwBwIBAAICEXEwCgIFAOaS6boCAQAwNgYKKwYBBAGE
# WQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDAN
# BgkqhkiG9w0BAQUFAAOBgQAhp8Aod4IrqWSzJRIvhdfsjjJ0NJWgA/ZOXoGxuTHB
# Nc+n4eD9raE8WV172xcQru+BQW4ecbLSElX8gQ88qDD0qPr3S/FY/5drB43kpsZb
# 3smIRpvR0AhUrfQV/szgrx7+5TBOZSinvdOPsft4KHAzsWahf7BfumsXJdtpt6+W
# nzGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABj/NRqOtact3MAAEAAAGPMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0B
# CQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIC+yfvwvhx5d4V3eA1Yz
# RltvhQm31Fz6BvqK+xUgHrcoMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQg
# l3IFT+LGxguVjiKm22ItmO6dFDWW8nShu6O6g8yFxx8wgZgwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAY/zUajrWnLdzAABAAABjzAiBCDK
# yRgnJWWXshnmgygiJTZnJFpENKNV36rl3eKKIz0TKjANBgkqhkiG9w0BAQsFAASC
# AgB2evzAG4cTbbuihSbULXcE3oPWVWAIoy5CGayKZg4sRV9e0/vhn3NpIXo2S7fH
# zFNn6V7HCx12rUBiHTqhMY4YbUEMpQZZAd25Zop/MmBHgqdf494d5VigUajDlT4Y
# dU54LBFNUKcWddyuDLR+nzeGH6a23UrifQTQaZ70WZpgqFa6kg9mzJcIrHjgWd+I
# fTUR0AXBbvR/3sjj/ir606kB1F1OBWFSeFNPbkckL46ytEZAu/MFP5BMHHgBAPvq
# j4ovbqumat45QlUtYjWZ3KCGdOGPqjwvIEIw7Hz3GKrSTcDr6OJdhnFhl2lMnOrV
# BmSGAy8cqfvebfk/VWaOkzuE6zczhmYAL1YsGLR/VOU4dFBObbmIKhpJPXys0Y/M
# rmG4rbZfQx81LHN7TdS0O333sc4y2faqjTuTlYz9ywxQKiBquaRooLJ8FInvA8D4
# RuILv5LaHKfVHiUhHS1BlhgHWgy6/G/3xQyg9JAf2UNkWM/ijF41cCSrCYHLrMVl
# qXH7fF8xejoVPmBTGSFAcD5/uvJoieBKZWVR0wy7ViQSfJYUuRHBei/HBIQ/J7J5
# dDDQ6M7+pt5K0InVpP0/ceD6s4ph2waaDNpqEwUKOETvOG2TiDwKem7oe8gl5pSX
# mZ6azHsmChI6ddSWVU/UUgJstbdKoWSgrnaOdai1p0pKUA==
# SIG # End signature block
