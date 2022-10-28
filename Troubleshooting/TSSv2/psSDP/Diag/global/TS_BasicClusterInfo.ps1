#************************************************
# DC_BasicClusterInfo.ps1
# Version 2.0.3
# Date: 03-28-2010
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script writes to the report basic information regarding 
#              the cluster (Cluster Info, Nodes and Groups)
#************************************************


#Troubleshooter:

PARAM([switch] $IncludeCoreGroups)

# 2019-03-17 WalterE added Trap #_#
Trap [Exception]
	{
	 # Handle exception and throw it to the stdout log file. Then continue with function and script.
		 $Script:ExceptionMessage = $_
		 "[info]: Exception occurred."  | WriteTo-StdOut
		 "[info]: Exception.Message $ExceptionMessage."  | WriteTo-StdOut 
		 $Error.Clear()
		 continue
	}
	
$ClusterSvcKey = "HKLM:\SYSTEM\CurrentControlSet\services\ClusSvc"

if (Test-Path $ClusterSvcKey)
{
	Import-LocalizedData -BindingVariable ClusterBasicInfo 
	Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status $ClusterBasicInfo.ID_ClusterInfoObtaining

	$StartupType = (get-itemproperty -Path $ClusterSvcKey -Name "Start").Start
	if (($StartupType -eq 2) -or ($StartupType -eq 3)) 
	{  # Auto or Manual
		if ($StartupType -eq 2) {$StartupTypeDisplay = "Auto"}
		if ($StartupType -eq 3) {$StartupTypeDisplay = "Manual"}
		$ClusterSvc = Get-Service -Name ClusSvc
		if ($ClusterSvc.Status.Value__ -ne 4) 
		{ #Cluster Service is not running
			Update-DiagRootCause -id "RC_ClusterSvcDown" -Detected $true 
			$InformationCollected = @{"Service State"=$ClusterSvc.Status; "Startup Type"=$StartupTypeDisplay}
			Write-GenericMessage -RootCauseID "RC_ClusterSvcDown" -Component "FailoverCluster" -InformationCollected $InformationCollected -Verbosity "Error" -PublicContentURL "http://blogs.technet.com/b/askcore/archive/2010/06/08/windows-server-2008-and-2008r2-failover-cluster-startup-switches.aspx" -SupportTopicsID 8001 -MessageVersion 2 -Visibility 4
		}
		else 
		{
			Update-DiagRootCause -Id "RC_ClusterSvcDown" -Detected $false
			$ClusterKey="HKLM:\Cluster"
			
			#   Win2K8 R2
			if ((Test-Path $ClusterKey) -and ($OSVersion.Build -gt 7600))
			{
				Import-Module FailoverClusters
				
				$Cluster = Get-Cluster
				
				$Cluster_Summary = new-object PSObject
				
				add-member -inputobject $Cluster_Summary -membertype noteproperty -name $ClusterBasicInfo.ID_ClusterName -value $cluster.Name
				add-member -inputobject $Cluster_Summary -membertype noteproperty -name $ClusterBasicInfo.ID_ClusterDomain -value $cluster.Domain
				add-member -inputobject $Cluster_Summary -membertype noteproperty -name $ClusterBasicInfo.ID_ClusterCSV -value $cluster.EnableSharedVolumes
				
				if ($cluster.EnableSharedVolumes -eq "Enabled") 
				{
					add-member -inputobject $Cluster_Summary -membertype noteproperty -name $ClusterBasicInfo.ID_ClusterCSVRoot -value $cluster.SharedVolumesRoot
				}
				
				$Cluster_Summary | convertto-xml | update-diagreport -id 02_ClusterSummary -name $ClusterBasicInfo.ID_ClusterInfo -verbosity informational

				$ClusterQuorum_Summary = new-object PSObject
				$ClusterQuorum = Get-ClusterQuorum

				add-member -inputobject $ClusterQuorum_Summary -membertype noteproperty -name "Quorum Type" -value $ClusterQuorum.QuorumType
				if ($null -ne $ClusterQuorum.QuorumResource) 
				{
					add-member -inputobject $ClusterQuorum_Summary -membertype noteproperty -name "Quorum Resource" -value $ClusterQuorum.QuorumResource.Name
					
						switch ($ClusterQuorum.QuorumResource.State.value__) {
							2 {$Color = "Green"} #ClusterResourceOnline 
							3 {$Color = "Black"} #ClusterResourceOffline
							4 {$Color = "Red"}   #ClusterResourceFailed
							default { $Color = "Orange" } #Other state
						}

						$State = "<font face=`"Webdings`" color=`"$Color`">n</font> " + $ClusterQuorum.QuorumResource.State
						$ResourceStateDisplay = $State + " - Owner: " + $ClusterQuorum.QuorumResource.OwnerNode
						
						add-member -inputobject $ClusterQuorum_Summary -membertype noteproperty -name "State" -value $ResourceStateDisplay
				}

				$ClusterQuorum_Summary | convertto-xml2 | update-diagreport -id 03_ClusterQuorumSummary -name "Quorum Information" -verbosity informational
				
				$ClusterNodes_Summary = new-object PSObject
				$ClusterNodesNotUp_Summary = new-object PSObject
				
				Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status "Cluster Nodes"
				
				$Error.Clear()
				
				$ClusterNodes = Get-ClusterNode -ErrorAction SilentlyContinue #_# -EA added 2020-08-20
				
				if ($Error.Count -ne 0) 
				{
					$errorMessage = $Error[0].Exception.Message
					$errorCode = "0x{0:X}" -f $Error[0].Exception.ErrorCode
					$ServiceState = $ClusterSvc.Status
					Update-DiagRootCause -id "RC_ClusterInfoErr" -Detected 
					$InformationCollected = @{"Error Message"=$errorMessage; "Error Code"=$errorCode; "Service State" = $ServiceState}
					Write-GenericMessage -RootCauseID "RC_ClusterInfoErr" -InformationCollected $InformationCollected -Verbosity "Warning" -Component "FailoverCluster"  -SupportTopicsID 8001 -MessageVersion 2 -Visibility 3
				}
				
				if ($Null -ne $ClusterNodes) 
				{
					$ReportNodeNotUpNames=""
					foreach ($ClusterNode in $ClusterNodes) 
					{
						switch ($ClusterNode.State.value__) 
						{
							0 {$Color = "Green"} # Up
							1 {$Color = "Red"}   #Down
							default { $Color = "Orange" } 
						}

						$State = "<font face=`"Webdings`" color=`"$Color`">n</font> " + $ClusterNode.State
						$NodeName = $ClusterNode.NodeName
						if ($NodeName -eq "$ComputerName") {$NodeName += "*"}
						add-member -inputobject $ClusterNodes_Summary -membertype noteproperty -name $NodeName -value $State
						if ($ClusterNode.State.value__ -ne 0 ) 
						{ 
							if ($ReportNodeNotUpNames -ne "") 
							{
								$ReportNodeNotUpNames += ", "
							}
							$ReportNodeNotUpNames += $ClusterNode.NodeName + "/ " + $ClusterNode.State
							add-member -inputobject $ClusterNodesNotUp_Summary -membertype noteproperty -name $NodeName -value ($ClusterNode.State)
						}
					}
		
					if ($ReportNodeNotUpNames -ne "") 
					{
						$XMLFile = "..\ClusterNodesDown.XML"
						#$XMLObj = $ClusterNodesNotUp_Summary | ConvertTo-Xml2 
						#$XMLObj.Save($XMLFile)
						Update-DiagRootCause -id "RC_ClusterNodeDown" -Detected $true #-Parameter @{"NotUpNodesXML"=$XMLFile}
						#$InformationCollected = @{"Cluster Node(s)/ State"= $ReportNodeNotUpNames}
						Write-GenericMessage -RootCauseID "RC_ClusterNodeDown" -InformationCollected $ClusterNodesNotUp_Summary -SupportTopicsID 8001 -MessageVersion 2 -Visibility 3
					}
					else
					{
						Update-DiagRootCause -Id "RC_ClusterNodeDown" -Detected $false
					}
					
					$ClusterNodes_Summary | ConvertTo-Xml2 | update-diagreport -id 04_ClusterNodes -name "Cluster Nodes" -verbosity informational
					
					Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status "Cluster Groups"
					
					$ClusterGroups_Summary = new-object PSObject
					$ClusterGroupNotOnline_Summary = new-object PSObject
					
					if ($IncludeCoreGroups.IsPresent) {
						$ClusterGroups = Get-ClusterGroup
					} else {
						$ClusterGroups = Get-ClusterGroup | Where-Object {$_.IsCoreGroup -eq $false}
					}
					
					if ($null -ne $ClusterGroups)
					{
						$GroupNamesNotOnline = ""
						foreach ($ClusterGroup in $ClusterGroups) {
							switch ($ClusterGroup.State.value__) {
								0 {$Color = "Green"} #Online
								1 {$Color = "Black"}   #ClusterGroupOffline
								2 {$Color = "Red"} #ClusterGroupFailed
								3 {$Color = "Orange"} #ClusterGroupPartialOnline
								4 {$Color = "Yellow"} #ClusterGroupPending
								default { $Color = "Orange" } #Pending
							}

							$State = "<font face=`"Webdings`" color=`"$Color`">n</font> " + $ClusterGroup.State
							$GroupStateDisplay = $State + " - Owner: " + $ClusterGroup.OwnerNode
							if (($IncludeCoreGroups.IsPresent) -and ($ClusterGroup.IsCoreGroup)) {
								$ClusterGroupDisplay = $ClusterGroup.Name + " (Core Group)"
							} else {
								$ClusterGroupDisplay = $ClusterGroup.Name
							}
							add-member -inputobject $ClusterGroups_Summary -membertype noteproperty -name $ClusterGroupDisplay -value $GroupStateDisplay
							
							if (($ClusterGroup.State.value__ -eq 1) -or ($ClusterGroup.State.value__ -eq 2)) 
							{ 
								if ($GroupNamesNotOnline -ne "") 
								{
									$GroupNamesNotOnline += ", "
								}
								$GroupNamesNotOnline += $ClusterGroup.Name + "/ " + $ClusterGroup.State
								add-member -inputobject $ClusterGroupNotOnline_Summary -membertype noteproperty -name $ClusterGroup.Name -value $GroupStateDisplay 
							}
						}

						if ($GroupNamesNotOnline -ne "") 
						{
							$XMLFileName = "..\ClusterGroupsProblem.XML"
							#$XMLObj = $ClusterGroupNotOnline_Summary | ConvertTo-Xml2 
							#$XMLObj.Save($XMLFileName)
							Update-DiagRootCause -id "RC_ClusterGroupDown" -Detected $true #-Parameter @{"XMLFilename"=$XMLFileName}
							$InformationCollected = @{"Cluster Group(s)" = $ClusterGroupNotOnline_Summary}
							Write-GenericMessage -RootCauseID "RC_ClusterGroupDown" -InformationCollected $InformationCollected -Verbosity "Warning" -Component "FailoverCluster" -PublicContentURL "http://technet.microsoft.com/en-us/library/cc757139(WS.10).aspx"
						}
						else
						{
							Update-DiagRootCause -id "RC_ClusterGroupDown" -Detected $false
						}

						$ClusterGroups_Summary | ConvertTo-Xml2 | update-diagreport -id 05_ClusterGroup -name "Cluster Groups" -verbosity informational
						
						if ($clusterGroups.Length -le 50)
						{
							foreach ($ClusterGroup in $ClusterGroups) {
								$ClusterGroup_Summary = new-object PSObject
								$GroupName = $ClusterGroup.Name
								Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status "Cluster Group $GroupName - Querying resources"
								foreach ($ClusterResourceType in get-clusterResource | Where-Object {$_.OwnerGroup.Name -eq $ClusterGroup.Name} | Select-Object ResourceType -Unique) {
									$ResourceTypeDisplayName = $ClusterResourceType.ResourceType.DisplayName
									Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status "Cluster Group $GroupName - Querying $ResourceTypeDisplayName resources"
									$ResourceLine = ""
									foreach ($ClusterResource in get-clusterResource | Where-Object {($_.ResourceType.Name -eq $ClusterResourceType.ResourceType.Name) -and ($_.OwnerGroup.Name -eq $ClusterGroup.Name)}){
										switch ($ClusterResource.State.value__) {
											2 {$Color = "Green"} #Online
											3 {$Color = "Black"} #Offline
											4 {$Color = "Red"}   #ClusterResourceFailed
											default { $Color = "Orange" } #Pending or other state
										}
										$State = "<font face=`"Webdings`" color=`"$Color`">n</font> " + $ClusterResource.State
										if ($ResourceLine -ne "") { $ResourceLine += "<br/>" }
										$ResourceLine += $State + " - " + $ClusterResource.Name
									}			
									add-member -inputobject $ClusterGroup_Summary -membertype noteproperty -name $ResourceTypeDisplayName -value $ResourceLine
								}
								$strID = "05a_" + $GroupName + "_ClusterGroup"
								$ClusterGroup_Summary | ConvertTo-Xml2 | update-diagreport -id $strID -name "Cluster Group $GroupName" -verbosity informational
							}	
						}
						else
						{
							$ClusterGroup_Summary = new-object PSObject
							$ClusterGroup_Summary | ConvertTo-Xml2 | update-diagreport -id "05a" -name "A large number of cluster groups were detected on this system.  Detailed cluster group information is not available in Resultreport.xml" -verbosity informational
						}
						Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status $ClusterBasicInfo.ID_ClusterInfoObtaining
						
						
						
					}
				}
				
				
				$ClusterNetWorks = get-clusternetwork
				if($null -ne $ClusterNetWorks)
				{
					foreach($Psnetwork in $ClusterNetWorks)
					{
					    $PSClusterNetWork = New-Object PSObject
						$AutoMetric = ""
						$RoleDescription = ""
						$IPv6Addresses = ""
						$State = ""
						$Ipv4Addresses = ""
						if($Psnetwork.IPv6Addresses.Count -eq 0)
						{
							$IPv6Addresses = "None/0"
						}
						else
						{
							for($c =0 ;$c -lt $Psnetwork.IPv6Addresses.Count; $c++ )
							{
	
								if($c -eq $Psnetwork.IPv6Addresses.Count-1)
								{
									$IPv6Addresses += $Psnetwork.IPv6Addresses[$c] + " / " + $Psnetwork.Ipv6PrefixLengths[$c]
								}
								else
								{
									$IPv6Addresses += $Psnetwork.IPv6Addresses[$c] + " / " + $Psnetwork.Ipv6PrefixLengths[$c] +"<br/>"
								}
							}
						}
						
						if($Psnetwork.Ipv4Addresses.Count -eq 0)
						{
							$Ipv4Addresses = "None / None"
						}
						else
						{
							for($i =0 ;$i -lt $Psnetwork.Ipv4Addresses.Count; $i++ )
							{
	
								if($i -eq $Psnetwork.Ipv4Addresses.Count-1)
								{
									$Ipv4Addresses += $Psnetwork.Ipv4Addresses[$i] + " / " +$Psnetwork.AddressMask[$i]
								}
								else
								{
									$Ipv4Addresses += $Psnetwork.Ipv4Addresses[$i] + " / " +$Psnetwork.AddressMask[$i] +"<br/>"
								}
							}
						}
						
						if($Psnetwork.AutoMetric)
						{
							$AutoMetric = " [AutoMetric]"
						}
						switch ($Psnetwork.Role) 
						{
								0 {$RoleDescription = " (Do not allow cluster network communications on this network)"}
								1 {$RoleDescription = " (Allow cluster network communications on this network"}
								3 {$RoleDescription = " (Allow clients to connect through this network)"}
						   default{$RoleDescription = ' (Unknown)' }
						}

						$color = $null
						switch ($Psnetwork.State.value__) {
										1 {$Color = "Black"} #down
										2 {$Color = "Red"} #partitioned 
										3 {$Color = "Green"} #up
										default { $Color = "Orange" } #unavailable  or unknow
									}
						$State = "<font face=`"Webdings`" color=`"$Color`">n</font> " + $Psnetwork.State
						Add-member -InputObject $PSClusterNetWork -Membertype Noteproperty -Name "State" -Value $State
						Add-member -InputObject $PSClusterNetWork -Membertype Noteproperty -Name "IPv6 Addresses" -Value $IPv6Addresses
						Add-member -InputObject $PSClusterNetWork -Membertype Noteproperty -Name "IPv4 Addresses" -Value $Ipv4Addresses
						Add-member -InputObject $PSClusterNetWork -Membertype Noteproperty -Name "Metric" -Value ($Psnetwork.Metric.ToString() + $AutoMetric)
						Add-member -InputObject $PSClusterNetWork -Membertype Noteproperty -Name "Role" -Value ($Psnetwork.Role.ToString() + $RoleDescription)
	
						$PsClusterNetworkInfo = Convert-PSObjectToHTMLTable -PSObject $PSClusterNetWork
						$ClusterNetWorkInfoSection = New-Object PSObject
						Add-member -InputObject $ClusterNetWorkInfoSection -Membertype Noteproperty -Name $Psnetwork.Name -Value $PsClusterNetworkInfo
						$ClusterNetWorkName = $Psnetwork.Name
						$ClusterNetWorkCluster = $Psnetwork.Cluster
						$SectionName = "Cluster Networks - $ClusterNetWorkCluster"
						$ClusterNetWorkInfoSection | ConvertTo-Xml2 | update-diagreport -id  "06_$ClusterNetWorkName" -name $SectionName -verbosity informational -Description "Cluster Networks"
						Write-DiagProgress -activity $ClusterBasicInfo.ID_ClusterInfo -status "Cluster Network Information"
					}
				}

			}
			
			#   Win2K8 & 2003
			if ((Test-Path "HKLM:\Cluster") -and ($OSVersion.Build -lt 7600))
			{
				
				$CommandToRun = "`"" + $pwd.Path  + "\clusmps.exe`" /S /G /P:`"" + $pwd.Path + "`""
				$FileTocollect = $pwd.Path  + "\" + $Computername + "_cluster_mps_information.txt"
				$fileDescription = "Cluster Information"
				
				$Null = Runcmd -commandToRun $CommandToRun -fileDescription $fileDescription -sectionDescription "Cluster Basic Information" -filesToCollect $FileTocollect -useSystemDiagnosticsObject
				
			}
			
		}
	}
}

Trap{WriteTo-StdOut "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $_" -shortformat;Continue}

# SIG # Begin signature block
# MIInoQYJKoZIhvcNAQcCoIInkjCCJ44CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDJ41dEGZrDksAH
# 8itWkOlGvAiic50ff1b5eZ7rcZ021KCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYEwghl9AgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIODhgC0dFkahsaVgFjP+0nHN
# W2ArMC4EUBOQImBqUETpMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAaIT/InrRRY0yF3CQKbMFi+ugrJOBuTliEGz5hVNBFmbIf47HJF7PI
# ChGRRci3d0AX95p64tQcEvVlt3KAwTZ16rmF+PS5A+BxTdMhsZmIJaBZ24RsQCDb
# tf+U1rVmJ2gZixdmNgKzaFcQk+50IM56hJ2lDw5CA+PZntfcj2IQtb4j7mYjeTo4
# 6CscJJcfdwab4muBzUPJDk/T+vYk5TbANzgWQKKf6rfKtPKljojKvo2gnUSUs7qs
# R4/e+9qaMFQ5+CZ2fW1lqfZtmcjnyDnPsfXGlCZ5kTQ9EVovw2Bgbvh1B6oKKc46
# BfIcLDi81GFb6kVcdkTLF4y7z8t54c1ioYIXCTCCFwUGCisGAQQBgjcDAwExghb1
# MIIW8QYJKoZIhvcNAQcCoIIW4jCCFt4CAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIBSX76nxou95wa2ZnXADs7B6u5ICYFE/Zc8mEtA3NJkGAgZi2xAP
# WWIYEzIwMjIwODAxMDc1NjAzLjk0NFowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4
# OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEVwwggcQMIIE+KADAgECAhMzAAABqwkJ76tj1OipAAEAAAGrMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTEyOFoXDTIzMDUxMTE4NTEyOFowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcw
# MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMmdS1o5dehASUsscLqyx2wm/WirNUfq
# kGBymDItYzEnoKtkhrd7wNsJs4g+BuM3uBX81WnO270lkrC0e1mmDqQt420Tmb8l
# wsjQKM6mEaNQIfXDronrVN3aw1lx9bAf7VZEA3kHFql6YAO3kjQ6PftA4iVHX3JV
# v98ntjkbtqzKeJMaNWd8dBaAD3RCliMoajTDGbyYNKTvxBhWILyJ8WYdJ/NBDpqP
# zQl+pxm6ZZVSeBQAIOubZjU0vfpECxHC5vI1ErrqapG+0oBhhON+gllVklPAWZv2
# iv0mgjCTj7YNKX7yL2x2TvrvHVq5GPNa5fNbpy39t5cviiYqMf1RZVZccdr+2vAp
# k5ib5a4O8SiAgPSUwYGoOwbZG1onHij0ATPLkgKUfgaPzFfd5JZSbRl2Xg347/Lj
# WQLR+KjAyACFb06bqWzvHtQJTND8Y0j5Y2SBnSCqV2zNHSVts4+aUfkUhsKS+GAX
# S3j5XUgYA7SMNog76Nnss5l01nEX7sHDdYykYhzuQKFrT70XVTZeX25tSBfy3Vac
# zYd1JSI/9wOGqbFU52NyrlsA1qimxOhsuds7Pxo+jO3RjV/kC+AEOoVaXDdminsc
# 3PtlBCVh/sgYno9AUymblSRmee1gwlnlZJ0uiHKI9q2HFgZWM10yPG5gVt0prXnJ
# Fi1Wxmmg+BH/AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUFFvO8o1eNcSCIQZMvqGf
# dNL+pqowHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEAykuUgTc1KMszMgsHbhgjgEGv/dCHFf0by99C45SR770/udCN
# NeqlT610Ehz13xGFU6Hci+TLUPUnhvUnSuz7xkiWRru5RjZZmSonEVv8npa3z1Qv
# eUfngtyi0Jd6qlSykoEVJ6tDuR1Kw9xU9yvthZWhQs/ymyOwh+mxt0C9wbeLJ92e
# r2vc9ly12pFxbCNDJ+mQ7v520hAvreWqZ02GOJhw0R4c1iP39iNBzHOoz+DsO0sY
# jwhaz9HrvYMEzOD1MJdLPWfUFsZ//iTd3jzEykk02WjnZNzIe2ENfmQ/KblGXHeS
# e8JYqimTFxl5keMfLUELjAh0mhQ1vLCJZ20BwC4O57Eg7yO/YuBno+4RrV0CD2gp
# 4BO10KFW2SQ/MhvRWK7HbgS6Bzt70rkIeSUto7pRkHMqrnhubITcXddky6GtZsmw
# M3hvqXuStMeU1W5NN3HA8ypjPLd/bomfGx96Huw8OrftcQvk7thdNu4JhAyKUXUP
# 7dKMCJfrOdplg0j1tE0aiE+pDTSQVmPzGezCL42slyPJVXpu4xxE0hpACr2ua0LH
# v/LB6RV5C4CO4Ms/pfal//F3O+hJZe5ixevzKNkXXbxPOa1R+SIrW/rHZM6RIDLT
# JxTGFDM1hQDyafGu9S/a7umkvilgBHNxZfk0IYE7RRWJcG7oiY+FGdx1cs0wggdx
# MIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGI
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylN
# aWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5
# MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
# eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa
# 4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxR
# MTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEByd
# Uv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi9
# 47SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJi
# ss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+
# /NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY
# 7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtco
# dgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH
# 29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94
# q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
# AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0G
# A1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQB
# gjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# GQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB
# /wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0f
# BE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJv
# ZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4w
# TDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIB
# AJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
# fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6
# Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveV
# tihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKB
# GUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoy
# GtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQE
# cb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFU
# a2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+
# k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0
# +CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cir
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzzCCAjgCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo4OTdBLUUzNTYtMTcwMTElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAW6h6/24WCo7W
# Zz6CEVAeLztcmD6ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOaRa9gwIhgPMjAyMjA4MDEwMTAwMDhaGA8yMDIy
# MDgwMjAxMDAwOFowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pFr2AIBADAHAgEA
# AgIG1DAHAgEAAgIRNzAKAgUA5pK9WAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgor
# BgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUA
# A4GBAAEU+pL+fVXcuqgydyRS2xu0KXbaAiTD3MltCnjkn3ekNvFgcP+4OrTJe4DA
# punTRCb4bvJrYifK/egPCUPI67+Obaj9M50cuVtH9NzEUFs8QheQObEU6tG04X/B
# v0cqzEG3yZKdp0O0h1k6MMtIrIccKN3JPMbdFmEHAeb7w1TAMYIEDTCCBAkCAQEw
# gZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGrCQnvq2PU6KkA
# AQAAAaswDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0B
# CRABBDAvBgkqhkiG9w0BCQQxIgQg6+nChPa68CpPicADTHmThs24AIk0WP3g+FGv
# bSLWVxgwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAOHK/6sIVgEVSVD3Ar
# vk6OyQKvRxFHKyraUzbN1/AKVzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwAhMzAAABqwkJ76tj1OipAAEAAAGrMCIEIHI+RQKHTZ2Id7/ufvKq
# /DQk+dqQy1YkmvsPNzOkpL0iMA0GCSqGSIb3DQEBCwUABIICADVTB77DWUtHbC0B
# e9sKZQ4RGFCWF/Ya2HLa7n5Pv8hXdYgSLFFG2taMTJp7Y7TJ+PqyxOKp3DETmOfe
# x/jy8Se9UCx1HlySE9/uWFKp9wDbCSgzxabHUmCy6Y6DiYMKd9DPdFOnb2Ji35Nk
# aLw1zR4lGyYVF7UP7T1gzpj4GqDs/5te0yaRSN3aDzpfbgMvESe964M5yc6kjVcw
# WYxxM+QcAghokstTbx3xVnVJGv85MZ77NtkN58O7oF1KVm9PgxmXOEsMkMbpaQzv
# hUyNKuM+ao1BDoD7iTrzcoSh7Nd0CU+FMe0J1BiWcHHV8m8w+Xxh2oGHN2/pDH23
# f1UUkjWJ9IzN6W4RDJSTJAVcNUC806jvS6YxHDPVx+/GPioY7xqnCRoocYJaR9Kz
# D/538jMQOlwDbRmUhptiA0F2SrL5pfEv8gyk+5MLP4827Zz5mUNskgi+9JKvRUL1
# 5gr1b6oqf0bQS/e7wZZpEAxSXCG8IfUVdjL6hZLIML6zZ4aWIEIihj/+Egql2FzH
# p77K40oOmhqTezxPEfMRx6/8RCKwFkYi3XvZOKKQmJI04QZjGqPNA6oYIq0A9kUR
# KZtOFVz+nQa1Cc3LMgQK69aNvKv9QSVr/Qm1IBfEnKVdhTgFJP7ncHetfUNQwgty
# n2g1MFCh8rBqVqt0xeAvto74y+kr
# SIG # End signature block
