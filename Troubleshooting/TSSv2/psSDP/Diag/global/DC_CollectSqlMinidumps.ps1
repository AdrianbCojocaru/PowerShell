
# This script has dependencies on utils_CTS and utils_DSD
#
param ( [Object[]] $instances ) 

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

$LOGvars= Get-Variable LOG*
if (!($LOGvars.name -contains "LOGFILE_PATH")) {
	New-Variable LOGFILE_PATH      -Scope "Global" #_# only set new var if LOGFILE_PATH does not exits
}

#
# Function : WriteTo-LogFile
# ---------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
# 			This function should is used to log progress and error messages to the ErrorloLogCollectorResults.log 
#			file and the test harness executes
# 
# Arguments:
#			String to write to file
# 
# Owner:
#			DanSha 
#
function WriteTo-LogFile($StringToWrite)
{
	$Error.Clear()           
    trap 
    {
    	"[WriteTo-LogFile] : [ERROR] Trapped exception ..." | WriteTo-StdOut
    	Report-Error 
	}

	"[{0:yyyy-MM-dd HH:mm:ss.fff}] : {1}" -f (Get-Date), $StringToWrite |  Out-File -FilePath $global:LOGFILE_PATH -Append
}

#
# Function : Write-DumpInventory
# ------------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function from your PowerShell scripts.  
#
# Description:
#		    Writes an inventory of all dump files found for target instance
# 
# Arguments:
#			String to write to file
# 
# Owner:
#			DanSha 
#   
function Write-DumpInventory([string]$InstanceName, [string]$DumpDir)
{
    $Error.Clear()           
    trap 
    {
    	"[Write-DumpInventory] : [EROR] Trapped exception ..." | WriteTo-StdOut
    	Report-Error
    }
   
    if ($null -ne $InstanceName)
    {
        if ($null -ne $DumpDir)
        {
            # This collector can be configured to collect a subset of the minidumps on a given machine.  
            # As such, for debugging purposes the collector writes a dump inventory that's collected with the dump files  
            $DumpInventoryFile = "{0}_{1}_DumpInventory.log" -f $env:ComputerName, $InstanceName
            New-Item -ItemType file -Name $DumpInventoryFile -Path $PWD.Path -Force | Out-Null
            $global:LOGFILE_PATH = Join-Path -Path $PWD.Path -ChildPath $DumpInventoryFile 
            
            # Is path passed to function in $DumpDir valid?
            if ($true -eq (Test-Path -Path $DumpDir -PathType "Container"))
            {
                # Collect (up to) 10 most recent minidump files for this instance
                $Dumpfiles = get-childitem -Path (Join-Path $Dumpdir "*") -Include "*.mdmp" | sort-object -Property Length -Descending
                
                if ($true -eq (Test-Path -Path $global:LOGFILE_PATH -PathType "Leaf"))
                {
                    WriteTo-LogFile ("Dump inventory for instance: {0}" -f $InstanceName)
                    WriteTo-LogFile ("Dump directory: {0}" -f $DumpDir)
                    
                    if ($null -ne $Dumpfiles) 
                    {
                        if (0 -lt $Dumpfiles.Count) 
                        {
                            WriteTo-LogFile ("Total number of dumps discovered is: {0}" -f $Dumpfiles.Count)
                            
                            foreach($DumpFile in $Dumpfiles)
                            {
                                WriteTo-LogFile ("{0} Creation Time: {1} Size: {2}" -f $DumpFile.Name, $DumpFile.CreationTime, $DumpFile.Length)
                            }
                        }
                    }
                    else
                    {
                        WriteTo-LogFile "No minidumps found ..." 
                    }
            		# Now collect the file so that it will be included in CAB that's uploaded
                	CollectFiles -FilesToCollect $global:LOGFILE_PATH -SectionDescription ("SQL Server minidumps and related files for instance {0}" -f $InstanceName)
                }
            }
            else
            {
                "[Write-DumpInventory] : [ERROR] Invalid path [{0}] passed by caller" -f $DumpDir | WriteTo-StdOut        
            }
            
        } # if ($null -eq $DumpDir)
        else
        {
             '[Write-DumpInventory] : [ERROR] Required parameter -DumpDir was not specified' | WriteTo-StdOut        
        }
        
    } # if ($null -eq $InstanceName)
    else
    {
        '[Write-DumpInventory] : [ERROR] Required parameter -InstanceName was not specified' | WriteTo-StdOut        
    }
}


# This function works with and returns the dump directory as a string so not susceptible to issues caused by
# cluster drive being offline to the node the collector is run against
function Get-DumpDirectory ([string] $SqlInstance)
{
    $Error.Clear()           
	trap 
	{
		"[Get-DumpDirectory] : [ERROR] Trapped exception ..." | WriteTo-Stdout
		Report-Error
	}
    
    if ($null -ne $SqlInstance)
    {
    	$InstanceKey = Get-SqlInstanceRootKey -SqlInstanceName $SqlInstance
        
        if ($null -ne $InstanceKey)
        {
        								
        	if ($true -eq (Test-Path -Path (Join-Path -Path $InstanceKey -ChildPath '\CPE')))
        	{				
        		$CpeRegKey = Join-Path -Path $InstanceKey -ChildPath '\CPE'
        		
                # Test to be sure CpeRegKey is valid
                if ($true -eq (Test-Path -Path $CpeRegKey))
                {
                    # Get the MSSQLServer\Parameters Key
            		$SqlDumpDir = (Get-ItemProperty -Path $CpeRegKey ).ErrorDumpDir
                    
                    if ($true -ne $?)
                    {
                        "[Get-DumpDirectory] : [ERROR] Failed to retrieve ErrorDumpDir registry value from key: [{0}]" -f $CpeRegKey | WriteTo-StdOut
                        Report-Error
                    }
                }  
                else
                {
                    "[Get-DumpDirectory] : [ERROR] Cpe registry key: [{0}] is invalid or does not exist" -f $CpeRegKey | WriteTo-StdOut
                    Report-Error
                }              
                
        	}
        	else
        	{
        		# Report that we could not locate the SQL Server dump directory
        		"[Get-DumpDirectory] : [ERROR] Unable to locate dump directory for SQL Instance: [{0}]" -f $SqlInstance | WriteTo-StdOut
        		"[Get-DumpDirectory] : [ERROR] Registry key: [{0}] is invalid" -f ($InstanceKey + "\CPE") | WriteTo-StdOut
        	}
            
        } # if ($null -ne $InstanceKey)
        else
        {
            '[Get-DumpDirectory] : [ERROR] Get-SqlInstanceRootKey returned a null value' | WriteTo-StdOut
        }
    } 
    else
    {
        '[Get-DumpDirectory] : [ERROR] Required parameter -SqlInstance was not specified' | WriteTo-StdOut
    }
    
	return $SqlDumpDir
}

#
# Function : Collect-SqlServerMinidumps
# --------------------------------------
#
# PowerShell Version:
#			Written to be compatible with PowerShell 1.0
#
# Visibility:
#			Private/Internal - Do not call this function directly. Instead, call the top-level script and pass args
#			indicating which instances to collect dumps for  
#
# Description:
# 			This function enumerates the minidump files for a given SQL Server installation and 
# 
# Arguments:
#			String to write to file
# 
# Owner:
#			DanSha 
#
function Collect-SqlServerMinidumps ([string]$InstanceToCollect, [bool]$IsClustered )
{
    $Error.Clear()           
    trap 
    {
    	"[Collect-SqlServerMinidumps] : [ERROR] Trapped error ..." | WriteTo-StdOut
    	Report-Error 
    }
	
    If ($null -ne $InstanceToCollect)
    {
        if ($null -ne $IsClustered)
        {
            $DumpDir = Get-DumpDirectory -SqlInstance $InstanceToCollect

        	if ($null -ne $DumpDir)
            {
                # Make sure the dump directory path is valid. 
                # When SQL Server is clustered, the instance could be online to another cluster node
                # If so, the drive where the dumps are stored may be offline from the node where the collector is running
                #
                if (Test-Path -Path $DumpDir -PathType "Container")
                {
                    #$DumpCount = get-childitem -Path (Join-Path -Path $Dumpdir -ChildPath "*") -Include "*.mdmp" | Get-Count
                    
                    # Create the dump inventory report ... even if there are no dumps present ... report will indicate this
                    Write-DumpInventory -InstanceName $InstanceToCollect -DumpDir $DumpDir
                    
                    $FileFilters = @('*.mdmp')
                    
                    # First pass, enumerate the files but to not copy
				    $DumpFiles = @()
				    $DumpFiles = Copy-FileSql -SourcePath $DumpDir `
                         -FileFilters $FileFilters `
                         -FilePolicy $global:SQL:FILE_POLICY_SQL_SERVER_MINIDUMPS `
                         -InstanceName $InstanceToCollect `
						 -EnumerateOnly
                                            
                    #Since forcing an array to be created with above syntax need to check the length to see if there are any entries in array
                    if (($null -ne $DumpFiles) -and (0 -ne $Dumpfiles.Length))
                    {
                        # Need to go get the SQLDUMP*.log and SQLDUMP*.txt files associated with the dumps we just collected
                        foreach ($file in $dumpfiles)
                        {
                           $LogFileFullPath = $file.Replace("mdmp", "log")
                           # Add the .log file to the list of filefilters to enumerate.  No need to test-path as the enumerate/copy routine does this
                           $FileFilters += split-path -Leaf -Path $LogFileFullPath
                           
                           $TxtFileFullPath = $file.Replace("mdmp", "txt")
                           $FileFilters += split-path -Leaf -Path $TxtFileFullPath
                        } 
                        
                        # Add SQLDUMPER_ERRORLOG
                        $FileFilters += "SQLDUMPER_ERRORLOG.log" 
                       
                        # Add exception.log if present
                        $FileFilters += "exception.log" 
                        
                        $MiniDumpArchiveName = "{0}_{1}_{2}_SqlMiniDumps.zip" -f $env:ComputerName, $InstanceToCollect, (Get-LcidForSqlServer -SqlInstanceName $InstanceToCollect)
                    
                        # Re-enumerate, this time copy and compress since we should have all files we want.  FilePolicy is applied "by filter" so no need
                        # to adjust it to account for additional files for this subsequent call
                        $DumpFiles = @()
				        $DumpFiles = Copy-FileSql -SourcePath $DumpDir `
                         -FileFilters $FileFilters `
                         -FilePolicy $global:SQL:FILE_POLICY_SQL_SERVER_MINIDUMPS `
                         -InstanceName $InstanceToCollect `
                         -SectionDescription ("SQL Server minidumps and related files for instance {0}" -f $InstanceToCollect) `
                         -ZipArchiveName $MiniDumpArchiveName `
                         -CompressCollectedFiles
                         #-RenameCollectedFiles
                         
         
					} # if (($null -ne $DumpFiles) -and (0 -ne $Dumpfiles.Length))
                    else
                    {
                        "[Collect-SqlServerMinidumps] : [INFO] No minidumps found for instance: [{0}]" -f $InstanceToCollect | WriteTo-StdOut
                    }  
                }
                # Test-path failed for $DumpDir ... could be because the cluster resource where the dumpfiles are stored is offline to this cluster node
                else 
            	{
                    if ($true -eq (Check-IsSqlDiskResourceOnline $InstanceToCollect $DumpDir))
                    {
                        "[Check-IsSqlDiskResourceOffline] : [ERROR] Path to minidumps: [{0}] for instance: {1} is invalid" -f $DumpDir, $InstanceToCollect | WriteTo-StdOut
                    }
            	}
                
            } #if ($null -ne $DumpDir)
            else
            {
                '[Collect-SqlServerMinidumps] : [ERROR} Get-Dumpdirectory returned a null dump directory path for instance: [{0}]' -f $InstanceToCollect  | WriteTo-StdOut
            }
            
        } # if ($null -ne $IsClustered)
        else
        {
            '[Collect-SqlServerMinidumps] : [ERROR} Required parameter -IsClustered was not specified' | WriteTo-StdOut
        }
        
    } # If ($null -ne $InstanceToCollect)
    else
    {
        '[Collect-SqlServerMinidumps] : [ERROR} Required parameter -InstanceToCollect was not specified' | WriteTo-StdOut
    }
} 

#
# Script entry point
#
#region: MAIN ::::: 
$Error.Clear()           
trap 
{
	"[DC-CollectSqlSqlMinidumps] : [ERROR] Trapped error ..." | WriteTo-StdOut
	Report-Error
}
	
Import-LocalizedData -BindingVariable minidumpCollectorStrings

# Check to be sure that there is at least one SQL Server installation on target machine before proceeding
#
if ($true -eq (Check-SqlServerIsInstalled))
{
	# If $instance parameter is null, collect minidumps for all instances installed on machine
	#
	if ($null -eq $instances)
	{
		$instances = Enumerate-SqlInstances -Offline
	}
    
    if ($null -ne $instances)
    {
    
        foreach ($instance in $instances)
        {
			"[DC-CollectSqlSqlMinidumps] : Attempting to collect minidumps for SQL instance: [{0}]" -f $instance.InstanceName | WriteTo-StdOut
            Write-DiagProgress -Activity $minidumpCollectorStrings.ID_SQL_CollectSqlMinidumps -Status ($minidumpCollectorStrings.ID_SQL_CollectSqlMinidumpsDesc + ": " + $instance.InstanceName)
			
            # DEFAULT instance name is MSSQLSERVER in registry and filesystem.  Translate it here before doing any work
            if ('DEFAULT' -eq $instance.InstanceName.ToUpper()) {$instance.InstanceName='MSSQLSERVER'}
            
			Collect-SqlServerMinidumps -InstanceToCollect $instance.InstanceName -IsClustered $instance.IsClustered
        }
    }
} # if ($true -eq (Check-SqlServerIsInstalled))
else
{
    "[DC-CollectSqlSqlMinidumps] : [INFO] No SQL Server installation(s) were found on server: [{0}]" -f $env:ComputerName | WriteTo-StdOut
}
#endregion: MAIN ::::: 


# SIG # Begin signature block
# MIInpAYJKoZIhvcNAQcCoIInlTCCJ5ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDOy+lO1k20RWzi
# YHjTRwWNv1ZcL3i4LqPcMI9QSedO8aCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGYQwghmAAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMp8tIioqDg4X2Co77Sqy9qI
# tgRQfJ0dT+esJVJqK21BMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQC1mkqjxTO6vXH00zN8x589JA3ei2nJzeEuJqAjiSSDEBm/M0XfdDnZ
# 9+BaACYIaHCBD9kVQuZ1GJ7qQGFdamYA7a3WPwBnrcqJnjh5npM8WIgTEVsy+PhS
# VfzTU6Ws1YOH3OkQfimiOH9lZWVlPfqBOfOHDRXc4+H6U+PnHKLbW3Huf6fhwJJ7
# DDtC7X8O/s7wRLfemCiWY8824cv3S5pXVwA6lpwtnRICnP0Wn/ORz1IheaZRrly+
# zitcG7I7gRSENr/E2Hc4E+/1P+4e2bT3TmYdZgv/I1JCnzvqTvAT9Fv3R/xjjiCN
# eYWZJvXyANf6IizAS8/0jr6REnes5ZKdoYIXDDCCFwgGCisGAQQBgjcDAwExghb4
# MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQMEAgEFADCCAVUG
# CyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIO88vJIrh+F9mYEZMvg+AeRiAJFDOxfoMu/9me6cKykrAgZi2rcC
# Qr8YEzIwMjIwODAxMTEwNTEwLjI1N1owBIACAfSggdSkgdEwgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0
# NjJGLUUzMTktM0YyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABpAfP44+jum/WAAEAAAGkMA0GCSqG
# SIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMw
# MjE4NTExOFoXDTIzMDUxMTE4NTExOFowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo0NjJGLUUzMTktM0Yy
# MDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMBHjgD6FPy81PUhcOIVGh4bOSaq634Y
# +TjW2hNF9BlnWxLJCEuMiV6YF5x6YTM7T1ZLM6NnH0whPypiz3bVZRmwgGyTURKf
# VyPJ89R3WaZ/HMvcAJZnCMgL+mOpxE94gwQJD/qo8UquOrCKCY/fcjchxV8yMkfI
# qP69HnWfW0ratk+I2GZF2ISFyRtvEuxJvacIFDFkQXj3H+Xy9IHzNqqi+g54iQjO
# AN6s3s68mi6rqv6+D9DPVPg1ev6worI3FlYzrPLCIunsbtYt3Xw3aHKMfA+SH8CV
# 4iqJ/eEZUP1uFJT50MAPNQlIwWERa6cccSVB5mN2YgHf8zDUqQU4k2/DWw+14iLk
# wrgNlfdZ38V3xmxC9mZc9YnwFc32xi0czPzN15C8wiZEIqCddxbwimc+0LtPKand
# RXk2hMfwg0XpZaJxDfLTgvYjVU5PXTgB10mhWAA/YosgbB8KzvAxXPnrEnYg3XLW
# kgBZ+lOrHvqiszlFCGQC9rKPVFPCCsey356VhfcXlvwAJauAk7V0nLVTgwi/5ILy
# HffEuZYDnrx6a+snqDTHL/ZqRsB5HHq0XBo/i7BVuMXnSSXlFCo3On8IOl8JOKQ4
# CrIlri9qWJYMxsSICscotgODoYOO4lmXltKOB0l0IAhEXwSSKID5QAa9wTpIagea
# 2hzjI6SUY1W/AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQU4tATn6z4CBL2xZQd0jjN
# 6SnjJMIwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWlj
# cm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
# BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG
# 9w0BAQsFAAOCAgEACVYcUNEMlyTuPDBGhiZ1U548ssF6J2g9QElWEb2cZ4dL0+5G
# 8721/giRtTPvgxQhDF5rJCjHGj8nFSqOE8fnYz9vgb2YclYHvkoKWUJODxjhWS+S
# 06ZLR/nDS85HeDAD0FGduAA80Q7vGzknKW2jxoNHTb74KQEMWiUK1M2PDN+eISPX
# PhPudGVGLbIEAk1Goj5VjzbQuLKhm2Tk4a22rkXkeE98gyNojHlBhHbb7nex3zGB
# TBGkVtwt2ud7qN2rcpuJhsJ/vL/0XYLtyOk7eSQZdfye0TT1/qj18iSXHsIXDhHO
# uTKqBiiatoo4Unwk7uGyM0lv38Ztr+YpajSP+p0PEMRH9RdfrKRm4bHV5CmOTIzA
# mc49YZt40hhlVwlClFA4M+zn3cyLmEGwfNqD693hD5W3vcpnhf3xhZbVWTVpJH1C
# PGTmR4y5U9kxwysK8VlfCFRwYUa5640KsgIv1tJhF9LXemWIPEnuw9JnzHZ3iSw5
# dbTSXp9HmdOJIzsO+/tjQwZWBSFqnayaGv3Y8w1KYiQJS8cKJhwnhGgBPbyan+E5
# D9TyY9dKlZ3FikstwM4hKYGEUlg3tqaWEilWwa9SaNetNxjSfgah782qzbjTQhwD
# gc6Jf07F2ak0YMnNJFHsBb1NPw77dhmo9ki8vrLOB++d6Gm2Z/jDpDOSst8wggdx
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
# Ooo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCCAjsCAQEwgfyh
# gdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAn
# BgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjo0NjJGLUUzMTktM0YyMDElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUANBwo4pNrfEL6
# DVo+tw96vGJvLp+ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOaRu2gwIhgPMjAyMjA4MDEwNjM5MzZaGA8yMDIy
# MDgwMjA2MzkzNlowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5pG7aAIBADAKAgEA
# AgIQvwIB/zAHAgEAAgIRETAKAgUA5pMM6AIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBAKd/vm3XKHbzg1W5Vr6tLGc1BXf4lrCYDbQbzYNIR4xl0it4jcm0OvvT
# ari4axIY/cRc1+IjTcD591ivgf6+FxEv/kMGptZfbZphXCDYdQqteOGAVCikRG/9
# 5G9XYv4cAQhz8T6XrUFjP65GCGgKYOhx8QE1QSXE3Dm5WcS/+YekMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGkB8/jj6O6
# b9YAAQAAAaQwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg1qeCnvoaZJnsMTzliaU+lXJkSlhveSLq
# O8kMEJzbn7IwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCAF/OCjISZwpMBJ
# 8MJ3WwMCF3qOa5YHFG6J4uHjaup5+DCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABpAfP44+jum/WAAEAAAGkMCIEIAr0/gLXQOhyBflA
# rvuauNozVDAQ5zeYuEHe5PkPrgSNMA0GCSqGSIb3DQEBCwUABIICAFHcr1Tl6m5o
# 0UOceLP52181Q13lcEL6kgZdlsVt4Wxz3lwDgIQKMku/y9q7ViVSXd6ymxQ6fMcy
# T96oIwI01jbLdSK/Tn8O/gwSvIScHqMEWytbWgsx9C6sAHBtNIz80Tl+3pFtCiig
# UiKaqSWnUqmwb9kHSy/ceIME5HTIF4p0HX+6QICSEXhar66tg32pd+GS3I9kpH05
# 21dXVaYnzDzIIXTilF7YN+4axluk+JFxQm4Ecb4dZq7Re1POz9nRswpQBt4wn0jC
# txByJSxATWxODQosDkIXShbBR2tS9CGEUEeuGDV0/WSf1AsQDGxDasd1Odfh9WuZ
# 4gLkmrbdP6DqeFP8J5GjZKcBNmbkjrneRByLG2hHwv4pDk/8ZUzDE2SyPiSiL3aT
# Gm+rhf7wrer0ijloJKlgGVt4XjuhjZcKsfdsvBZFIREi2WhFK+W9G2SwXHyAunA0
# A6QaJAl6nZK6M6V2mdDrdkGVLbBOmv4DDPcB8pOm4bQCwCGhnNEG/eu9/oJFtR7P
# 5i0T5EcZ4rtLIBKXnesJDpttFLsjLcA2gTy0fS7+lsgH13BgXTlJQJe+SWriNFFP
# HHOyyCt6AtYnv6GkbMssCq6n7AMseLXnQk/YPPHAME9uEDewrrd3KrP5OjleEsGN
# PijIdr8rOBhA66R4wJpRi4abKnLnE2no
# SIG # End signature block
