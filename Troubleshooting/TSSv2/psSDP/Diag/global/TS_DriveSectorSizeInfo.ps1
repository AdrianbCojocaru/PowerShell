#************************************************
# TS_4KDriveInfo.ps1
# Version 1.0.2
# Date: 03-21-2011
# Author: Andre Teixeira - andret@microsoft.com
# Description: This script detects 4KB/ 512e drive informaiton
#************************************************
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

[string]$typeDefinition = @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;

namespace Microsoft.DeviceIoControl
{
    internal static class NativeMethods
    {

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode,
             ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr CreateFile(string fileName,
                                                  int desiredAccess,
                                                  int sharedMode,
                                                  IntPtr securityAttributes,
                                                  int creationDisposition,
                                                  int flagsandAttributes,
                                                  IntPtr templatFile);

        [DllImport("kernel32.dll", ExactSpelling = true, EntryPoint = "DeviceIoControl", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        internal static extern bool DeviceIoControl(IntPtr device,
                                                    int ioControlCode,
                                                    IntPtr inBuffer,
                                                    int inBufferSize,
                                                    IntPtr outBuffer,
                                                    int outputBufferSize,
                                                    out int bytesReturned,
                                                    IntPtr ignore);


        internal static readonly IntPtr INVALID_HANDLE_VALUE = (IntPtr)(-1);

        [DllImport("kernel32.dll")]
        internal static extern void ZeroMemory(IntPtr destination, int size);

    }

    public class SectorSize
    {

        [StructLayout(LayoutKind.Sequential)]   
        public struct STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR  
        {
            public int Version;
            public int Size;
            public int BytesPerCacheLine;
            public int BytesOffsetForCacheAlignment;
            public int BytesPerLogicalSector;
            public int BytesPerPhysicalSector;
            public int BytesOffsetForSectorAlignment;
        }

        public enum STORAGE_PROPERTY_ID 
        {
            StorageDeviceProperty = 0,
            StorageAdapterProperty,
            StorageDeviceIdProperty,
            StorageDeviceUniqueIdProperty,              // See storduid.h for details
            StorageDeviceWriteCacheProperty,
            StorageMiniportProperty,
            StorageAccessAlignmentProperty = 6,
            StorageDeviceSeekPenaltyProperty,
            StorageDeviceTrimProperty,
            StorageDeviceWriteAggregationProperty
        }

        public enum STORAGE_QUERY_TYPE {
              PropertyStandardQuery     = 0,
              PropertyExistsQuery,
              PropertyMaskQuery,
              PropertyQueryMaxDefined 
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STORAGE_PROPERTY_QUERY
        {
            public STORAGE_PROPERTY_ID PropertyId;
            public STORAGE_QUERY_TYPE QueryType;
            public IntPtr AdditionalParameters;
        }

        private const int GENERIC_READ = -2147483648;
        private const int FILE_SHARE_READ = 0x00000001;
        private const int FILE_SHARE_WRITE = 0x00000002;
        private const int OPEN_EXISTING = 3;
        private const int FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const int FSCTL_IS_VOLUME_DIRTY = 589944;
        private const int VOLUME_IS_DIRTY = 1;

        private const int PropertyStandardQuery = 0;
        private const int StorageAccessAlignmentProperty = 6;

        public static STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR DetectSectorSize(string devName)
        {
            string FileName = @"\\.\" + devName;
            int bytesReturned;
            IntPtr outputBuffer = IntPtr.Zero;

            STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR pAlignmentDescriptor = new STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR();

            SectorSize.STORAGE_PROPERTY_QUERY StoragePropertQuery = new SectorSize.STORAGE_PROPERTY_QUERY();

            StoragePropertQuery.QueryType = SectorSize.STORAGE_QUERY_TYPE.PropertyStandardQuery;
            StoragePropertQuery.PropertyId = SectorSize.STORAGE_PROPERTY_ID.StorageAccessAlignmentProperty;

            IntPtr hVolume = NativeMethods.CreateFile(FileName, 0, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

            if (hVolume != NativeMethods.INVALID_HANDLE_VALUE)
            {
                outputBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(pAlignmentDescriptor));
                NativeMethods.ZeroMemory(outputBuffer, Marshal.SizeOf(pAlignmentDescriptor));

                IntPtr outputBufferStoragePropertQuery = Marshal.AllocHGlobal(Marshal.SizeOf(StoragePropertQuery));
                Marshal.StructureToPtr(StoragePropertQuery, outputBufferStoragePropertQuery,false);

                int IOCTL_STORAGE_QUERY_PROPERTY = 2954240;
                
                bool status = NativeMethods.DeviceIoControl(hVolume,
                         IOCTL_STORAGE_QUERY_PROPERTY,
                         outputBufferStoragePropertQuery,
                         Marshal.SizeOf(StoragePropertQuery),
                         outputBuffer,
                         Marshal.SizeOf(pAlignmentDescriptor),
                         out bytesReturned,
                         IntPtr.Zero);

                if (!status)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                pAlignmentDescriptor = (STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR) Marshal.PtrToStructure(outputBuffer, typeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR));
            }
            return pAlignmentDescriptor;
        }
	}
}
"@

function FormatBytes 
{
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


Function CheckMinimalFileVersionWithCTS([string] $Binary, $RequiredMajor, $RequiredMinor, $RequiredBuild, $RequiredFileBuild)
{
	$newProductVersion = Get-FileVersionString($Binary)
	if((CheckMinimalFileVersion -Binar $Binary -RequiredMajor $RequiredMajor -RequiredMinor $RequiredMinor -RequiredBuild $RequiredBuild -RequiredFileBuild $RequiredFileBuild -LDRGDR) -eq $true)
	{
		"[CheckMinimalFileVersion] $Binary version is " + $newProductVersion + " - OK" | WriteTo-StdOut -ShortFormat
		return $true
	}
	else
	{
		"[CheckMinimalFileVersion] $Binary version is " + $newProductVersion | WriteTo-StdOut -ShortFormat
		add-member -inputobject $KB982018Binaries_Summary  -membertype noteproperty -name $Binary -value $newProductVersion
		return $false
	}
}

Function KB982018IsInstalled()
{
	if ($OSVersion.Build -le 7601) #Win7 Service Pack 1 or RTM
	{
		#Pre-Win7 SP1 - Need to check if KB 982018 is actually installed
		$System32Folder = $Env:windir + "\system32"		
		if (((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Amdsata.sys" 1 1 2 5) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Amdxata.sys" 1 1 2 5) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Nvraid.sys" 10 6 0 18) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Nvstor.sys" 10 6 0 18) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7600 16778) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7600 20921) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7601 17577) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Ntfs.sys" 6 1 7601 21680) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7600 16778) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7600 20921) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7601 17577) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Usbstor.sys" 6 1 7601 21680) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7601 17577) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7601 21680) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7600 16778) -eq $true) -and
			((CheckMinimalFileVersionWithCTS "$System32Folder\Drivers\Storport.sys" 6 1 7600 20921) -eq $true)
			)
		{ 
			#Everything is fine
			return $true
		} else {
			return $false
		}		
	} else {
		#SP1 is already installed
		return $true
	}
}

$512eDrivesXML = Join-Path -Path $PWD.Path -ChildPath "512eDrives.xml"

# Windows 8 fully support 4KB drives: http://blogs.msdn.com/b/b8/archive/2011/11/29/enabling-large-disks-and-large-sectors-in-windows-8.aspx
if (($OSVersion.Build -gt 7000) -and ($OSVersion.Build -lt 9000))
{
	Import-LocalizedData -BindingVariable AdvDrivesString

	$4KBDriveE = @()
	$4KBDriveN = @()
	
	if (Test-Path $512eDrivesXML)
	{
		$512eDrivesXML | Remove-Item -Force -ErrorAction Continue
	}

	Write-DiagProgress -Activity $AdvDrivesString.ID_CheckingDriveSize

	$StorageType = Add-Type -TypeDefinition $typeDefinition -PassThru
		
	$AlignmentDescriptor = $StorageType::STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR
	#$AlignmentDescriptor = $StorageType[1]::DetectSectorSize("C:")

	#$devices = (Get-CimInstance -query "Select DeviceID from Win32_LogicalDisk WHERE ((MediaType=12) or (MediaType=11)) and ((DriveType=3) or (DriveType=2))")
	$devices = (Get-CimInstance -query "Select DeviceID, Model, InterfaceType, Size, BytesPerSector, MediaType from Win32_DiskDrive where ConfigManagerErrorCode=0 and MediaLoaded = true and SectorsPerTrack > 0")
	
	if($null -ne $devices) 
	{
	
		$4KDriveDetected = $false
		$SectorSize_Summary = new-object PSObject
		$4KDrive_Summary = new-object PSObject
		$KB982018Binaries_Summary = new-object PSObject
		$4KNativeDetected = $false
		
	    foreach($device in $devices) 
		{
			trap [Exception] 
			{
			    $errorMessage = $_.Exception.Message
				"           Error: " + $errorMessage | WriteTo-StdOut
				$_.InvocationInfo | Format-List | out-string | WriteTo-StdOut
				
				WriteTo-ErrorDebugReport -ErrorRecord $_ -InvokeInfo $MyInvocation
				$Error.Clear()
				continue
			}

			Write-DiagProgress -Activity $AdvDrivesString.ID_CheckingDriveSize -Status ($AdvDrivesString.ID_4KDriveDetectedDesc -replace ("%Drive%", $device.DeviceID))
			
			
			$Interface = Get-CimInstance -Query ("ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + $device.DeviceID + "'} Where ResultClass=Win32_PnPEntity") | ForEach-Object {Get-CimInstance -Query ("ASSOCIATORS OF {Win32_PnPEntity.DeviceID='" + $_.DeviceID + "'} Where ResultClass=CIM_Controller")}
			$Partitions = Get-CimInstance -Query ("ASSOCIATORS OF {Win32_DiskDrive.DeviceID='" + $device.DeviceID + "'} Where ResultClass=Win32_DiskPartition")
			
			$DriveLetters = @()
			foreach ($Partition in $Partitions)
			{
				$Win32Logical = Get-CimInstance -Query ("ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + $Partition.DeviceID + "'} Where ResultClass=Win32_LogicalDisk")
				if ($null -ne $Win32Logical)
				{
					$DriveLetters += $Win32Logical.DeviceID
				}
			}
			
			if ($DriveLetters.Length -gt 0)
			{
				$DriveLetterString = "[" + [string]::Join(", ", $DriveLetters) + "]"
				$DriveLetters | Export-Clixml -Path $512eDrivesXML
			}
			else
			{
				$DriveLetterString = ""
			}
			
			$BytesDisplay = ""
			$4KDriveType = ""
			"Checking drive: " + $device.DeviceID | WriteTo-StdOut -ShortFormat
			"Storage Type: " + $StorageType[1].ToString() | WriteTo-StdOut -ShortFormat
			$AlignmentDescriptor = $StorageType[1]::DetectSectorSize($device.DeviceID)
			if ($null -ne $AlignmentDescriptor)
			{
				$BytesDisplay = ($AlignmentDescriptor.BytesPerPhysicalSector.ToString()) + " Bytes"
			}
			else
			{
				$BytesDisplay = "(Unknown)"
			}
			
			$DebugString = "    Results for drive " + $device.DeviceID
			$DebugString += "`r`n      Drive Letter(s)       : " + $DriveLetterString
			$DebugString += "`r`n      Model                 : " + $device.Model
			$DebugString += "`r`n      Interface Name        : " + $Interface.Name
			$DebugString += "`r`n      Interface Type        : " + $device.InterfaceType
			$DebugString += "`r`n      Bytes per sector (WMI): " + $device.BytesPerSector
			$DebugString += "`r`n      BytesPerPhysicalSector: " + $AlignmentDescriptor.BytesPerPhysicalSector
			$DebugString += "`r`n      BytesPerLogicalSector : " + $AlignmentDescriptor.BytesPerLogicalSector
			$DebugString += "`r`n      Version               : " + $AlignmentDescriptor.Version
			
			$DebugString | WriteTo-StdOut
			
			if (($AlignmentDescriptor.BytesPerPhysicalSector -gt 512) -or ($device.BytesPerSector -ne 512))
			{
				trap [Exception] 
				{
				    $errorMessage = $_.Exception.Message
					"           Error: " + $errorMessage | WriteTo-StdOut
					$_.InvocationInfo | Format-List | out-string | WriteTo-StdOut
					
					WriteTo-ErrorDebugReport -ErrorRecord $_ -InvokeInfo $MyInvocation
					$Error.Clear()
					continue
				}

				#4K Drive
				$4KDriveDetected = $true

				$InformationCollected = @{"Drive Model"=$device.Model}
				$InformationCollected += @{"Device ID"=$device.DeviceID}
				$InformationCollected += @{"Drive Letter(s)"=$DriveLetterString}
				$InformationCollected += @{"Drive Size"=($device.Size | FormatBytes -precision 2)}
				$InformationCollected += @{"Media Type"=$device.MediaType}
				$InformationCollected += @{"Drive Type"=$device.InterfaceType}
				$InformationCollected += @{"Interface Name"=$Interface.Name}
				$InformationCollected += @{"Bytes per sector (Physical)"=$AlignmentDescriptor.BytesPerPhysicalSector}
				$InformationCollected += @{"Bytes per sector (Logical)"=$AlignmentDescriptor.BytesPerLogicalSector}
				$InformationCollected += @{"Bytes per sector (WMI)"=$device.BytesPerSector}

				if (($AlignmentDescriptor.BytesPerPhysicalSector -eq 3072) -or ($device.BytesPerSector -eq 4096))
				{
					# known issue
					$BytesDisplay = "Physical: 4KB"
				} 
				else
				{
					$BytesDisplay = "Physical: " + ($AlignmentDescriptor.BytesPerPhysicalSector.ToString())
				}
				
				
				if (($AlignmentDescriptor.BytesPerLogicalSector -eq 512) -and ($device.BytesPerSector -eq 512))
				{
					$512EDriveDetected = $true
					$4KDriveType = " - Logical: " + $AlignmentDescriptor.BytesPerLogicalSector + " bytes<br/><b>[512e Drive]</b>"
					$4KBDriveE += $device.DeviceID
				}
				elseif ($device.BytesPerSector -eq 4096)
				{
					$4KNativeDetected = $true
					if ($AlignmentDescriptor.BytesPerPhysicalSector -eq 4096)
					{
						$4KDriveType = "Physical: " + ($AlignmentDescriptor.BytesPerPhysicalSector.ToString()) + "<b><font color=`"red`">[4KB Native]</font></b>"
					}
					else
					{
						$4KDriveType = "<b><font color=`"red`">[4KB Native]</font></b>"
					}					
				}
				else 
				{
					$4KNativeDetected = $true
					$4KDriveType = " - Logical: " + $AlignmentDescriptor.BytesPerLogicalSector + " bytes<br/><b><font color=`"red`">[4KB Native]</font></b>"
					$4KBDriveN += $device.DeviceID
				}
				
			}
			
			add-member -inputobject $SectorSize_Summary  -membertype noteproperty -name ($device.DeviceID + " " + $DriveLetterString) -value ($BytesDisplay + $4KDriveType)
			
			if ($512EDriveDetected)
			{
				Write-GenericMessage -RootCauseID "RC_4KDriveDetected" -PublicContentURL "http://support.microsoft.com/kb/2510009" -Verbosity "Informational" -InformationCollected $InformationCollected -Visibility 4 -MessageVersion 4 -SupportTopicsID 8122
				$512EDriveDetected = $false
				$RC_4KDriveDetected = $true
			}
						
			if ($4KNativeDetected)
			{
				Write-GenericMessage -RootCauseID "RC_4KNativeDriveDetected" -PublicContentURL "http://support.microsoft.com/kb/2510009" -Verbosity "Error" -InformationCollected $InformationCollected -MessageVersion 3 -Visibility 4 -MessageVersion 4 -SupportTopicsID 8122
				$RC_4KNativeDriveDetected = $true
				$4KNativeDetected = $false
			}
			
	    }
		
		$SectorSize_Summary | ConvertTo-Xml2 | update-diagreport -id 99_SectorSizeSummary -name "Drive Sector Size Information" -verbosity informational
		
		if ($RC_4KDriveDetected)
		{	

			Update-DiagRootCause -id "RC_4KDriveDetected" -Detected $true
			
			if (-not (KB982018IsInstalled))
			{
				$XMLFileName = "..\KB982018.XML"
				($KB982018Binaries_Summary | ConvertTo-Xml2).Save($XMLFileName)
				
				Update-DiagRootCause -id "RC_KB982018IsNotInstalled" -Detected $true 
				Write-GenericMessage -RootCauseID "RC_KB982018IsNotInstalled" -PublicContentURL "http://support.microsoft.com/kb/982018" -Verbosity "Error" -MessageVersion 3 -Visibility 4 -MessageVersion 3 -SupportTopicsID 8122
			}
			else
			{
				Update-DiagRootCause -Id "RC_KB982018IsNotInstalled" -Detected $false
			}
		}
		else
		{
			Update-DiagRootCause -Id "RC_4KDriveDetected" -Detected $false
		}
		
		if ($RC_4KNativeDriveDetected)
		{
			Update-DiagRootCause -id "RC_4KNativeDriveDetected" -Detected $true
			Write-GenericMessage -RootCauseID "RC_4KNativeDriveDetected" -Verbosity "Error" -PublicContentURL "http://support.microsoft.com/kb/2510009" -Visibility 4 -MessageVersion 3 -SupportTopicsID 8122
		}
		else
		{
			Update-DiagRootCause -Id "RC_4KNativeDriveDetected" -Detected $false
		}
	}
}


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBIZxv351ToXhIr
# ra20Q4QHbObADmg5T1ywTt0ugyFIQqCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGXUwghlxAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICLXru2WrmmFhN7h30X8uMam
# ub4RK2pzeRvgfImm52HJMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAipi7d/55XVEJL4HzmGOO/C6Zu4ieQEvxHj4cl7asjMF+Elg6NMZXv
# hxBirCeVxiQC8/fII2nb/sQ3QcX3GkqvOblFZtxeHO/LGLpTyZ0e7MwG03lkjJtD
# 5+eAcvsf47doqeVZXGLv+WbvWCLVZQteqoFnmaGfIvIjMtpUvcRB0eYbIoe176aD
# fKcpijWqoJV/Rbh3EbAGCYYRC0yiYrHKvRdft3EnaMemNwFI3Dq4APjqT03P0rVZ
# epXC2QqywEQB2ZISihL0xzYveLtuc5isY1yW9ig38+X7HcJnzqImWCYW+b8Lxv5q
# LT/1+jLbj3+PNaWmyo78j6bj2rN0v+CxoYIW/TCCFvkGCisGAQQBgjcDAwExghbp
# MIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEG
# CyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIABYEn1wAr4Kx5/m1c6v74MSWELka1WdozBaG6PvKZvcAgZi1+uY
# akIYEzIwMjIwODAxMDgwMTExLjcwM1owBIACAfSggdCkgc0wgcoxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBB
# bWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjQ5QkMt
# RTM3QS0yMzNDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# oIIRVDCCBwwwggT0oAMCAQICEzMAAAGXA89ZnGuJeD8AAQAAAZcwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkw
# NTE0WhcNMjMwMjI4MTkwNTE0WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9u
# czEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046NDlCQy1FMzdBLTIzM0MxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDtAErqSkFN8/Ce/csrHVWcv1iSjNTArPKEMqKPUTpY
# JX8TBZl88LNrpw4bEpPimO+Etcli5RBoZEieo+SzYUnb0+nKEWaEYgubgp+HTFZi
# D85Lld7mk2Xg91KMDE2yMeOIH2DHpTsn5p0Lf0CDlfPE5HOwpP5/vsUxNeDWMW6z
# sSuKU69aL7Ocyk36VMyCKjHNML67VmZMJBO7bX1vYVShOvQqZUkxCpCR3szmxHT0
# 9s6nhwLeNCz7nMnU7PEiNGVxSYu+V0ETppFpK7THcGYAMa3SYZjQxGyDOc7J20kE
# ud6tz5ArSRzG47qscDfPYqv1+akex81w395E+1kc4uukfn0CeKtADum7PqRrbRMD
# 7wyFnX2FvyaytGj0uaKuMXFJsZ+wfdk0RsuPeWHtVz4MRCEwfYr1c+JTkmS3n/pv
# Hr/b853do28LoPHezk3dSxbniQojW3BTYJLmrUei/n4BHK5mTT8NuxG6zoP3t8HV
# mhCW//i2sFwxVHPsyQ6sdrxs/hapsPR5sti2ITG/Hge4SeH7Sne942OHeA/T7sOS
# JXAhhx9VyUiEUUax+dKIV7Gu67rjq5SVr5VNS4bduOpLsWEjeGHpMei//3xd8dxZ
# 42G/EDkr5+L7UFxIuBAq+r8diP/D8yR/du7vc4RGKw1ppxpo4JH9MnYfd+zUDuUg
# cQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFG3PAc8o6zBullUL0bG+3X69FQBgMB8G
# A1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCG
# Tmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUy
# MFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQAD
# ggIBAARI2GHSJO0zHnshct+Hgu4dsPU0b0yUsDXBhAdAGdH1T+uDeq3c3Hp7v5C4
# QowSEqp0t/eDlFHhH+hkvm8QlVZR8hIf+hJZ3OqtKGpyZPg7HNzYIGzRS2fKilUO
# bhbYK6ajeq7KRg+kGgZ16Ku8N13XncDCwmQgyCb/yzEkpsgF5Pza2etSeA2Y2jy7
# uXW4TSGwwCrVuK9Drd9Aiev5Wpgm9hPRb/Q9bukDeqHihw2OJfpnx32SPHwvu4E8
# j8ezGJ8KP/yYVG+lUFg7Ko/tjl2LlkCeNMNIcxk1QU8e36eEVdRweNc9FEcIyqom
# DgPrdfpvRXRHztD3eKnAYhcEzM4xA0i0k5F6Qe0eUuLduDouemOzRoKjn9GUcKM2
# RIOD7FXuph5rfsv84pM2OqYfek0BrcG8/+sNCIYRi+ABtUcQhDPtYxZJixZ5Q8Vk
# jfqYKOBRjpXnfwKRC0PAzwEOIBzL6q47x6nKSI/QffbKrAOHznYF5abV60X4+TD+
# 3xc7dD52IW7saCKqN16aPhV+lGyba1M30ecB7CutvRfBjxATa2nSFF03ZvRSJLEy
# YHiE3IopdVoMs4UJ2Iuex+kPSuM4fyNsQJk5tpZYuf14S8Ov5A1A+9Livjsv0Brw
# uvUevjtXAnkTaAISe9jAhEPOkmExGLQqKNg3jfJPpdIZHg32MIIHcTCCBVmgAwIB
# AgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1
# WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O
# 1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZn
# hUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t
# 1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxq
# D89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmP
# frVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSW
# rAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv
# 231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zb
# r17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYcten
# IPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQc
# xWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17a
# j54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQAB
# MCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQU
# n6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEw
# QTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9E
# b2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3h
# LB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x
# 5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74p
# y27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1A
# oL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbC
# HcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB
# 9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNt
# yo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3
# rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcV
# v7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A24
# 5oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lw
# Y1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHK
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxN
# aWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNT
# IEVTTjo0OUJDLUUzN0EtMjMzQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAYUDSsI2YSTTNTXYNg0YxTcHWY9Gg
# gYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0B
# AQUFAAIFAOaRkxgwIhgPMjAyMjA4MDEwNzQ3MzZaGA8yMDIyMDgwMjA3NDczNlow
# dDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5pGTGAIBADAHAgEAAgIeizAHAgEAAgIR
# wzAKAgUA5pLkmAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
# CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAF1eQuLWB69l
# cRkwlDC//Q8t6MKhMl4o4Q+GcAYe9w/P1hDjWpsFI3X3Q+q6z8QtX/Q1c4IK5S6G
# JXMlxEbcKpiXknCiQ8r4UssZYTe3qUIeBsh0XohckQUJEbEzUMUAqe474r3Ibf4d
# gwN5gry9881JMrkws7I0ZHaZmL36EBVuMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGXA89ZnGuJeD8AAQAAAZcwDQYJYIZI
# AWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG
# 9w0BCQQxIgQgBpIfppTo6pheMZOpUKjkOCPbxFmzPD680pail/M43vUwgfoGCyqG
# SIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBbe9obEJV6OP4EDMVJ8zF8dD5vHGSoLDwu
# Qxj9BnimvzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMz
# AAABlwPPWZxriXg/AAEAAAGXMCIEIJ3XeUNIGOGvXHlvVJ8soX+gMgA0CH0mLbWJ
# R46ykrvfMA0GCSqGSIb3DQEBCwUABIICADHrtkWWFMvDWazQoxxxf1zaFuWAv10u
# AB8fRT5kmZLT1LPRC5liWo1AQQiWjUX9PeR9tgMyfTW4bMtJoaFKuxp/m4+wRQcY
# uAIBjj4XZZTFVTZnTf7bNslno/8q8BFrUzjzRpEKeE2iQ8HLq87sO5KXfKtgZwVo
# y/VYZ7re9CQosJKXD8Pr2d80FRRNKdkLg+kPNqvfhDtQTY+cgon7IaffuLtjfM/B
# d4KqeHvFhd1+/FmOIonuA88wdlLcetrZZG6pQHJfFY1+epuZ3/CsydKiN/5jt2hX
# nj/cOyMYc/611ZHi0rZ1Boit0vT46daA73Rwu8dBIQPYyG79z1+Ptvtlotxl3nrZ
# IFc/snRYQr/e/bWL1q/Rc3yw5tMNAEEMPpuuGmRQhZxiU9IPqJFrvAKxu3VoUvHG
# CJX7Fgq4UApr+QptRUKcVOu0ruTNNYWzBA6Jb8vZjdcdKz9jqcCKab/L6r1b3iz3
# FYy0lWOwXB6js7S/zSNWnftKBYiNa4oBLJGvXoBJARVbzjtyw7OJN6vs1M3bVSWa
# KtpD120qEgmJ5vqnStukn+Dk0TCBMABdcQBvt3MZG80tlpkq+X1w36aOLNi3D7gv
# PbxhAYy2Y7z6lhQxb0qM1JvHMiyxz2erxypanAnez9LmQ1wV+1trJ6gnhJ0dfkm4
# NbPi4t97OMZx
# SIG # End signature block
