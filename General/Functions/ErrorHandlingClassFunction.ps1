
#region----------------------------------------------------- [Classes] ----------------------------------------------
class OraException : Exception {
	[string] $additionalData

	OraException($Message, $additionalData) : base($Message) {
		$this.additionalData = $additionalData
	}
}
#endregion----------------------------------------------------- [Classes] ----------------------------------------------
#region----------------------------------------------------- [Functions] ----------------------------------------------
Function Write-Log {
	<#
 .Synopsis
  Used to write to the log file.

 .Example
   ### Call Write-Log with -Caller (optional parameter).
   Write-Log -Message "Your message goes here" -Caller "Caller Name goes here"

 .Example
   ### Call Write-Log.
   Write-Log -Message "Your message goes here"
#>

	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
		[ValidateNotNull()]
		[AllowEmptyString()]
		# Mandatory. Specifies the message string.
		[string]$Message,
		[Parameter(Mandatory = $false, Position = 1)]
		# Optional. Specifies the message color in the powershell console White(default) Green Blue Yellow DarkYellow Red
		[string]$Color = 'White',
		[Parameter(Mandatory = $false, Position = 2)]
		# Optional. Specifies the message color in the powershell console White(default) Green Blue Yellow DarkYellow Red
		[string]$BackgroundColor = '',
		[Parameter(Mandatory = $false, Position = 3)]
		[ValidateNotNull()]
		# Optional. Specifies the name of the message writter. Function, command or custom name. Defaults to FunctioName or unknown
		[string]$Caller = 'Unknown'
	)
	Begin {
		[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
		[string]$LogTime = (Get-Date -Format 'HH\:mm\:ss.fff').ToString()
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		#if ([string]::IsNullOrEmpty($Message)) { return }
	}
	Process {
		#if ([string]::IsNullOrEmpty($Message)) { return }
		ForEach ($Msg in $Message) {
			If ($Msg) {
				[string]$CompleteMsg = "[$LogDate $LogTime] [${Caller}] :: $Msg"
				#Try {
				if ($BackgroundColor -eq '') {
					$CompleteMsg | Write-Host -ForegroundColor $Color
				}
				else {
					$CompleteMsg | Write-Host -ForegroundColor $Color -BackgroundColor $BackgroundColor 
				}
				$CompleteMsg | Out-File -FilePath $LogPath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop' 
				#}
				#Catch {
				# Write-Error2 -Message  "[$LogDate $LogTime] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogPath]" -Category WriteError
				#}
			}
		}
	}
	End {}
}
function Write-Error2 {
	<#
     .Synopsis
      Used to dump errors to the log file. Parameters needed only for a collection.
     .Example
     ###
     Write-Error2
    #>
    
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $false, Position = 0)]
		[AllowEmptyCollection()]
		# Optional. The errorr collection.
		[array]$ErrorRecord,
		[Parameter(Mandatory = $false, Position = 1)]
		[AllowEmptyCollection()]
		# Optional.
		[switch]$Pause
	)
	Begin {
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		If (-not $ErrorRecord) {
			If ($global:Error.Count -eq 0) {
				Return
			}
			Else {
				[array]$ErrorRecord = $global:Error[0]
			}
		}
	}
	Process {
		$ErrorRecord | ForEach-Object {
			$errNumber = $ErrorRecord.count - $( $ErrorRecord.IndexOf($_))
			$ExceptionType = $_.exception.GetType().fullname
			if ($ExceptionType -eq 'OraException') {
				"[$($($_.Exception).Message)]:: $($($_.Exception).additionalData)" | Write-Log -Caller "${CmdletName} Nr. $errNumber" -Color Red
			}
			else {
				$_.CategoryInfo | Write-Log -Caller "${CmdletName} Nr. $errNumber"  -Color Red
				#$_.InvocationInfo.Line | Write-Log -Caller "Error Nr. $errNumber"
				#"$($($Error[2].InvocationInfo).ScriptName): $($($Error[2].InvocationInfo).ScriptLineNumber) char:$($($Error[2].InvocationInfo).OffsetInLine)"
				$_ | Write-Log -Caller "${CmdletName} Nr. $errNumber" -Color Red
				$_.InvocationInfo.PositionMessage | Write-Log -Caller "${CmdletName} Nr. $errNumber" -Color Red
			}
			if ($Pause) {
				Write-Log "Please review before continuing!" -BackgroundColor DarkMagenta -Color Yellow -Caller $CmdletName
				Pause
			}
		}
	}
	End {}
}

#endregion----------------------------------------------------- [ Functions] ----------------------------------------------