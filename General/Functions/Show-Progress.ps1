function Show-Progress {
    	<#
 .DESCRIPTION
  Write a progress bar inside the powershell console.
  Original js code from https://github.com/watson/progress-string
  
 .INPUTS
  TotalValue - Maximum value that will get the progrgess to 100%
  CurrentValue
  PrrogressText - Text to be displayed before the progress bar

 .OUTPUTS
  
 .Example
   Show-Progress -TotalValue 50 -CurrentValue 100 -ProgressText "Uploading.."
#>
	param (
		# Enter total value
		[Parameter(Mandatory)]
		[Single]$TotalValue,

		# Enter current value
		[Parameter(Mandatory)]
		[Single]$CurrentValue,

		# Enter custom progresstext
		[Parameter(Mandatory)]
		[string]$ProgressText,

		# Enter value suffix
		[Parameter()]
		[string]$ValueSuffix,

		# Enter bar lengh suffix
		[Parameter()]
		[int]$BarSize = 40,

		# show complete bar
		[Parameter()]
		[switch]$Complete
	)
	
	# calc %
	$percent = $CurrentValue / $TotalValue
	$percentComplete = $percent * 100
	if ($ValueSuffix) {
		$ValueSuffix = " $ValueSuffix" # add space in front
	}
	if ($psISE) {
		Write-Progress "$ProgressText $CurrentValue$ValueSuffix of $TotalValue$ValueSuffix" -id 0 -percentComplete $percentComplete            
	}
	else {
		# build progressbar with string function
		$curBarSize = $BarSize * $percent
		$progbar = ""
		$progbar = $progbar.PadRight($curBarSize, [char]9608)
		$progbar = $progbar.PadRight($BarSize, [char]9617)

		if (!$Complete.IsPresent) {
			Write-Host -NoNewLine "`r$ProgressText $progbar [ $($CurrentValue.ToString("#.###").PadLeft($TotalValue.ToString("#.###").Length))$ValueSuffix / $($TotalValue.ToString("#.###"))$ValueSuffix ] $($percentComplete.ToString("##0.00").PadLeft(6)) % complete"
		}
		else {
			Write-Host -NoNewLine "`r$ProgressText $progbar [ $($TotalValue.ToString("#.###").PadLeft($TotalValue.ToString("#.###").Length))$ValueSuffix / $($TotalValue.ToString("#.###"))$ValueSuffix ] $($percentComplete.ToString("##0.00").PadLeft(6)) % complete"                    
		}                
	}   
}
