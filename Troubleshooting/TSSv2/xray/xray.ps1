<#
.SYNOPSIS
Detects known issues and helps resolve them.

.DESCRIPTION
xray aims to automate detection of known issues and help resolve them with minimal time and effort.
It consists of multiple diagnostic functions each looking for a known issue.

.PARAMETER Area
Which technology area xray should run diagnostics for. 
Specify either Area or Component to check or Diagnostic to run (they are mutually exclusive), multiple items can be specified (comma-separated).
When area(s) specified, all components within the specified area(s) are checked
"-Area all" or "-Area *" checks all areas

.PARAMETER Conponent
Which conponent xray should run diagnostics for. 
Specify either Area or Component to check or Diagnostic to run (they are mutually exclusive), multiple items can be specified (comma-separated).
When component(s) specified, all diagnostics within the specified component(s) are run
No wildcards allowed, to run diagnostics for all components, use -Area parameter instead.

.PARAMETER Diagnostic
Which conponent xray should run diagnostics for. 
Specify either Area or Component to check or Diagnostic to run (they are mutually exclusive), multiple items can be specified (comma-separated).
When diagnostic(s) specified, only the specified diagnostics are run
No wildcards allowed, to run all diagnostics, consider using -Area or -Component parameter instead.

.PARAMETER DataPath
Path for input/output files

.PARAMETER Offline
Indicates xray is not running on the actual machine being examined (some -not all- diagnostics can use data files to search for issues)

.PARAMETER WaitBeforeClose
If any known issues are detected, pauses just before script terminates/window closes
Used to ensure detected issues shown on screen are not missed (they are always saved to report file)

.PARAMETER SkipDiags
Do not run diagnostics, only do the minimum essential work, like checking Windows update status etc.
Use carefully, any known issues present will go undetected when this switch is specified.

.PARAMETER DevMode
For diagnostic developers, to be used only whilst developing a diagnostic function. 
When specified, error messages for diagnostics are not suppressed.

.PARAMETER AcceptEULA
Do not display EULA at start

.EXAMPLE
PS> xray.ps1 -Component dhcpsrv,dnssrv -DataPath c:\xray -WaitBeforeClose

This command runs all diagnostics for both dhcpsrv and dnssrv components, saves results to specified path c:\xray and waits for user before terminating if any issues found.

.EXAMPLE
PS> .\xray.ps1 -Area * -DataPath c:\MS_DATA

This command runs all diagnostics for all components in all technology areas and saves results to data path specified.
#>

Param(
    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [ValidateSet("All", "*", "ADS", "DND", "NET", "PRF", "SHA", "UEX")]
    [String[]]
    $Area,

    [Parameter(Mandatory=$true,
    ParameterSetName="Components")]
    [String[]]
    $Component,

    [Parameter(Mandatory=$true,
    ParameterSetName="Diagnostics")]
    [String[]]
    $Diagnostic,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [String]
    $DataPath,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $Offline,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $WaitBeforeClose,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $SkipDiags,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $DevMode,

    [Parameter(Mandatory=$false,
    ParameterSetName="Areas")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Components")]
    [Parameter(Mandatory=$false,
    ParameterSetName="Diagnostics")]
    [switch]
    $AcceptEULA
)

Import-Module -Name .\xray_WU.psm1 -Force
Import-Module -Name .\diag_api.psm1 -Force

Import-Module -Name .\diag_ads.psm1 -Force
Import-Module -Name .\diag_dnd.psm1 -Force
Import-Module -Name .\diag_net.psm1 -Force
Import-Module -Name .\diag_prf.psm1 -Force
Import-Module -Name .\diag_sha.psm1 -Force
Import-Module -Name .\diag_uex.psm1 -Force

# used for diagnostic development only
if ($DevMode) {
    Import-Module -Name .\diag_test.psm1 -Force
}

# version
$version = "1.0.221019.1"

# Area and Area/Component arrays
$TechAreas = @("ADS", "DND", "NET", "PRF", "SHA", "UEX")
#endregion globals

#region helpers

# Processes provided area(s) with all its components & checks
function RunDiagForArea($areas)
{
    foreach ($area in $areas) {
        LogWrite "Processing area:$area"

        try {
            $components = (Get-Variable -Name $area -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
        }
        catch {
            LogWrite $Error[0].Exception
        }

        if($ErrorMsg) {
            LogWrite $ErrorMsg
        }
        else {
            RunDiagForComponent $components
        }
    }
}

# Processes provided components and runs corresponding diags
function RunDiagForComponent($components)
{
    if($components.Count -eq 0){
        LogWrite "No components!"
        return
    }

    foreach ($component in $components) {
        LogWrite "Processing component: $component"

        try {
            $diags = (Get-Variable -Name $component -ErrorVariable ErrorMsg -ErrorAction SilentlyContinue).Value
        }
        catch {
            LogWrite $Error[0].Exception
        }

        if($ErrorMsg) {
            LogWrite $ErrorMsg
        }
        else {
            RunDiag $diags
        }
    }
}

# Runs specified diagnostics
function RunDiag($diagnostics)
{
    if($diagnostics.Count -eq 0){
        LogWrite "No diagnostics!"
        return
    }

    foreach ($diag in $diagnostics) {
        if($executedDiags.Contains($diag)) {
            LogWrite "Skipping duplicate instance: $diag"
            continue
        }
        $Global:currDiagFn = $diag
        $executedDiags.Add($diag)
        LogWrite "Running diagnostic: $diag"
        XmlAddDiagnostic $diag
        Write-Host "." -NoNewline
        $time1 = (Get-Date).ToUniversalTime()

        $Global:numDiagsRun++
        if ($DevMode) {
            # no error/exception protection
            $result = & $diag $Offline
        }
        else {
            # to prevent failure messages from diag functions
            $ErrorActionPreference = "Stop"
            try {
                $result = & $diag $Offline
            }
            catch {
                $result = $RETURNCODE_EXCEPTION
                LogWrite $Error[0].Exception.Message
            }
            # revert to normal error handling 
            $ErrorActionPreference = "Continue"
        }

        LogWrite "$diag returned: $result"
        $time2 = (Get-Date).ToUniversalTime()
        [UInt64] $timeTaken = ($time2 - $time1).TotalMilliseconds
        XmlDiagnosticComplete $diag $result $timeTaken

        if($result -eq $RETURNCODE_SUCCESS){
            $Global:numDiagsSuccess++
        }
        elseif($result -eq $RETURNCODE_SKIPPED){
            $Global:numDiagsSkipped++
        }
        else {
            $Global:numDiagsFailed++
        }
        $Global:currDiagFn = $null
    }
}

# 'Translates' TSS scenarios to xray components 
function ValidateTssComponents
{
    param(
        [Parameter(Mandatory=$true)]
        [String[]]
        $TssComponents
    )

    $tssComps  = @("802Dot1x", "WLAN",     "Auth", "BITS", "BranchCache", "Container", "CSC", "DAcli", "DAsrv", "DFScli", "DFSsrv", "DHCPcli", "DhcpSrv", "DNScli", "DNSsrv", "Firewall", "General", "HypHost", "HypVM", "IIS", "IPAM", "MsCluster", "MBAM", "MBN", "Miracast", "NCSI", "NetIO", "NFScli", "NFSsrv", "NLB", "NPS", "Proxy", "RAS", "RDMA", "RDScli", "RDSsrv", "SDN", "SdnNC", "SQLtrace", "SBSL", "UNChard", "VPN", "WFP", "Winsock", "WIP", "WNV", "Workfolders")
    $xrayComps = @("802Dot1x", "802Dot1x", "Auth", "BITS", "BranchCache", "Container", "CSC", "DAcli", "DAsrv", "DFScli", "DFSsrv", "DHCPcli", "DhcpSrv", "DNScli", "DNSsrv", "Firewall", "General", "HypHost", "HypVM", "IIS", "IPAM", "MsCluster", "MBAM", "MBN", "Miracast", "NCSI", "NetIO", "NFScli", "NFSsrv", "NLB", "NPS", "Proxy", "RAS", "RDMA", "RDScli", "RDSsrv", "SDN", "SdnNC", "SQLtrace", "SBSL", "UNChard", "VPN", "WFP", "Winsock", "WIP", "WNV", "Workfolders")

    for ($i = 0; $i -lt $tssComps.Count; $i++) {
        $tssComps[$i] = $tssComps[$i].ToLower()
        $xrayComps[$i] = $xrayComps[$i].ToLower()
    }
    for ($i = 0; $i -lt $TssComponents.Count; $i++) {
        $TssComponents[$i] = $TssComponents[$i].ToLower()
    }
    [System.Collections.Generic.List[String]] $newComps = $TssComponents

    for ($i = 0; $i -lt $TssComponents.Count; $i++) {
        $index = -1
        for ($j = 0; $j -lt $tssComps.Count; $j++) {
            if ($tssComps[$j] -eq $TssComponents[$i]) {
                $index = $j
                break
            }
        }
        if($index -lt 0) {
            continue
        }
        if($TssComponents[$i] -ne $xrayComps[$index]) {
            # remove
            $newComps.RemoveAt($i)
            if(!$newComps.Contains($xrayComps[$index])) {
                # replace
                $newComps.Insert($i, $xrayComps[$index])
            }
        }
    }
    return [String[]] $newComps
}

# Displays help/usage info
function ShowHelp
{
    "
No parameters specified, nothing do. 

For usage info, run:
    Get-Help .\xray.ps1

List of available diagnostic areas/components to scan for issues:

Area (version):  `tComponents:
=================`t==========="

    foreach ($techarea in $TechAreas) {
        $version_name = $techarea + "_version"
        $techarea_version = (Get-Variable -Name $version_name).Value
        $components = (Get-Variable -Name $techarea).Value
        "$techarea ($techarea_version)`t$components"
    }
    ""
}
#endregion helpers

#region EULA
[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')

function ShowEULAPopup($mode)
{
    $EULA = New-Object -TypeName System.Windows.Forms.Form
    $richTextBox1 = New-Object System.Windows.Forms.RichTextBox
    $btnAcknowledge = New-Object System.Windows.Forms.Button
    $btnCancel = New-Object System.Windows.Forms.Button

    $EULA.SuspendLayout()
    $EULA.Name = "EULA"
    $EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"

    $richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $richTextBox1.Location = New-Object System.Drawing.Point(12,12)
    $richTextBox1.Name = "richTextBox1"
    $richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
    $richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
    $richTextBox1.TabIndex = 0
    $richTextBox1.ReadOnly=$True
    $richTextBox1.Add_LinkClicked({Start-Process -FilePath $_.LinkText})
    $richTextBox1.Rtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fswiss\fprq2\fcharset0 Segoe UI;}{\f1\fnil\fcharset0 Calibri;}{\f2\fnil\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue255;}
{\*\generator Riched20 10.0.19041}{\*\mmathPr\mdispDef1\mwrapIndent1440 }\viewkind4\uc1 
\pard\widctlpar\f0\fs19\lang1033 MICROSOFT SOFTWARE LICENSE TERMS\par
Microsoft Diagnostic Scripts and Utilities\par
\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}\par
\pard 
{\pntext\f0 1.\tab}{\*\pn\pnlvlbody\pnf0\pnindent0\pnstart1\pndec{\pntxta.}}
\fi-360\li360 INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (\ldblquote Microsoft\rdblquote ) grants you (\ldblquote Customer\rdblquote  or \ldblquote you\rdblquote ) a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the "Software"), solely for Customer\rquote s internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). \ldblquote Use\rdblquote  means to copy, install, execute, access, display, run or otherwise interact with the Software. \par
\pard\widctlpar\par
\pard\widctlpar\li360 You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft\rquote s IT systems or impair anyone else\rquote s use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above.\par
\par
\pard\widctlpar\fi-360\li360 2.\tab DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at {{\field{\*\fldinst{HYPERLINK https://aka.ms/privacy }}{\fldrslt{https://aka.ms/privacy\ul0\cf0}}}}\f0\fs19 . Your use of the Software operates as your consent to these practices.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 3.\tab FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose.\~ You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 4.\tab EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit {{\field{\*\fldinst{HYPERLINK https://aka.ms/exporting }}{\fldrslt{https://aka.ms/exporting\ul0\cf0}}}}\f0\fs19 .\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 5.\tab REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party\rquote s intellectual property to any other license terms or require the other party to distribute source code to any of its technologies.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 6.\tab DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED \ldblquote AS IS,\rdblquote  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\par
\pard\widctlpar\qj\par
\pard\widctlpar\fi-360\li360\qj 7.\tab LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 8.\tab BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States.  If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can\rquote t, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (\ldblquote FAA\rdblquote ), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at {{\field{\*\fldinst{HYPERLINK https://aka.ms/arb-agreement-4 }}{\fldrslt{https://aka.ms/arb-agreement-4\ul0\cf0}}}}\f0\fs19 . You and Microsoft agree to these terms. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 9.\tab LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration).\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 10.\tab ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software.\par
\pard\sa200\sl276\slmult1\f1\fs22\lang9\par
\pard\f2\fs17\lang2057\par
}
"@
    $richTextBox1.BackColor = [System.Drawing.Color]::White
    $btnAcknowledge.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnAcknowledge.Location = New-Object System.Drawing.Point(544, 415)
    $btnAcknowledge.Name = "btnAcknowledge";
    $btnAcknowledge.Size = New-Object System.Drawing.Size(119, 23)
    $btnAcknowledge.TabIndex = 1
    $btnAcknowledge.Text = "Accept"
    $btnAcknowledge.UseVisualStyleBackColor = $True
    $btnAcknowledge.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::Yes})

    $btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnCancel.Location = New-Object System.Drawing.Point(669, 415)
    $btnCancel.Name = "btnCancel"
    $btnCancel.Size = New-Object System.Drawing.Size(119, 23)
    $btnCancel.TabIndex = 2
    if($mode -ne 0)
    {
	    $btnCancel.Text = "Close"
    }
    else
    {
	    $btnCancel.Text = "Decline"
    }
    $btnCancel.UseVisualStyleBackColor = $True
    $btnCancel.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::No})

    $EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
    $EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    $EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
    $EULA.Controls.Add($btnCancel)
    $EULA.Controls.Add($richTextBox1)
    if($mode -ne 0)
    {
	    $EULA.AcceptButton=$btnCancel
    }
    else
    {
        $EULA.Controls.Add($btnAcknowledge)
	    $EULA.AcceptButton=$btnAcknowledge
        $EULA.CancelButton=$btnCancel
    }
    $EULA.ResumeLayout($false)
    $EULA.Size = New-Object System.Drawing.Size(800, 650)

    Return ($EULA.ShowDialog())
}

function ShowEULAIfNeeded($toolName, $mode)
{
	$eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
	$eulaAccepted = "No"
	$eulaValue = $toolName + " EULA Accepted"
	if(Test-Path $eulaRegPath)
	{
		$eulaRegKey = Get-Item $eulaRegPath
		$eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
	}
	else
	{
		$eulaRegKey = New-Item $eulaRegPath
	}
	if($mode -eq 2) # silent accept
	{
		$eulaAccepted = "Yes"
       		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
	}
	else
	{
		if($eulaAccepted -eq "No")
		{
			$eulaAccepted = ShowEULAPopup($mode)
			if($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes)
			{
	        		$eulaAccepted = "Yes"
	        		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
			}
		}
	}
	return $eulaAccepted
}
#endregion EULA

#region main
# main script

Write-Host "xray by tdimli, v$version"

# validate cmdline
if (($Area -eq $null) -and ($Component -eq $null) -and ($Diagnostic -eq $null) -and ($SkipDiags -eq $false)) {
    ShowHelp
    return
}

# EULA
if ($AcceptEULA -eq $false) {
    $eulaAccepted = ShowEULAIfNeeded "xray" 0
    if($eulaAccepted -ne "Yes") {
        "EULA Declined"
        exit
    }
}

# validate DataPath, do it here before any file operations
$origDataPath = $DataPath
if(($DataPath.Length -eq 0) -or -not(Test-Path -Path $DataPath)) {
    $DataPath = (Get-Location).Path
}
else {
    $DataPath = Convert-Path $DataPath
}

InitGlobals $version $DataPath

LogWrite "xray by tdimli, v$version"

Write-Host "`r`nInitialising..."
foreach ($techarea in $TechAreas) {
    $version_name = $techarea + "_version"
    $techarea_version = (Get-Variable -Name $version_name).Value
    LogWrite " $techarea $techarea_version"
    XmlAddTechArea $techarea $techarea_version
}

# these splits are needed for TSS interoperability
if ($Area -ne $null) {
    $Area = $Area -split ","
    if (($Area -eq "all") -or ($Area -eq "*")) {
        $Area = $TechAreas
    }
}
if ($Component -ne $null) {
    $Component = $Component -split ","
    for ($i = 0; $i -lt $Component.Count; $i++) {
        $Component[$i] = $Component[$i].Replace(' ', '')
    }
}
if ($Diagnostic -ne $null) {
    $Diagnostic = $Diagnostic -split ","
}

# log parameters
LogWrite "Parameters:"
LogWrite " Area(s): $Area"
LogWrite " Component(s): $Component"
if(($Component -ne $null) -and ($Component.Count -gt 0)) {
    $ConvertedComponent = ValidateTssComponents $Component
    LogWrite "  after conversion: $ConvertedComponent"
    $Component = $ConvertedComponent
}
# handle "-component general"
for ($i = 0; $i -lt $Component.Count; $i++) {
    $Component[$i] = $Component[$i].Replace(' ', '')
    if ($Component[$i].ToLower() -eq "general") {
        $Area = $TechAreas
        $Components = $null
        LogWrite "  general specified, running with -Area All instead"
    }
}
LogWrite " Diagnostic(s): $Diagnostic"
LogWrite " Datapath: $DataPath"
if (!$DataPath.Equals($origDataPath)) {
    LogWrite "  Original Datapath: $origDataPath"
}
LogWrite " Offline: $Offline"
LogWrite " WaitBeforeClose: $WaitBeforeClose"
LogWrite " SkipDiags: $SkipDiags"
LogWrite " DevMode: $DevMode"
XmlAddParameters $Area $Component $Diagnostic $Offline $WaitBeforeClose $SkipDiags $DevMode

LogWrite "Log file: $logFile"
LogWrite "XML report: $xmlRptFile"

# collect basic system info
LogWrite "Collecting system info..."
AddSysInfo $Offline

# collect poolmon info
LogWrite "Collecting poolmon info..."
InitPoolmonData $Offline

# diagnostics
[System.Collections.Generic.List[String]] $executedDiags = New-Object "System.Collections.Generic.List[string]"

# check for Windows updates
$updateListsLastUpdatedDate = [datetime]::ParseExact($updateListsLastUpdated, "yyyyMMdd", $null)
Write-Host "Checking Windows Update status using update data v$updateListsLastUpdated "
LogWrite "Checking Windows Update status using update data v$updateListsLastUpdated"
$updateListsGracePeriod = 14 # days
if ((New-TimeSpan -Start $updateListsLastUpdatedDate -End $startTime).Days -gt $updateListsGracePeriod) {
    Write-Host "The update data is more than $updateListsGracePeriod days old, update status report may not be accurate." -ForegroundColor yellow
    LogWrite "The update data is more than $updateListsGracePeriod days old, update status report may not be accurate."
}
Write-Host "Looking for missing updates... " -NoNewline
LogWrite "Looking for missing updates..."
RunDiag CheckUpdateStatus
Write-Host ""
if ($NumMissingUpdates -eq 0) {
    Write-Host "System up-to-date (last installed update: $($installedUpdates[0].HotfixId))`r`n"
    LogWrite "System up-to-date (last installed update: $($installedUpdates[0].HotfixId))"
}
elseif ($NumMissingUpdates -lt 0) {
    Write-Host "Update status cannot be determined, please check that you have latest updates installed.`r`n" -ForegroundColor yellow
    LogWrite "Update status cannot be determined, please check that you have latest updates installed."
}
elseif ($numIssues -eq 0) {
    Write-Host "This system is missing $NumMissingUpdates update(s), please install below Windows update to resolve:" -ForegroundColor yellow
    Write-Host "  $($MissingUpdates[0].heading)`r`n"
    LogWrite "This system is missing $NumMissingUpdates update(s), please install Windows update $($MissingUpdates[0].id) to resolve."
}

if ($SkipDiags) {
    LogWrite "Diagnostics skipped on user request"
}
else {
    # run diagnostics
    Write-Host "Starting diagnostics, checking for known issues..."
    LogWrite "Starting diagnostics, checking for known issues..."
    if ($Area) {
        RunDiagForArea $Area
    } elseif ($Component) {
        RunDiagForComponent $Component
    } elseif ($Diagnostic) {
        RunDiag $Diagnostic
    }
}

XmlMarkComplete

# log/show summary
$stats1 = "$numDiagsRun diagnostic check(s) run (R:$numDiagsSuccess S:$numDiagsSkipped F:$numDiagsFailed)"
$stats2 = "$numIssues issue(s) found"
if(Test-Path -Path $issuesFile){
    $stats2 += ", details saved to $issuesFile"
}
elseif(Test-Path -Path $infoFile) {
    $stats2 += ", details saved to $infoFile"
}

LogWrite $stats1
LogWrite $stats2
LogWrite "Diagnostics completed."

Write-Host
Write-Host $stats1
Write-Host $stats2
Write-Host "Diagnostics completed.`r`n"

if($WaitBeforeClose -and $issueShown) {
    # wait for user
    pause
}
#endregion main

# SIG # Begin signature block
# MIInzQYJKoZIhvcNAQcCoIInvjCCJ7oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBswThAIAWo6653
# qCdkijsYrq7Lf52E84opvAzktumCHaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZojCCGZ4CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgxtYi73HB
# zoEXTVnsF3NyehpnV2rS4C6GBU+AKgmG9PIwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCchrM3sy90VPrU3pvr6NH+5Wurc7ki45pJqOommRjv
# Y4bUesIBdpSuP++4eNLvAyLyzowbtYVcLRwSst0xBSB+wFi2L2gSQvmvNWN1dVOB
# wO41H0XE/3hs8M9ZpTPlpWHwO0X1qu2QkVPa7MynCF3HaP2P/wR8ETAcdDG2lW5z
# AGHplrNuhGfrUMn3NA66A5djilhzZhWVF7J6F1uJcXNnYbsxXBXlEPC1m80GeUy3
# g2RiNiTiXvaPAiiu2ySBXKvwcHYhfBlEWKnxCtosEDdYIOyeFw2ddEzcg8bQu0S0
# /+frfE78zbHTTMQ4I+Plb3fVgeoG44w2kgzw4oDxcQy9oYIXLDCCFygGCisGAQQB
# gjcDAwExghcYMIIXFAYJKoZIhvcNAQcCoIIXBTCCFwECAQMxDzANBglghkgBZQME
# AgEFADCCAVkGCyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIPyAy3d4up4COLdZv/KWylWFzPNUfyIaFL7cubH4
# ftXtAgZjT+tCuYwYEzIwMjIxMDI2MTQyOTUxLjA4NFowBIACAfSggdikgdUwgdIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046OEQ0MS00QkY3LUIzQjcxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2WgghF7MIIHJzCCBQ+gAwIBAgITMwAAAbP+Jc4pGxuK
# HAABAAABszANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMjA5MjAyMDIyMDNaFw0yMzEyMTQyMDIyMDNaMIHSMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHwPuuYY
# gK4ssGCCsr2N7eElKlz0JPButr/gpvZ67kNlHqgKAW0JuKAy4xxjfVCUev/eS5aE
# cnTmfj63fvs8eid0MNvP91T6r819dIqvWnBTY4vKVjSzDnfVVnWxYB3IPYRAITNN
# 0sPgolsLrCYAKieIkECq+EPJfEnQ26+WTvit1US+uJuwNnHMKVYRri/rYQ2P8fKI
# JRfcxkadj8CEPJrN+lyENag/pwmA0JJeYdX1ewmBcniX4BgCBqoC83w34Sk37RMS
# sKAU5/BlXbVyDu+B6c5XjyCYb8Qx/Qu9EB6KvE9S76M0HclIVtbVZTxnnGwsSg2V
# 7fmJx0RP4bfAM2ZxJeVBizi33ghZHnjX4+xROSrSSZ0/j/U7gYPnhmwnl5SctprB
# c7HFPV+BtZv1VGDVnhqylam4vmAXAdrxQ0xHGwp9+ivqqtdVVDU50k5LUmV6+Glm
# WyxIJUOh0xzfQjd9Z7OfLq006h+l9o+u3AnS6RdwsPXJP7z27i5AH+upQronsemQ
# 27R9HkznEa05yH2fKdw71qWivEN+IR1vrN6q0J9xujjq77+t+yyVwZK4kXOXAQ2d
# T69D4knqMlFSsH6avnXNZQyJZMsNWaEt3rr/8Nr9gGMDQGLSFxi479Zy19aT/fHz
# sAtu2ocBuTqLVwnxrZyiJ66P70EBJKO5eQECAwEAAaOCAUkwggFFMB0GA1UdDgQW
# BBTQGl3CUWdSDBiLOEgh/14F3J/DjTAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
# MCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3Rh
# bXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEA
# Woa7N86wCbjAAl8RGYmBZbS00ss+TpViPnf6EGZQgKyoaCP2hc01q2AKr6Me3TcS
# JPNWHG14pY4uhMzHf1wJxQmAM5Agf4aO7KNhVV04Jr0XHqUjr3T84FkWXPYMO4ul
# QG6j/+/d7gqezjXaY7cDqYNCSd3F4lKx0FJuQqpxwHtML+a4U6HODf2Z+KMYgJzW
# RnOIkT/od0oIXyn36+zXIZRHm7OQij7ryr+fmQ23feF1pDbfhUSHTA9IT50KCkpG
# p/GBiwFP/m1drd7xNfImVWgb2PBcGsqdJBvj6TX2MdUHfBVR+We4A0lEj1rNbCpg
# UoNtlaR9Dy2k2gV8ooVEdtaiZyh0/VtWfuQpZQJMDxgbZGVMG2+uzcKpjeYANMlS
# KDhyQ38wboAivxD4AKYoESbg4Wk5xkxfRzFqyil2DEz1pJ0G6xol9nci2Xe8LkLd
# ET3u5RGxUHam8L4KeMW238+RjvWX1RMfNQI774ziFIZLOR+77IGFcwZ4FmoteX1x
# 9+Bg9ydEWNBP3sZv9uDiywsgW40k00Am5v4i/GGiZGu1a4HhI33fmgx+8blwR5nt
# 7JikFngNuS83jhm8RHQQdFqQvbFvWuuyPtzwj5q4SpjO1SkOe6roHGkEhQCUXdQM
# nRIwbnGpb/2EsxadokK8h6sRZMWbriO2ECLQEMzCcLAwggdxMIIFWaADAgECAhMz
# AAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0z
# MDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP9
# 7pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMM
# tY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gm
# U3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130
# /o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP
# 3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7
# vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+A
# utuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz
# 1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6
# EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/Zc
# UlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZy
# acaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJ
# KwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVd
# AF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8G
# CCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3Mv
# UmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQC
# BAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYD
# VR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZF
# aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcw
# AoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJB
# dXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cB
# MSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7
# bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/
# SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2
# EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2Fz
# Lixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0
# /fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9
# swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJ
# Xk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+
# pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW
# 4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N
# 7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC1zCCAkACAQEwggEAoYHYpIHVMIHSMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNy
# b3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOjhENDEtNEJGNy1CM0I3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBxi0Tolt0eEqXCQl4qgJXU
# kiQOYaCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqG
# SIb3DQEBBQUAAgUA5wOjvjAiGA8yMDIyMTAyNjIwMTcwMloYDzIwMjIxMDI3MjAx
# NzAyWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDnA6O+AgEAMAoCAQACAhrEAgH/
# MAcCAQACAhFTMAoCBQDnBPU+AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEA
# b6elv9Wk4jlxjZ+StWQgpmnuq90KA68mjgBiCZfaKF/gT6cjMcdh5+zAKXtfEIHg
# OkwPwY2LvtGTMwhMeXhpl/QwDlkgAlRjwwwa1JJbeiD5Sq1YGQgB7tmozxD58VtC
# 7M5+IcnizJyN4UBFziiSplAmmYm7gJV/Vm/C6TE7mBMxggQNMIIECQIBATCBkzB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbP+Jc4pGxuKHAABAAAB
# szANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MC8GCSqGSIb3DQEJBDEiBCC/827GZBXFVgImRM89DaYU4KmPR5S2fHIGdTH0vrMx
# 0TCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIIahM9UqENIHtkbTMlBlQzaO
# T+WXXMkaHoo6GfvqT79CMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGz/iXOKRsbihwAAQAAAbMwIgQgDiaL4TziB9qFiVntb0DoyY+P
# NeWGSoKV6FVwY5ZMJacwDQYJKoZIhvcNAQELBQAEggIAg9YYReR4RrL6gDkVMiKS
# A3Nhq15BaEGBaUW73KoWidKcffNZTtm+8IntWjZv9nfVyNVyaAHaJT+2ZqQaamsU
# XqPSZ+HxD/f9XultCyvbZ+BjWm+IjwfH//kelJrcB+mdCjMhpYplJFhMu2lJ/GjA
# IkULsRzdu7g/0CAH0YS4trFUNPlW0m9mAtiNtv5Uf9G4oaIof2ioPlxFeulLS7vd
# LO/wZyZVlh7H/mZRYKzEg2GYKTKVIPcMJW1x9OQO8fKEk75xr9TP9UrGMDeRWqQH
# PDTyUK0MqpkATcgOEwiRptNAMF7/s1ltQDHUXxvFn6H8gCCC3Jss+kGlBO+obddw
# UDtaIyD2AjA2a/pVIjcG7KWA6vUG8LSsl1+3OqN9opc+U1j4kuWbEMvmWy1K3MFo
# Qukv1k9ecw/1EXQRFUHWDZ+e5xlpkRfFBvD7kwMXcQfWio2pZUnDWy5aMF/XzS3P
# kYnR6xlIdSho6D1EXZeeWJokCGiVIPntf+TbBe15Ai9TWRsShWcDIkVQOg/ZIzUw
# IDlCFQv1OFZnaKOQFevUEuDMQpz2jW4GBZqe4KgqthCEn1smspdJCCEY3TVwV0Ho
# AY1K2Nc+xXWtU/fk6A5zX5BOWiKtbiFw5JifMptnG6K4GZvCYATaP6enTZrcQXBe
# q4LqhdRUYbgw+2I/7d+iuAA=
# SIG # End signature block
