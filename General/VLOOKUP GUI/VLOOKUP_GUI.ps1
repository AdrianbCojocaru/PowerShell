<#
.SYNOPSIS
	This script geenrates a GUI and performs a VLOOKUP between two  Excel sheets.
    You can select the files, the worksheets and the keys.
.OUTPUTS
    *.xlsx file under "$PSScriptRoot\${DateTime}.xlsx"
.NOTES
  Version:        1.2
  Author:         Adrian
  Version 1.1:  Added Required Modules functionality
  Version 1.2:  Added DPI awareness
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)]
    [switch] $IM
)
#Region ================================[Variables]================================

# Define the Console Script name (without extension).
[string]$ConsoleScriptName = "VLOOKUP_GUI" # ! Change THIS!
# Define the GlobalOutput variable.
[array]$Global:Output = @()
# Exit code variable.
[int32]$Global:ExitCode = 0
# Define log file parent folder.
[string]$LogFolder = $env:temp
#EndRegion =============================[Variables]================================

#Region ================================[INIT]=====================================
# Configure error action variable to STOP on all errors.
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
# Force current script culture. This helps avoid issues with date/time.
# !Set to specific culture if running DOS commands.
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
# If the log parent folder doesn't exist, try to create it.
if (!(Test-Path -Path $LogFolder)) {
    try {
        New-Item -Path $LogFolder -ItemType 'Directory' -EA 'Stop' | Out-Null
    }
    catch {
        throw "Cannot create log folder [$LogFolder]."
    }
}
# Define the script log file full path.
[string]$Global:LogFile = "$LogFolder\SCRIPT-$($ConsoleScriptName -replace ('\s+', '')).log"
# Remove the log file if it already exists.
if (Test-Path -Path $Global:LogFile) { Remove-Item -Path $Global:LogFile -Force }

#EndRegion =============================[INIT]=====================================
$WriteHost = $true
Add-Type -AssemblyName PresentationCore, PresentationFramework
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="Window"
    FontSize="18" Title="VLOOKUP"
    Height="800" Width="600" ShowInTaskbar = "True"
    SizeToContent="WidthAndHeight">
    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="20"/>
            <ColumnDefinition Width="auto"/>
            <ColumnDefinition Width="auto"/>
            <ColumnDefinition Width="20"/>
            <ColumnDefinition Width="auto"/>
            <ColumnDefinition Width="auto"/>
            <ColumnDefinition Width="*"/>
            <ColumnDefinition Width="20"/>
        </Grid.ColumnDefinitions>
        <Grid.RowDefinitions>
            <RowDefinition Height="20"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="5"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Column="1" Grid.Row="1" FontWeight="Black"
                   Text="File 1:" Margin="0,0,0,5" />
        <Button Grid.Column="2" Grid.Row="1"
                x:Name="File1BrowseButton" Content="Browse" Margin="0,0,0,5" />
        <TextBox Grid.Column="1" Grid.Row="2" Grid.ColumnSpan="2" MaxWidth="600"
                 x:Name="File1PathText" IsReadOnly="True" Margin="0,0,0,5" />
        <TextBlock Grid.Column="1" Grid.Row="3"
                   Text="Select Sheet:" Margin="0,0,0,5" />
        <ComboBox Grid.Column="2" Grid.Row="3"
                  x:Name="File1SelectSheet" Margin="0,0,0,5" />
        <TextBlock Grid.Column="1" Grid.Row="4"
                   Text="Select Primary Key: " Margin="0,0,0,5" />
        <ComboBox Grid.Column="2" Grid.Row="4"
                  x:Name="File1SelectKey" Margin="0,0,0,5" />
        <TextBlock Grid.Column="1" Grid.Row="5"
                   Text="Select Columns:" Margin="0,0,0,5" />
        <ListBox Grid.Column="1" Grid.Row="6"  Grid.ColumnSpan="2"
            ScrollViewer.VerticalScrollBarVisibility="Visible"
            x:Name="File1Columns" SelectionMode="Multiple" Margin="0,0,0,5" />

        <TextBlock Grid.Column="4" Grid.Row="1" FontWeight="Black"
                   Text="File 2:" Margin="0,0,0,5" />
        <Button Grid.Column="5" Grid.Row="1"
                x:Name="File2BrowseButton" Content="Browse" Margin="0,0,0,5" />
        <TextBox Grid.Column="4" Grid.Row="2" Grid.ColumnSpan="2" MaxWidth="600"
                 x:Name="File2PathText" IsReadOnly="True" Margin="0,0,0,5" />
        <TextBlock Grid.Column="4" Grid.Row="3"
                   Text="Select Sheet:" Margin="0,0,0,5" />
        <ComboBox Grid.Column="5" Grid.Row="3"
                  x:Name="File2SelectSheet" Margin="0,0,0,5" />
        <TextBlock Grid.Column="4" Grid.Row="4"
                   Text="Select Primary Key: " Margin="0,0,0,5" />
        <ComboBox Grid.Column="5" Grid.Row="4"
                  x:Name="File2SelectKey" Margin="0,0,0,5" />
        <TextBlock Grid.Column="4" Grid.Row="5"
                   Text="Select Columns:" Margin="0,0,0,5" />
        <ListBox Grid.Column="4" Grid.Row="6"  Grid.ColumnSpan="2"
            ScrollViewer.VerticalScrollBarVisibility="Visible"
            x:Name="File2Columns"  SelectionMode="Multiple" Margin="0,0,0,5" />

        <Button Grid.Column="2" Grid.Row="8" Grid.ColumnSpan="3"
            x:Name="ExportButton" Content="Export" Margin="0,0,0,5"  Visibility="Hidden"/>
        <ProgressBar  Grid.Column="3" Grid.Row="9"
            Minimum="0" Maximum="5" x:Name="ProgressBar"/>
    </Grid>
</Window>
"@

$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$Window = [Windows.Markup.XamlReader]::Load( $reader )

function Get-FileName {
    <#
.SYNOPSIS
   Show an Open File Dialog and return the file selected by the user

.PARAMETER WindowTitle
   Message Box title
   Mandatory - [String]

.PARAMETER InitialDirectory
   Initial Directory for browsing
   Mandatory - [string]

.PARAMETER Filter
   Filter to apply
   Optional - [string]

.PARAMETER AllowMultiSelect
   Allow multi file selection
   Optional - switch

.EXAMPLE
   Get-FileName -WindowTitle MyDialogBox -InitialDirectory c:\temp
   Choose only one file. All files extensions are allowed

.EXAMPLE
   Get-FileName -WindowTitle MyDialogBox -InitialDirectory c:\temp -AllowMultiSelect
   Choose multiple files. All files are allowed

.EXAMPLE
   Get-FileName -WindowTitle MyDialogBox -InitialDirectory c:\temp -AllowMultiSelect -Filter "text file (*.txt) | *.txt"
   Choose multiple files but only one specific extension (here : .txt) is allowed

.EXAMPLE
   Get-FileName -WindowTitle MyDialogBox -InitialDirectory c:\temp -AllowMultiSelect -Filter "Text files (*.txt)|*.txt| csv files (*.csv)|*.csv | log files (*.log) | *.log"
   Choose multiple file with the same extension

.EXAMPLE
   Get-FileName -WindowTitle MyDialogBox -InitialDirectory c:\temp -AllowMultiSelect -Filter "selected extensions (*.txt, *.log) | *.txt;*.log"
   Choose multiple file with different extensions
   Nota :It's important to have no white space in the extension name if you want to show them

.OUTPUTS
   System.String

.NOTESs
  Version         : 1.0
  Author          : O. FERRIERE
  Creation Date   : 11/09/2019
  Purpose/Change  : Initial development

  Based on different pages :
   mainly based on https://blog.danskingdom.com/powershell-multi-line-input-box-dialog-open-file-dialog-folder-browser-dialog-input-box-and-message-box/
   https://code.adonline.id.au/folder-file-browser-dialogues-powershell/
   https://thomasrayner.ca/open-file-dialog-box-in-powershell/
#>
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # WindowsTitle help description
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Message Box Title",
            Position = 0)]
        [String]$WindowTitle,

        # InitialDirectory help description
        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Initial Directory for browsing",
            Position = 1)]
        [String]$InitialDirectory,

        # Filter help description
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Filter to apply",
            Position = 2)]
        [String]$Filter = "All files (*.*)|*.*",

        # AllowMultiSelect help description
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Allow multi files selection",
            Position = 3)]
        [Switch]$AllowMultiSelect
    )

    # Load Assembly
    Add-Type -AssemblyName System.Windows.Forms

    # Open Class
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog

    # Define Title
    $OpenFileDialog.Title = $WindowTitle

    # Define Initial Directory
    if (-Not [String]::IsNullOrWhiteSpace($InitialDirectory)) {
        $OpenFileDialog.InitialDirectory = $InitialDirectory
    }

    # Define Filter
    $OpenFileDialog.Filter = $Filter

    # Check If Multi-select if used
    if ($AllowMultiSelect) {
        $OpenFileDialog.MultiSelect = $true
    }
    $OpenFileDialog.ShowHelp = $true    # Without this line the ShowDialog() function may hang depending on system configuration and running from console vs. ISE.
    $OpenFileDialog.ShowDialog() | Out-Null
    if ($AllowMultiSelect) {
        return $OpenFileDialog.Filenames
    }
    else {
        Write-Log "Opening file: $($OpenFileDialog.Filename)"
        return $OpenFileDialog.Filename
    }
}
function Join-Object {
    <#
    .SYNOPSIS
        Join data from two sets of objects based on a common value

    .DESCRIPTION
        Join data from two sets of objects based on a common value

        For more details, see the accompanying blog post:
            http://ramblingcookiemonster.github.io/Join-Object/

        For even more details,  see the original code and discussions that this borrows from:
            Dave Wyatt's Join-Object - http://powershell.org/wp/forums/topic/merging-very-large-collections
            Lucio Silveira's Join-Object - http://blogs.msdn.com/b/powershell/archive/2012/07/13/join-object.aspx

    .PARAMETER Left
        'Left' collection of objects to join.  You can use the pipeline for Left.

        The objects in this collection should be consistent.
        We look at the properties on the first object for a baseline.

    .PARAMETER Right
        'Right' collection of objects to join.

        The objects in this collection should be consistent.
        We look at the properties on the first object for a baseline.

    .PARAMETER LeftJoinProperty
        Property on Left collection objects that we match up with RightJoinProperty on the Right collection

    .PARAMETER RightJoinProperty
        Property on Right collection objects that we match up with LeftJoinProperty on the Left collection

    .PARAMETER LeftProperties
        One or more properties to keep from Left.  Default is to keep all Left properties (*).

        Each property can:
            - Be a plain property name like "Name"
            - Contain wildcards like "*"
            - Be a hashtable like @{Name="Product Name";Expression={$_.Name}}.
                 Name is the output property name
                 Expression is the property value ($_ as the current object)

                 Alternatively, use the Suffix or Prefix parameter to avoid collisions
                 Each property using this hashtable syntax will be excluded from suffixes and prefixes

    .PARAMETER RightProperties
        One or more properties to keep from Right.  Default is to keep all Right properties (*).

        Each property can:
            - Be a plain property name like "Name"
            - Contain wildcards like "*"
            - Be a hashtable like @{Name="Product Name";Expression={$_.Name}}.
                 Name is the output property name
                 Expression is the property value ($_ as the current object)

                 Alternatively, use the Suffix or Prefix parameter to avoid collisions
                 Each property using this hashtable syntax will be excluded from suffixes and prefixes

    .PARAMETER Prefix
        If specified, prepend Right object property names with this prefix to avoid collisions

        Example:
            Property Name                   = 'Name'
            Suffix                          = 'j_'
            Resulting Joined Property Name  = 'j_Name'

    .PARAMETER Suffix
        If specified, append Right object property names with this suffix to avoid collisions

        Example:
            Property Name                   = 'Name'
            Suffix                          = '_j'
            Resulting Joined Property Name  = 'Name_j'

    .PARAMETER Type
        Type of join.  Default is AllInLeft.

        AllInLeft will have all elements from Left at least once in the output, and might appear more than once
          if the where clause is true for more than one element in right, Left elements with matches in Right are
          preceded by elements with no matches.
          SQL equivalent: outer left join (or simply left join)

        AllInRight is similar to AllInLeft.

        OnlyIfInBoth will cause all elements from Left to be placed in the output, only if there is at least one
          match in Right.
          SQL equivalent: inner join (or simply join)

        AllInBoth will have all entries in right and left in the output. Specifically, it will have all entries
          in right with at least one match in left, followed by all entries in Right with no matches in left,
          followed by all entries in Left with no matches in Right.
          SQL equivalent: full join

    .EXAMPLE
        #
        #Define some input data.

        $l = 1..5 | Foreach-Object {
            [pscustomobject]@{
                Name = "jsmith$_"
                Birthday = (Get-Date).adddays(-1)
            }
        }

        $r = 4..7 | Foreach-Object{
            [pscustomobject]@{
                Department = "Department $_"
                Name = "Department $_"
                Manager = "jsmith$_"
            }
        }

        #We have a name and Birthday for each manager, how do we find their department, using an inner join?
        Join-Object -Left $l -Right $r -LeftJoinProperty Name -RightJoinProperty Manager -Type OnlyIfInBoth -RightProperties Department


            # Name    Birthday             Department
            # ----    --------             ----------
            # jsmith4 4/14/2015 3:27:22 PM Department 4
            # jsmith5 4/14/2015 3:27:22 PM Department 5

    .EXAMPLE
        #
        #Define some input data.

        $l = 1..5 | Foreach-Object {
            [pscustomobject]@{
                Name = "jsmith$_"
                Birthday = (Get-Date).adddays(-1)
            }
        }

        $r = 4..7 | Foreach-Object{
            [pscustomobject]@{
                Department = "Department $_"
                Name = "Department $_"
                Manager = "jsmith$_"
            }
        }

        #We have a name and Birthday for each manager, how do we find all related department data, even if there are conflicting properties?
        $l | Join-Object -Right $r -LeftJoinProperty Name -RightJoinProperty Manager -Type AllInLeft -Prefix j_

            # Name    Birthday             j_Department j_Name       j_Manager
            # ----    --------             ------------ ------       ---------
            # jsmith1 4/14/2015 3:27:22 PM
            # jsmith2 4/14/2015 3:27:22 PM
            # jsmith3 4/14/2015 3:27:22 PM
            # jsmith4 4/14/2015 3:27:22 PM Department 4 Department 4 jsmith4
            # jsmith5 4/14/2015 3:27:22 PM Department 5 Department 5 jsmith5

    .EXAMPLE
        #
        #Hey!  You know how to script right?  Can you merge these two CSVs, where Path1's IP is equal to Path2's IP_ADDRESS?

        #Get CSV data
        $s1 = Import-CSV $Path1
        $s2 = Import-CSV $Path2

        #Merge the data, using a full outer join to avoid omitting anything, and export it
        Join-Object -Left $s1 -Right $s2 -LeftJoinProperty IP_ADDRESS -RightJoinProperty IP -Prefix 'j_' -Type AllInBoth |
            Export-CSV $MergePath -NoTypeInformation

    .EXAMPLE
        #
        # "Hey Warren, we need to match up SSNs to Active Directory users, and check if they are enabled or not.
        #  I'll e-mail you an unencrypted CSV with all the SSNs from gmail, what could go wrong?"

        # Import some SSNs.
        $SSNs = Import-CSV -Path D:\SSNs.csv

        #Get AD users, and match up by a common value, samaccountname in this case:
        Get-ADUser -Filter "samaccountname -like 'wframe*'" |
            Join-Object -LeftJoinProperty samaccountname -Right $SSNs `
                        -RightJoinProperty samaccountname -RightProperties ssn `
                        -LeftProperties samaccountname, enabled, objectclass

    .NOTES
        This borrows from:
            Dave Wyatt's Join-Object - http://powershell.org/wp/forums/topic/merging-very-large-collections/
            Lucio Silveira's Join-Object - http://blogs.msdn.com/b/powershell/archive/2012/07/13/join-object.aspx

        Changes:
            Always display full set of properties
            Display properties in order (left first, right second)
            If specified, add suffix or prefix to right object property names to avoid collisions
            Use a hashtable rather than ordereddictionary (avoid case sensitivity)

    .LINK
        http://ramblingcookiemonster.github.io/Join-Object/

    .FUNCTIONALITY
        PowerShell Language

    #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeLine = $true)]
        [object[]] $Left,

        # List to join with $Left
        [Parameter(Mandatory = $true)]
        [object[]] $Right,

        [Parameter(Mandatory = $true)]
        [string] $LeftJoinProperty,

        [Parameter(Mandatory = $true)]
        [string] $RightJoinProperty,

        [object[]]$LeftProperties = '*',

        # Properties from $Right we want in the output.
        # Like LeftProperties, each can be a plain name, wildcard or hashtable. See the LeftProperties comments.
        [object[]]$RightProperties = '*',

        [validateset( 'AllInLeft', 'OnlyIfInBoth', 'AllInBoth', 'AllInRight')]
        [Parameter(Mandatory = $false)]
        [string]$Type = 'AllInLeft',

        [string]$Prefix,
        [string]$Suffix
    )
    Begin {
        function AddItemProperties($Item, $properties, $hash) {
            if ($null -eq $Item) {
                return
            }

            foreach ($property in $properties) {
                $propertyHash = $property -as [hashtable]
                if ($null -ne $propertyHash) {
                    $hashName = $propertyHash["name"] -as [string]
                    $expression = $propertyHash["expression"] -as [scriptblock]

                    $expressionValue = $expression.Invoke($Item)[0]

                    $hash[$hashName] = $expressionValue
                }
                else {
                    foreach ($ItemProperty in $Item.psobject.Properties) {
                        if ($ItemProperty.Name -like $property) {
                            $hash[$ItemProperty.Name] = $ItemProperty.Value
                        }
                    }
                }
            }
        }

        function TranslateProperties {
            [cmdletbinding()]
            param(
                [object[]]$Properties,
                [psobject]$RealObject,
                [string]$Side)

            foreach ($Prop in $Properties) {
                $propertyHash = $Prop -as [hashtable]
                if ($null -ne $propertyHash) {
                    $hashName = $propertyHash["name"] -as [string]
                    $expression = $propertyHash["expression"] -as [scriptblock]

                    $ScriptString = $expression.tostring()
                    if ($ScriptString -notmatch 'param\(') {
                        Write-Verbose "Property '$HashName'`: Adding param(`$_) to scriptblock '$ScriptString'"
                        $Expression = [ScriptBlock]::Create("param(`$_)`n $ScriptString")
                    }

                    $Output = @{Name = $HashName; Expression = $Expression }
                    Write-Verbose "Found $Side property hash with name $($Output.Name), expression:`n$($Output.Expression | out-string)"
                    $Output
                }
                else {
                    foreach ($ThisProp in $RealObject.psobject.Properties) {
                        if ($ThisProp.Name -like $Prop) {
                            Write-Verbose "Found $Side property '$($ThisProp.Name)'"
                            $ThisProp.Name
                        }
                    }
                }
            }
        }

        function WriteJoinObjectOutput($leftItem, $rightItem, $leftProperties, $rightProperties) {
            $properties = @{}

            AddItemProperties $leftItem $leftProperties $properties
            AddItemProperties $rightItem $rightProperties $properties

            New-Object psobject -Property $properties
        }

        #Translate variations on calculated properties.  Doing this once shouldn't affect perf too much.
        foreach ($Prop in @($LeftProperties + $RightProperties)) {
            if ($Prop -as [hashtable]) {
                foreach ($variation in ('n', 'label', 'l')) {
                    if (-not $Prop.ContainsKey('Name') ) {
                        if ($Prop.ContainsKey($variation) ) {
                            $Prop.Add('Name', $Prop[$Variation])
                        }
                    }
                }
                if (-not $Prop.ContainsKey('Name') -or $Prop['Name'] -like $null ) {
                    Throw "Property is missing a name`n. This should be in calculated property format, with a Name and an Expression:`n@{Name='Something';Expression={`$_.Something}}`nAffected property:`n$($Prop | out-string)"
                }


                if (-not $Prop.ContainsKey('Expression') ) {
                    if ($Prop.ContainsKey('E') ) {
                        $Prop.Add('Expression', $Prop['E'])
                    }
                }

                if (-not $Prop.ContainsKey('Expression') -or $Prop['Expression'] -like $null ) {
                    Throw "Property is missing an expression`n. This should be in calculated property format, with a Name and an Expression:`n@{Name='Something';Expression={`$_.Something}}`nAffected property:`n$($Prop | out-string)"
                }
            }
        }

        $leftHash = @{}
        $rightHash = @{}

        # Hashtable keys can't be null; we'll use any old object reference as a placeholder if needed.
        $nullKey = New-Object psobject

        $bound = $PSBoundParameters.keys -contains "InputObject"
        if (-not $bound) {
            [System.Collections.ArrayList]$LeftData = @()
        }
    }
    Process {
        #We pull all the data for comparison later, no streaming
        if ($bound) {
            $LeftData = $Left
        }
        Else {
            foreach ($Object in $Left) {
                [void]$LeftData.add($Object)
            }
        }
    }
    End {
        foreach ($Item in $Right) {
            $key = $Item.$RightJoinProperty

            if ($null -eq $key) {
                $key = $nullKey
            }

            $bucket = $rightHash[$key]

            if ($null -eq $bucket) {
                $bucket = New-Object System.Collections.ArrayList
                $rightHash.Add($key, $bucket)
            }

            $null = $bucket.Add($Item)
        }

        foreach ($Item in $LeftData) {
            $key = $Item.$LeftJoinProperty

            if ($null -eq $key) {
                $key = $nullKey
            }

            $bucket = $leftHash[$key]

            if ($null -eq $bucket) {
                $bucket = New-Object System.Collections.ArrayList
                $leftHash.Add($key, $bucket)
            }

            $null = $bucket.Add($Item)
        }

        $LeftProperties = TranslateProperties -Properties $LeftProperties -Side 'Left' -RealObject $LeftData[0]
        $RightProperties = TranslateProperties -Properties $RightProperties -Side 'Right' -RealObject $Right[0]

        #I prefer ordered output. Left properties first.
        [string[]]$AllProps = $LeftProperties

        #Handle prefixes, suffixes, and building AllProps with Name only
        $RightProperties = foreach ($RightProp in $RightProperties) {
            if (-not ($RightProp -as [Hashtable])) {
                Write-Verbose "Transforming property $RightProp to $Prefix$RightProp$Suffix"
                @{
                    Name       = "$Prefix$RightProp$Suffix"
                    Expression = [scriptblock]::create("param(`$_) `$_.'$RightProp'")
                }
                $AllProps += "$Prefix$RightProp$Suffix"
            }
            else {
                Write-Verbose "Skipping transformation of calculated property with name $($RightProp.Name), expression:`n$($RightProp.Expression | out-string)"
                $AllProps += [string]$RightProp["Name"]
                $RightProp
            }
        }

        $AllProps = $AllProps | Select-Object -Unique

        Write-Verbose "Combined set of properties: $($AllProps -join ', ')"

        foreach ( $entry in $leftHash.GetEnumerator() ) {
            $key = $entry.Key
            $leftBucket = $entry.Value

            $rightBucket = $rightHash[$key]

            if ($null -eq $rightBucket) {
                if ($Type -eq 'AllInLeft' -or $Type -eq 'AllInBoth') {
                    foreach ($leftItem in $leftBucket) {
                        WriteJoinObjectOutput $leftItem $null $LeftProperties $RightProperties | Select-Object $AllProps
                    }
                }
            }
            else {
                foreach ($leftItem in $leftBucket) {
                    foreach ($rightItem in $rightBucket) {
                        WriteJoinObjectOutput $leftItem $rightItem $LeftProperties $RightProperties | Select-Object $AllProps
                    }
                }
            }
        }

        if ($Type -eq 'AllInRight' -or $Type -eq 'AllInBoth') {
            foreach ($entry in $rightHash.GetEnumerator()) {
                $key = $entry.Key
                $rightBucket = $entry.Value

                $leftBucket = $leftHash[$key]

                if ($null -eq $leftBucket) {
                    foreach ($rightItem in $rightBucket) {
                        WriteJoinObjectOutput $null $rightItem $LeftProperties $RightProperties | Select-Object $AllProps
                    }
                }
            }
        }
    }
}
function Update-Box {
    <#
.SYNOPSIS
   Write data into a WPF ListBox or ListBox

.PARAMETER Box
   Name of the Box
   Mandatory - [String]

.PARAMETER  DataSource
   The data to be written
   Mandatory - [string]
.EXAMPLE
   Update-Box -Box "Box1" -DataSource "Item 1"
   #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)] $Box,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        $DataSource
    )
    $Box.Items.Clear()
    try {
        $Box.SelectedIndex = 0
        $DataSource | ForEach-Object {
            $Box.Items.Add($_)
        }
    }
    catch {
        $Box.Items.Add("Check the excel file. Empty/Invalid.")
    }
}

function Get-LeafProperty {
    <#
.SYNOPSIS
  Gets all leaf properties in a given object's hierarchy

.PARAMETER InputObject
   The object to be processed
   Mandatory - [Object]

.PARAMETER  NamePath
   The name of the property containing the values
   Not mandatory - [string]
.EXAMPLE
   Get-LeafProperty $str
   #>
    param(
        [Parameter(ValueFromPipeline)] [object] $InputObject,
        [string] $NamePath
    )
    process {
        if ($null -eq $InputObject -or $InputObject -is [DbNull] -or $InputObject.GetType().IsPrimitive -or $InputObject.GetType() -in [string], [datetime], [datetimeoffset], [decimal], [bigint]) {
            [pscustomobject] @{ NamePath = $NamePath; Value = $InputObject }
        }
        elseif ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [System.Collections.IDictionary]) {
            $i = 0
            foreach ($o in $InputObject) { Get-LeafProperty $o ($NamePath + '[' + $i++ + ']') }
        }
        else {
            $props = if ($InputObject -is [System.Collections.IDictionary]) { $InputObject.GetEnumerator() } else { $InputObject.psobject.properties }
            $sep = '.' * ($NamePath -ne '')
            foreach ($p in $props) {
                Get-LeafProperty $p.Value ($NamePath + $sep + $p.Name)
            }
        }
    }
}

Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, Position = 0)]
        [string]
        $Message,
        [Parameter(Mandatory = $False, Position = 1)]
        [int32]
        $Severity = 1,
        [Parameter(Mandatory = $False, Position = 2)]
        [boolean]
        $WriteHost = $false
    )
    switch ($Severity) {
        1 { $Level = 'Info:' }
        2 { $Level = 'Warning:' }
        3 { $Level = 'Error:' }
        Default { $Level = '-----' }
    }
    $TimeStamp = (Get-Date).ToString("yyyy-MM-dd HH:mm K")
    $LogFilePath = $LogFile
    $Entry = "$TimeStamp $Level $Message"
    if ($LogFilePath) {
        try {
            Add-Content $LogFilePath -Value $Entry -Encoding UTF8 -EA Stop
        }
        catch {
            Write-Warning "Unable to access log file [$LogFilePath]"
        }
    }
    else {
        Write-Warning "Log file is missing."
    }
    # If the "$WriteHost" variable is set, output the log data to console also.
    if ($WriteHost) {
        # Only output using color options if running in a host which supports colors.
        If ($Host.UI.RawUI.ForegroundColor) {
            Switch ($Severity) {
                3 { Write-Host -Object $Entry -ForegroundColor 'Red' -BackgroundColor 'Black' }
                2 { Write-Host -Object $Entry -ForegroundColor 'Yellow' -BackgroundColor 'Black' }
                Default { Write-Host -Object $Entry }
            }
        }
        # If executing "powershell.exe -File <filename>.ps1 > log.txt",
        # then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
        Else {
            Write-Output -InputObject $Entry
        }
    }
}
function Initialize-ExternalModules {
    if ($IM -and ($RequiredModules.Count -gt 0)) {
        # Make sure the network connection uses TLS1.2. Required by PSGallery connection.
        Write-Log "Settings HTTPS security protocol to TLS 1.2."
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Log "Installing / Upgrading NuGet."
        $null = Install-PackageProvider -Name 'NuGet' -Scope 'AllUsers' -Force
        Write-Log "Setting PSGallery as a trusted repository."
        $null = Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
        Write-Log "Setting execution policy to 'Bypass' to be able to import modules."
        $null = Set-ExecutionPolicy -ExecutionPolicy 'Bypass' -Scope 'CurrentUser' -Force -Confirm:$false
        # Go through the list of required modules and try to install them if missing.
        foreach ($ModuleName in $RequiredModules) {
            try {
                Import-Module -Name $ModuleName -Force -EA 'Stop'
            }
            catch {
                Write-Log "Installing module '$ModuleName'."
                $null = Install-Module -Name $ModuleName -Scope 'AllUsers' -Force
                Write-Log "Importing module '$ModuleName'."
                $null = Import-Module -Name $ModuleName -Force
            }
        }
    }
    else {
        # Try to import each module to check if all is OK.
        foreach ($ModuleName in $RequiredModules) {
            try {
                Write-Log "Importing module '$ModuleName'."
                Import-Module -Name $ModuleName -Force -ErrorAction Stop
            }
            catch {
                Write-Log "Module '$ModuleName' is missing." 2 $WriteHost
                Write-Log "Please restart this script with ADMIN privileges and the '-IM' parameter to install the missing module." 2 $WriteHost
                Pause
                exit 1
            }
        }
    }
}
function Get-DPI {
    #Detect DPI so $ColumnsHeight scaling can be adjusted
    Add-Type @'
    using System;
    using System.Runtime.InteropServices;
    using System.Drawing;

    public class DPI {
      [DllImport("gdi32.dll")]
      static extern int GetDeviceCaps(IntPtr hdc, int nIndex);

      public enum DeviceCap {
      VERTRES = 10,
      DESKTOPVERTRES = 117
      }

      public static float scaling() {
      Graphics g = Graphics.FromHwnd(IntPtr.Zero);
      IntPtr desktop = g.GetHdc();
      int LogicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.VERTRES);
      int PhysicalScreenHeight = GetDeviceCaps(desktop, (int)DeviceCap.DESKTOPVERTRES);

      return (float)PhysicalScreenHeight / (float)LogicalScreenHeight;
      }
    }
'@ -ReferencedAssemblies 'System.Drawing.dll' -ErrorAction SilentlyContinue
    $DPIScale = [DPI]::scaling() * 100
    Write-Log "Current Scaling = $DPIScale"
    return $DPIScale
}

$File1BrowseButton = $Window.FindName('File1BrowseButton')
$File2BrowseButton = $Window.FindName('File2BrowseButton')
$File1PathText = $Window.FindName('File1PathText')
$File2PathText = $Window.FindName('File2PathText')
$File1SelectSheet = $Window.FindName('File1SelectSheet')
$File2SelectSheet = $Window.FindName('File2SelectSheet')
$File1SelectKey = $Window.FindName('File1SelectKey')
$File2SelectKey = $Window.FindName('File2SelectKey')
$File1Columns = $Window.FindName('File1Columns')
$File2Columns = $Window.FindName('File2Columns')
$ProgressBar = $Window.FindName('ProgressBar')
$ProgressBar.Visibility = 'Hidden'
$ExportButton = $Window.FindName('ExportButton')
$DPIscale = Get-DPI
$ColumnsHeight = 60000 / $DPIscale
Write-Log "Columns Height = $ColumnsHeight"
$File1BrowseButton.Add_Click( {
        # Read File data, populate the GUI
        Update-Box $File1Columns "Please wait..."
        try {
            $Global:File1Path = Get-FileName -WindowTitle 'Select the report' -InitialDirectory 'c:\' -Filter "Excel Workboox (*.xlsx)|*.xlsx| Excel 97-2003 Workboox (*.xls) | *.xls"
            $File1Columns.Height = $ColumnsHeight
            $File1PathText.Text = $File1Path
            #            $ScriptBlock = {
            $Global:File1Sheets = (Get-ExcelSheetInfo $File1PathText.Text).name
            Update-Box $File1SelectSheet $File1Sheets
            $Global:File1SheetTable = Import-Excel $File1PathText.Text -WorksheetName $File1SelectSheet.Text
            $Global:File1ColumnsName = Get-LeafProperty $File1SheetTable[0]
            Update-Box $File1SelectKey $File1ColumnsName.NamePath
            Update-Box $File1Columns $File1ColumnsName.NamePath
            #            }
            #            Start-ThreadJob -ScriptBlock $ScriptBlock | Wait-Job | Receive-Job6
            $ExportButton.Visibility = if ($File2PathText.Text) { "Visible" } else { "Hidden" }
        }
        catch {
            Update-Box $File1Columns "File 1: Invalid file sheet..."
        }
        $File1SelectSheet.Add_DropDownClosed({
                #               $ScriptBlock = {
                Update-Box $File1SelectKey "Please wait..."
                Update-Box $File1Columns "Please wait..."
                $Global:File1SheetTable = Import-Excel $File1PathText.Text -WorksheetName $File1SelectSheet.Text
                $Global:File1ColumnsName = Get-LeafProperty $File1SheetTable[0]
                Update-Box $File1SelectKey $File1ColumnsName.NamePath
                Update-Box $File1Columns $File1ColumnsName.NamePath
                #                }
                #                Start-Job -ScriptBlock $ScriptBlock
            })
    })

$File2BrowseButton.Add_Click( {
        # Read File data, populate the GUI
        Update-Box $File2Columns "Please wait..."
        try {
            $Global:File2Path = Get-FileName -WindowTitle 'Select the report' -InitialDirectory 'c:\' -Filter "Excel Workboox (*.xlsx)|*.xlsx| Excel 97-2003 Workboox (*.xls) | *.xls"
            $File2Columns.Height = $ColumnsHeight
            $File2PathText.Text = $File2Path
            #            $ScriptBlock = {
            $Global:File2Sheets = (Get-ExcelSheetInfo $File2PathText.Text).name
            Update-Box $File2SelectSheet $File2Sheets
            $Global:File2SheetTable = Import-Excel $File2PathText.Text -WorksheetName $File2SelectSheet.Text
            $Global:File2ColumnsName = Get-LeafProperty $File2SheetTable[0]
            Update-Box $File2SelectKey $File2ColumnsName.NamePath
            Update-Box $File2Columns $File2ColumnsName.NamePath
            $ExportButton.Visibility = if ($File1PathText.Text) { "Visible" } else { "Hidden" }
            #            }
            #            Start-Job -ScriptBlock $ScriptBlock
        }
        catch {
            Update-Box $File2Columns "File 1: Invalid file sheet..."
        }
        $File2SelectSheet.Add_DropDownClosed({
                #                $ScriptBlock = {
                Update-Box $File2SelectKey "Please wait..."
                Update-Box $File2Columns "Please wait..."
                $Global:File2SheetTable = Import-Excel $File2PathText.Text -WorksheetName $File2SelectSheet.Text
                $Global:File2ColumnsName = Get-LeafProperty $File2SheetTable[0]
                Update-Box $File2SelectKey $File2ColumnsName.NamePath
                Update-Box $File2Columns $File2ColumnsName.NamePath
                #                }
                #                Start-Job -ScriptBlock $ScriptBlock
            })
    })

$ExportButton.Add_Click( {
        # add both GUI keys to SelectedItems
        if ($File1Columns.SelectedItems -contains $File1SelectKey.SelectedItem) {
            ($File1Columns.SelectedItems).Remove($File1SelectKey.SelectedItem)
        }
        $File1SelectedItems = $File1Columns.SelectedItems + $File1SelectKey.SelectedItem
        if ($File2Columns.SelectedItems -contains $File2SelectKey.SelectedItem) {
            ($File2Columns.SelectedItems).Remove($File2SelectKey.SelectedItem)
        }
        $File2SelectedItems = , $File2SelectKey.SelectedItem + $File2Columns.SelectedItems
        # create new objects is faster than removing properties from existing objects
        $File1SheetTable_new = $File1SheetTable | Select-Object $File1SelectedItems
        $File2SheetTable_new = $File2SheetTable | Select-Object $File2SelectedItems
        # create folder
        If (!(Test-Path -Path "$PSScriptRoot\Output" -PathType 'Container')) {
            New-Item -Path "$PSScriptRoot\Output" -Type 'Directory' -Force
        }
        # combine objetcs & export excel
        $DateTime = Get-Date -Format "yyyyMMddTHHmmss"
        $ExportExcelParams = @{
            WorkSheetName = "$($File1SelectKey.SelectedItem)_&_$($File2SelectKey.SelectedItem)"
            TableName     = 'Data'
            TableStyle    = 'Medium13'
            Show          = $true
            AutoSize      = $true
            ClearSheet    = $true
            Path          = "$PSScriptRoot\Output\${DateTime}.xlsx"
        }

        Join-Object -Left $File1SheetTable_new -Right $File2SheetTable_new -LeftJoinProperty $File1SelectKey.SelectedItem`
            -RightJoinProperty $File2SelectKey.SelectedItem -Type OnlyIfInBoth -Prefix r_ | Export-Excel @ExportExcelParams
    })
[array]$RequiredModules = @(
    "ImportExcel"
)
Initialize-ExternalModules
$Window.ShowDialog() | Out-Null
