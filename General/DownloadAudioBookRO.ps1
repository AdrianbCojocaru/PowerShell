[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
1..74 | %{ $a = '{0:D2}' -f $_

#(1..50).ForEach({ '{0:D2}' -f $_ })

$bookName = "Henryk_Sienkiewicz-Quo_Vadis"

$url = "https://www.cartiaudio.eu/d.php?254/${bookName}-Capitolul_${a}.mp3"


$output = "$PSScriptRoot\${bookName}-Capitolul_${a}.mp3"
$start_time = Get-Date

write-host $url
Invoke-WebRequest -Uri $url -OutFile $output
Start-Sleep -Seconds  (Get-Random -Minimum 2 -Maximum 100)
}



