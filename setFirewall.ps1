param(
    [parameter(Mandatory=$true)]
    [string]$remoteIP
)
# 指定远程IP地址
#$remoteIP = "114.114.114.114"

# 指定要添加规则的防火墙规则名称
$ruleName = "远程桌面 - 用户模式(TCP-In)"
$ruleNameudp = "远程桌面 - 用户模式(UDP-In)"

# # 检查是否存在该规则，如果不存在则创建
# $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

# if (-not $existingRule) {
#     New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389
#     Write-Host "已创建新的入站防火墙规则：$ruleName"
# }

# 获取防火墙规则的当前作用域
$ips = (Get-NetFirewallRule -DisplayName $ruleName | Get-NetFirewallAddressFilter ).RemoteAddress
$ipsudp = (Get-NetFirewallRule -DisplayName $ruleNameudp | Get-NetFirewallAddressFilter ).RemoteAddress

$havetcp = 2
$havedp = 2
# 如果远程IP地址已在作用域中，则退出
if ($ips -contains $remoteIP) {
    #$outinfo = "远程IP地址 $remoteIP 已在防火墙TCP规则的作用域中。"
    $havetcp = 1
    # exit
}
else {
    # 将远程IP地址添加到防火墙规则的作用域中
    $ips += $remoteIP
    $ips = $ips | Select-Object -Unique | Sort-Object
    Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $ips
    #$outinfo = "已将远程IP地址 $remoteIP 添加到入站防火墙TCP规则的作用域中。"
    $havetcp = 0
}

if ($ipsudp -contains $remoteIP) {
    #$outinfo += "远程IP地址 $remoteIP 已在防火墙UDP规则的作用域中。"
    $havedp = 1
}
else {
    $ipsudp += $remoteIP
    $ipsudp = $ipsudp | Select-Object -Unique | Sort-Object
    Set-NetFirewallRule -DisplayName $ruleNameudp -RemoteAddress $ipsudp
    #$outinfo += "已将远程IP地址 $remoteIP 添加到入站防火墙UDP规则的作用域中。"
    $havedp = 0
}

if ($havetcp -eq 0 -and $havedp -eq 0) {
    $outinfo = "远程IP地址 $remoteIP 已成功添加到防火墙TCP/UDP规则中。"
}
elseif ($havetcp -eq 1 -and $havedp -eq 1) {
    $outinfo = "远程IP地址 $remoteIP 已在防火墙TCP/UDP规则中。"
}
else {
    if ($havetcp -eq 1) {
        $outinfo = "远程IP地址 $remoteIP 添加到UDP成功，TCP已存在。"
    }
    elseif ($havedp -eq 1) {
        $outinfo = "远程IP地址 $remoteIP 添加到TCP成功，UDP已存在。"
    }
}


write-host $outinfo

# 192.168.0.0/255.255.0.0
# 10.0.0.0/255.0.0.0
# 172.16.0.0/255.240.0.0
