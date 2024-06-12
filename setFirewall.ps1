param(
    [parameter(Mandatory=$true)]
    [string]$remoteIP
)
# 指定远程IP地址
#$remoteIP = "114.114.114.114"

# 指定要添加规则的防火墙规则名称
$ruleName = "远程桌面 - 用户模式(TCP-In)"

# # 检查是否存在该规则，如果不存在则创建
# $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

# if (-not $existingRule) {
#     New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389
#     Write-Host "已创建新的入站防火墙规则：$ruleName"
# }

# 获取防火墙规则的当前作用域
$ips = (Get-NetFirewallRule -DisplayName $ruleName | Get-NetFirewallAddressFilter ).RemoteAddress

# 如果远程IP地址已在作用域中，则退出
if ($ips -contains $remoteIP) {
    Write-Host "远程IP地址 $remoteIP 已在防火墙规则的作用域中。"
    exit
}
else {
    # 将远程IP地址添加到防火墙规则的作用域中
    $ips += $remoteIP
    $ips = $ips | Select-Object -Unique | Sort-Object
    Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $ips
    Write-Host "已将远程IP地址 $remoteIP 添加到入站防火墙规则的作用域中。"
}

# 192.168.0.0/255.255.0.0
# 10.0.0.0/255.0.0.0
# 172.16.0.0/255.240.0.0
