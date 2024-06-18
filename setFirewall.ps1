param(
    [parameter(Mandatory=$true)]
    [string]$remoteIP
)
# ָ��Զ��IP��ַ
#$remoteIP = "114.114.114.114"

# ָ��Ҫ��ӹ���ķ���ǽ��������
$ruleName = "Զ������ - �û�ģʽ(TCP-In)"
$ruleNameudp = "Զ������ - �û�ģʽ(UDP-In)"

# # ����Ƿ���ڸù�������������򴴽�
# $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

# if (-not $existingRule) {
#     New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389
#     Write-Host "�Ѵ����µ���վ����ǽ����$ruleName"
# }

# ��ȡ����ǽ����ĵ�ǰ������
$ips = (Get-NetFirewallRule -DisplayName $ruleName | Get-NetFirewallAddressFilter ).RemoteAddress
$ipsudp = (Get-NetFirewallRule -DisplayName $ruleNameudp | Get-NetFirewallAddressFilter ).RemoteAddress

$havetcp = 2
$havedp = 2
# ���Զ��IP��ַ�����������У����˳�
if ($ips -contains $remoteIP) {
    #$outinfo = "Զ��IP��ַ $remoteIP ���ڷ���ǽTCP������������С�"
    $havetcp = 1
    # exit
}
else {
    # ��Զ��IP��ַ��ӵ�����ǽ�������������
    $ips += $remoteIP
    $ips = $ips | Select-Object -Unique | Sort-Object
    Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $ips
    #$outinfo = "�ѽ�Զ��IP��ַ $remoteIP ��ӵ���վ����ǽTCP������������С�"
    $havetcp = 0
}

if ($ipsudp -contains $remoteIP) {
    #$outinfo += "Զ��IP��ַ $remoteIP ���ڷ���ǽUDP������������С�"
    $havedp = 1
}
else {
    $ipsudp += $remoteIP
    $ipsudp = $ipsudp | Select-Object -Unique | Sort-Object
    Set-NetFirewallRule -DisplayName $ruleNameudp -RemoteAddress $ipsudp
    #$outinfo += "�ѽ�Զ��IP��ַ $remoteIP ��ӵ���վ����ǽUDP������������С�"
    $havedp = 0
}

if ($havetcp -eq 0 -and $havedp -eq 0) {
    $outinfo = "Զ��IP��ַ $remoteIP �ѳɹ���ӵ�����ǽTCP/UDP�����С�"
}
elseif ($havetcp -eq 1 -and $havedp -eq 1) {
    $outinfo = "Զ��IP��ַ $remoteIP ���ڷ���ǽTCP/UDP�����С�"
}
else {
    if ($havetcp -eq 1) {
        $outinfo = "Զ��IP��ַ $remoteIP ��ӵ�UDP�ɹ���TCP�Ѵ��ڡ�"
    }
    elseif ($havedp -eq 1) {
        $outinfo = "Զ��IP��ַ $remoteIP ��ӵ�TCP�ɹ���UDP�Ѵ��ڡ�"
    }
}


write-host $outinfo

# 192.168.0.0/255.255.0.0
# 10.0.0.0/255.0.0.0
# 172.16.0.0/255.240.0.0
