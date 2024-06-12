param(
    [parameter(Mandatory=$true)]
    [string]$remoteIP
)
# ָ��Զ��IP��ַ
#$remoteIP = "114.114.114.114"

# ָ��Ҫ��ӹ���ķ���ǽ��������
$ruleName = "Զ������ - �û�ģʽ(TCP-In)"

# # ����Ƿ���ڸù�������������򴴽�
# $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

# if (-not $existingRule) {
#     New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389
#     Write-Host "�Ѵ����µ���վ����ǽ����$ruleName"
# }

# ��ȡ����ǽ����ĵ�ǰ������
$ips = (Get-NetFirewallRule -DisplayName $ruleName | Get-NetFirewallAddressFilter ).RemoteAddress

# ���Զ��IP��ַ�����������У����˳�
if ($ips -contains $remoteIP) {
    Write-Host "Զ��IP��ַ $remoteIP ���ڷ���ǽ������������С�"
    exit
}
else {
    # ��Զ��IP��ַ��ӵ�����ǽ�������������
    $ips += $remoteIP
    $ips = $ips | Select-Object -Unique | Sort-Object
    Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $ips
    Write-Host "�ѽ�Զ��IP��ַ $remoteIP ��ӵ���վ����ǽ������������С�"
}

# 192.168.0.0/255.255.0.0
# 10.0.0.0/255.0.0.0
# 172.16.0.0/255.240.0.0
