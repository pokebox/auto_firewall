# 计算密钥值，使用users和auth字段加上当前时间的md5值作为密钥值
keyval=$(echo -n "<users val><auth val>`date +%Y%m%d%H%M`" | md5sum | awk '{print $1}')
# 使用curl发送请求，其中remote_ip为要添加的IP地址，实际服务器仅从请求源获取IP而非此处的数据
curl --location 'http://your_firewall_ip:1234/' --header "Authorization: Bearer ${keyval}" --header 'Content-Type: application/json' --data '{"remote_ip":"1.2.3.4"}'
