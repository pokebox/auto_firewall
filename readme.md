# 功能说明

auto firewall是一个通过web hook获取请求者IP，经过鉴权后放行对应防火墙的自动化脚本。

这个分支是PVE (Proxmox)服务器版本的。



# 使用说明

项目非常简单，首先复制`access.json-demo`并改名为`access.json`作为鉴权规则配置，修改文件中的`users`和`auth`作为鉴权密钥，每组一一对应。

`webhook_port`是要监听的端口号，自行修改，建议设置为`10000`以上。

`websocket_port`暂时没有用，未来可能会添加websocket请求功能。

配置好后，由于需要修改防火墙，需以root权限使用`python setFirewall.py`运行服务，此时可以在控制台看到信息输出。默认没有关闭调试信息，需要可自行修改源文件。

在PVE上添加一条放行规则，放行设置的`webhook_port`端口，确保服务可以被访问。

`test.sh`是放行测试脚本，修改脚本中的`<users val>`和`<auth val>`为自己设置的鉴权信息，`your_firewall_ip`为服务器的IP或域名以及设置的`webhook_port`端口号，然后运行脚本。查看pve数据中心防火墙设置中是否存在一个`temp`的IP规则集，以及其中是否有自己刚刚请求的IP，如果有则设置成功。

在需要放行的服务器上配置防火墙，设置`in`方向的操作为`ACCEPT`，源选择`ipset`类别中的`temp`规则，将规则放到最前面或根据自己需求设置即可。

> [!WARNING]
>
> 为保证安全，强烈建议先在内网环境下保证自己可以正常访问服务器的状态进行测试。

