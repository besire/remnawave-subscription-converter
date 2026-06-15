# Remnawave 订阅转换工具

这是一个纯前端工具，用来把代理分享链接转换成 Mihomo 配置。

支持输入：

- `vless://...`
- `trojan://...`
- `ss://...`
- Xray WireGuard outbound JSON，或包含 WireGuard outbound 的完整 Xray JSON 配置
- Xray WireGuard inbound JSON，或包含 WireGuard inbound 的完整 Xray JSON 配置

工具只在浏览器本地解析，不会请求后端，也不会上传你的链接。

## 使用方式

打开 `index.html`，粘贴分享链接或 Xray WireGuard JSON，然后复制生成结果。分享链接可以一次粘贴多条，每行一条；JSON 配置一次粘贴一份。

可选项：

- 入口 IP / 域名：填写后会替换原始链接里的入口地址，并同步修改 Mihomo YAML 的 `server` 字段。留空则不改变。
- 入口端口：填写后会替换原始链接里的端口，并同步修改 Mihomo YAML 的 `port` 字段。留空则不改变。
- 节点名称：单条时覆盖 Mihomo YAML 的 `name` 字段；多条时作为名称前缀自动追加序号。留空则使用原始名称。
- 每条链接单独设置：粘贴链接后可以展开每一条的下拉设置，单独覆盖入口 IP / 域名、入口端口和节点名称；单独设置优先于上面的全局设置。
- WireGuard 服务端配置补充：当输入是 Xray `inbounds` 里的 WireGuard 服务端配置时，填写客户端私钥、服务端公钥、客户端地址和可选预共享密钥。
- 当前 Mihomo 配置：填写后会在现有配置基础上追加新节点、代理组引用和规则；留空则生成新的基础配置。

WireGuard 说明：

- WireGuard 没有像 `vless://` 那样统一通用的分享链接格式。
- Xray WireGuard outbound 是客户端配置，可以直接转成 Mihomo `type: wireguard` 节点。主要映射：`settings.secretKey` -> `private-key`，`settings.address` -> `ip` / `ipv6`，`settings.peers` -> `server` / `port` / `public-key` / `allowed-ips`。
- Xray WireGuard inbound 是服务端配置，不包含 Mihomo 客户端所需的客户端私钥、服务端公钥和客户端地址。工具会要求你在页面的 WireGuard 补充区填写这些字段，并使用入口 IP / 域名与入口端口作为 Mihomo 的 `server` / `port`。
- Xray inbound 的 `settings.secretKey` 是服务端私钥，工具不会把它写入 Mihomo `private-key`。
- Xray 的 `noKernelTun`、`domainStrategy` 属于 Xray 运行时选项，不会写入 Mihomo 节点；工具会在警告里提示。

生成结果：

- `完整 Mihomo 配置`：包含基础 DNS、所有节点、代理组和 `MATCH` 规则；如果填写了当前配置，会在当前配置基础上生成。
- `Mihomo 节点 YAML`：粘贴到 Remnawave Mihomo 模板的 `proxies:` 下。
- `代理组片段`：把其中的节点名加入你需要的 `proxy-groups`。
- `规则片段`：和 `proxy-groups` 使用同一个名字，避免 `proxy not found`。
- `Xray 原始输入`：用于需要 raw/share link 或原始 JSON 的客户端或手工保存。

## 在 Remnawave 中只给某个用户使用

不要修改默认 `MIHOMO` 模板，否则所有使用默认模板的用户都会看到这个节点。

推荐做法：

1. 新建一个专用 `MIHOMO` 订阅模板。
2. 把本工具生成的节点 YAML 放进这个专用模板。
3. 新建一个 `External Squad`。
4. 只把目标用户加入这个 `External Squad`。
5. 给这个 `External Squad` 绑定专用的 `MIHOMO` 模板。

这样只有该用户的订阅会使用专用模板，其他用户仍然使用默认模板。

## Dokploy 部署

仓库地址：

```text
git@github.com:besire/remnawave-subscription-converter.git
```

### Dockerfile 方式

Dokploy 应用设置：

- Repository：`besire/remnawave-subscription-converter`
- Branch：`main`
- Build type：`Dockerfile`
- Dockerfile path：`Dockerfile`
- Build context：`.`
- Container port：`80`

域名绑定时把域名指向这个应用，容器端口填 `80`。不要在 `Advanced -> Ports` 里额外暴露公网端口。

### Static / SPA 方式

如果你的 Dokploy 版本提供 Static 或 SPA 部署，也可以直接部署：

- Install command：留空
- Build command：留空
- Publish / Output directory：`.`
- SPA fallback：开启，如果有这个选项

静态部署模式一般不会让你选择端口，这是正常的。

## 本地检查

运行解析测试：

```bash
node subscription-converter.test.js
```

本地 Docker 检查：

```bash
docker build -t subscription-converter .
docker run --rm -p 8088:80 subscription-converter
```

然后访问：

```text
http://localhost:8088/
```
