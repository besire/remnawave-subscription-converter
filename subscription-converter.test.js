const assert = require('assert');

const converter = require('./subscription-converter');

const vless =
    'vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&type=ws&security=tls&sni=example.com&fp=chrome&path=%2Fws%3Fed%3D2048&host=cdn.example.com#demo-vless';
const trojan =
    'trojan://secret@example.net:443?type=grpc&security=tls&sni=example.net&serviceName=svc#demo-trojan';
const ss = 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.org:8388#demo-ss';
const ssPlain = 'ss://chacha20-ietf-poly1305:plain-pass@example.org:8389#plain-ss';
const reality =
    'vless://22222222-2222-4222-8222-222222222222@[2001:db8::1]:8443?type=tcp&security=reality&sni=www.example.com&pbk=public-key&sid=abcd&flow=xtls-rprx-vision#reality-vless';
const httpUpgrade =
    'vless://33333333-3333-4333-8333-333333333333@example.com:443?type=httpupgrade&security=tls&path=%2Fupgrade&host=edge.example.com#hu-vless';
const xrayWireGuardOutbound = `{
  "tag": "warp-wireguard",
  "protocol": "wireguard",
  "settings": {
    "secretKey": "PRIVATE_KEY",
    "address": ["172.16.0.2/32", "2606:4700:110:8f77::2/128"],
    "mtu": 1420,
    "reserved": [1, 2, 3],
    "domainStrategy": "ForceIP",
    "peers": [
      {
        "endpoint": "engage.cloudflareclient.com:2408",
        "publicKey": "PUBLIC_KEY",
        "preSharedKey": "PRE_SHARED_KEY",
        "keepAlive": 25,
        "allowedIPs": ["0.0.0.0/0", "::/0"]
      }
    ]
  }
}`;
const xrayWireGuardInbound = `{
  "tag": "home-wg",
  "port": 51820,
  "protocol": "wireguard",
  "settings": {
    "secretKey": "SERVER_PRIVATE_KEY",
    "mtu": 1420,
    "peers": [
      {
        "publicKey": "CLIENT_PUBLIC_KEY",
        "preSharedKey": "PRE_SHARED_KEY",
        "allowedIPs": ["172.16.0.2/32"]
      }
    ]
  }
}`;

const vlessResult = converter.convertShareLink(vless);
assert.match(vlessResult.mihomoYaml, /type: "vless"/);
assert.match(vlessResult.mihomoYaml, /uuid: "11111111-1111-4111-8111-111111111111"/);
assert.match(vlessResult.mihomoYaml, /ws-opts:/);
assert.match(vlessResult.mihomoYaml, /max-early-data: 2048/);
assert.match(vlessResult.mihomoYaml, /Host: "cdn.example.com"/);
assert.match(vlessResult.ruleSnippet, /rules:/);
assert.match(vlessResult.ruleSnippet, /MATCH,Remnawave/);
assert.match(vlessResult.fullMihomoYaml, /proxy-groups:/);
assert.match(vlessResult.fullMihomoYaml, /name: "Remnawave"/);
assert.match(vlessResult.fullMihomoYaml, /MATCH,Remnawave/);

const trojanResult = converter.convertShareLink(trojan);
assert.match(trojanResult.mihomoYaml, /type: "trojan"/);
assert.match(trojanResult.mihomoYaml, /password: "secret"/);
assert.match(trojanResult.mihomoYaml, /grpc-opts:/);
assert.match(trojanResult.mihomoYaml, /grpc-service-name: "svc"/);

const ssResult = converter.convertShareLink(ss);
assert.match(ssResult.mihomoYaml, /type: "ss"/);
assert.match(ssResult.mihomoYaml, /cipher: "aes-256-gcm"/);
assert.match(ssResult.mihomoYaml, /password: "password"/);
assert.match(ssResult.ruleSnippet, /MATCH,Remnawave/);

const ssPlainResult = converter.convertShareLink(ssPlain);
assert.match(ssPlainResult.mihomoYaml, /cipher: "chacha20-ietf-poly1305"/);
assert.match(ssPlainResult.mihomoYaml, /password: "plain-pass"/);

const ssOverrideResult = converter.convertShareLink(ss, {
    entryHost: 'ss-entry.example.com',
    name: 'ss-name',
});
assert.match(ssOverrideResult.mihomoYaml, /server: "ss-entry.example.com"/);
assert.match(ssOverrideResult.xrayRaw, /^ss:\/\/YWVzLTI1Ni1nY206cGFzc3dvcmQ@ss-entry\.example\.com:8388/);
assert.match(ssOverrideResult.xrayRaw, /#ss-name$/);
assert.match(ssOverrideResult.ruleSnippet, /MATCH,Remnawave/);

const realityResult = converter.convertShareLink(reality);
assert.match(realityResult.mihomoYaml, /servername: "www.example.com"/);
assert.match(realityResult.mihomoYaml, /reality-opts:/);
assert.match(realityResult.mihomoYaml, /public-key: "public-key"/);
assert.match(realityResult.mihomoYaml, /short-id: "abcd"/);
assert.match(realityResult.mihomoYaml, /flow: "xtls-rprx-vision"/);

const httpUpgradeResult = converter.convertShareLink(httpUpgrade);
assert.match(httpUpgradeResult.mihomoYaml, /network: "ws"/);
assert.match(httpUpgradeResult.mihomoYaml, /v2ray-http-upgrade: true/);
assert.match(httpUpgradeResult.mihomoYaml, /Host: "edge.example.com"/);

const wireGuardResult = converter.convertShareLink(xrayWireGuardOutbound);
assert.match(wireGuardResult.mihomoYaml, /type: "wireguard"/);
assert.match(wireGuardResult.mihomoYaml, /name: "warp-wireguard"/);
assert.match(wireGuardResult.mihomoYaml, /server: "engage.cloudflareclient.com"/);
assert.match(wireGuardResult.mihomoYaml, /port: 2408/);
assert.match(wireGuardResult.mihomoYaml, /ip: "172.16.0.2\/32"/);
assert.match(wireGuardResult.mihomoYaml, /ipv6: "2606:4700:110:8f77::2\/128"/);
assert.match(wireGuardResult.mihomoYaml, /private-key: "PRIVATE_KEY"/);
assert.match(wireGuardResult.mihomoYaml, /public-key: "PUBLIC_KEY"/);
assert.match(wireGuardResult.mihomoYaml, /pre-shared-key: "PRE_SHARED_KEY"/);
assert.match(wireGuardResult.mihomoYaml, /persistent-keepalive: 25/);
assert.match(wireGuardResult.mihomoYaml, /allowed-ips:/);
assert.match(wireGuardResult.mihomoYaml, /reserved:/);
assert.match(wireGuardResult.warnings.join('\n'), /domainStrategy/);

const xrayFullConfig = JSON.stringify({
    outbounds: [
        {
            tag: 'direct',
            protocol: 'freedom',
        },
        JSON.parse(xrayWireGuardOutbound),
    ],
});
const wireGuardFullConfigResult = converter.convertShareLink(xrayFullConfig, {
    entryHost: 'wg.example.com',
    entryPort: 51820,
    name: 'WG 节点',
});
assert.match(wireGuardFullConfigResult.mihomoYaml, /name: "WG 节点"/);
assert.match(wireGuardFullConfigResult.mihomoYaml, /server: "wg.example.com"/);
assert.match(wireGuardFullConfigResult.mihomoYaml, /port: 51820/);
assert.match(wireGuardFullConfigResult.fullMihomoYaml, /type: "wireguard"/);
assert.strictEqual(wireGuardFullConfigResult.xrayRaw, xrayFullConfig);

const xrayWireGuardMultiPeer = JSON.stringify({
    tag: 'multi-wg',
    protocol: 'wireguard',
    settings: {
        secretKey: 'PRIVATE_KEY',
        address: ['172.16.0.3/32'],
        peers: [
            {
                endpoint: 'peer-a.example.com:51820',
                publicKey: 'PUBLIC_A',
                keepAlive: 15,
            },
            {
                endpoint: 'peer-b.example.com:51821',
                publicKey: 'PUBLIC_B',
            },
        ],
    },
});
const wireGuardMultiPeerResult = converter.convertShareLink(xrayWireGuardMultiPeer);
assert.match(wireGuardMultiPeerResult.mihomoYaml, /peers:/);
assert.match(wireGuardMultiPeerResult.mihomoYaml, /server: "peer-a.example.com"/);
assert.match(wireGuardMultiPeerResult.mihomoYaml, /server: "peer-b.example.com"/);
assert.match(wireGuardMultiPeerResult.mihomoYaml, /persistent-keepalive: 15/);

assert.throws(
    () => converter.convertShareLink(xrayWireGuardInbound),
    /Xray WireGuard inbound 是服务端配置，缺少：入口 IP \/ 域名、WG 客户端私钥、WG 服务端公钥、WG 客户端地址/,
);

const wireGuardInboundResult = converter.convertShareLink(xrayWireGuardInbound, {
    entryHost: 'wg.example.com',
    wireGuardClientPrivateKey: 'CLIENT_PRIVATE_KEY',
    wireGuardServerPublicKey: 'SERVER_PUBLIC_KEY',
    wireGuardClientAddress: '172.16.0.2/32,fd00::2/128',
});
assert.match(wireGuardInboundResult.mihomoYaml, /name: "home-wg"/);
assert.match(wireGuardInboundResult.mihomoYaml, /type: "wireguard"/);
assert.match(wireGuardInboundResult.mihomoYaml, /server: "wg.example.com"/);
assert.match(wireGuardInboundResult.mihomoYaml, /port: 51820/);
assert.match(wireGuardInboundResult.mihomoYaml, /ip: "172.16.0.2\/32"/);
assert.match(wireGuardInboundResult.mihomoYaml, /ipv6: "fd00::2\/128"/);
assert.match(wireGuardInboundResult.mihomoYaml, /private-key: "CLIENT_PRIVATE_KEY"/);
assert.match(wireGuardInboundResult.mihomoYaml, /public-key: "SERVER_PUBLIC_KEY"/);
assert.match(wireGuardInboundResult.mihomoYaml, /pre-shared-key: "PRE_SHARED_KEY"/);
assert.doesNotMatch(wireGuardInboundResult.mihomoYaml, /SERVER_PRIVATE_KEY/);
assert.match(wireGuardInboundResult.warnings.join('\n'), /inbound/);
assert.match(wireGuardInboundResult.warnings.join('\n'), /客户端私钥对应服务端 peers/);

const xrayFullInboundConfig = JSON.stringify({
    inbounds: [
        {
            tag: 'api',
            protocol: 'dokodemo-door',
            port: 10085,
        },
        JSON.parse(xrayWireGuardInbound),
    ],
});
const wireGuardFullInboundResult = converter.convertShareLink(xrayFullInboundConfig, {
    entryHost: '203.0.113.9',
    entryPort: 51821,
    wireGuardClientPrivateKey: 'CLIENT_PRIVATE_KEY',
    wireGuardServerPublicKey: 'SERVER_PUBLIC_KEY',
    wireGuardClientAddress: '172.16.0.2/32',
    wireGuardPreSharedKey: 'OVERRIDE_PRE_SHARED_KEY',
});
assert.match(wireGuardFullInboundResult.mihomoYaml, /server: "203.0.113.9"/);
assert.match(wireGuardFullInboundResult.mihomoYaml, /port: 51821/);
assert.match(wireGuardFullInboundResult.mihomoYaml, /pre-shared-key: "OVERRIDE_PRE_SHARED_KEY"/);

const xrayInboundWithDifferentPreSharedKeys = JSON.stringify({
    tag: 'multi-client-wg',
    protocol: 'wireguard',
    port: 51820,
    settings: {
        secretKey: 'SERVER_PRIVATE_KEY',
        peers: [
            {
                publicKey: 'CLIENT_PUBLIC_KEY_A',
                preSharedKey: 'PRE_SHARED_KEY_A',
            },
            {
                publicKey: 'CLIENT_PUBLIC_KEY_B',
                preSharedKey: 'PRE_SHARED_KEY_B',
            },
        ],
    },
});
const wireGuardDifferentPskResult = converter.convertShareLink(xrayInboundWithDifferentPreSharedKeys, {
    entryHost: 'wg.example.com',
    wireGuardClientPrivateKey: 'CLIENT_PRIVATE_KEY',
    wireGuardServerPublicKey: 'SERVER_PUBLIC_KEY',
    wireGuardClientAddress: '172.16.0.3/32',
});
assert.doesNotMatch(wireGuardDifferentPskResult.mihomoYaml, /pre-shared-key/);
assert.match(wireGuardDifferentPskResult.warnings.join('\n'), /多个不同的 peer preSharedKey/);

assert.strictEqual(vlessResult.xrayRaw, vless);

const overrideResult = converter.convertShareLink(vless, {
    entryHost: 'edge.example.org',
    entryPort: 8443,
    name: '专用节点',
});
assert.match(overrideResult.mihomoYaml, /name: "专用节点"/);
assert.match(overrideResult.mihomoYaml, /server: "edge.example.org"/);
assert.match(overrideResult.mihomoYaml, /port: 8443/);
assert.match(overrideResult.groupSnippet, /- "专用节点"/);
assert.match(overrideResult.xrayRaw, /^vless:\/\/11111111-1111-4111-8111-111111111111@edge\.example\.org:8443/);
assert.match(overrideResult.xrayRaw, /#%E4%B8%93%E7%94%A8%E8%8A%82%E7%82%B9$/);

const batchResult = converter.convertShareLinks(`${vless}\n${trojan}\n${ss}`, {
    entryHost: 'batch.example.com',
    name: '批量节点',
});
assert.strictEqual(batchResult.items.length, 3);
assert.match(batchResult.mihomoYaml, /name: "批量节点 1"/);
assert.match(batchResult.mihomoYaml, /name: "批量节点 2"/);
assert.match(batchResult.mihomoYaml, /name: "批量节点 3"/);
assert.match(batchResult.mihomoYaml, /server: "batch.example.com"/);
assert.match(batchResult.groupSnippet, /name: "Remnawave"/);
assert.match(batchResult.groupSnippet, /- "批量节点 1"/);
assert.match(batchResult.groupSnippet, /- "批量节点 2"/);
assert.match(batchResult.groupSnippet, /- "批量节点 3"/);
assert.match(batchResult.ruleSnippet, /MATCH,Remnawave/);
assert.match(batchResult.fullMihomoYaml, /proxies:/);
assert.match(batchResult.fullMihomoYaml, /proxy-groups:/);
assert.match(batchResult.fullMihomoYaml, /rules:/);
assert.match(batchResult.xrayRaw, /#%E6%89%B9%E9%87%8F%E8%8A%82%E7%82%B9%201/);
assert.match(batchResult.xrayRaw, /#%E6%89%B9%E9%87%8F%E8%8A%82%E7%82%B9%202/);
assert.match(batchResult.xrayRaw, /#%E6%89%B9%E9%87%8F%E8%8A%82%E7%82%B9%203/);

const perItemResult = converter.convertShareLinks(`${vless}\n${trojan}`, {
    entryHost: 'global.example.com',
    entryPort: 443,
    name: '全局节点',
    itemOverrides: [
        {},
        {
            entryHost: 'line.example.net',
            entryPort: 9443,
            name: '第二条节点',
        },
    ],
});
assert.match(perItemResult.mihomoYaml, /name: "全局节点 1"[\s\S]*server: "global.example.com"[\s\S]*port: 443/);
assert.match(perItemResult.mihomoYaml, /name: "第二条节点"[\s\S]*server: "line.example.net"[\s\S]*port: 9443/);
assert.match(perItemResult.xrayRaw, /^vless:\/\/11111111-1111-4111-8111-111111111111@global\.example\.com:443/m);
assert.match(perItemResult.xrayRaw, /^trojan:\/\/secret@line\.example\.net:9443/m);
assert.match(perItemResult.fullMihomoYaml, /name: "第二条节点"/);
assert.match(perItemResult.fullMihomoYaml, /port: 9443/);

const duplicateResult = converter.convertShareLinks(`${ssPlain}\n${ssPlain}`);
assert.match(duplicateResult.mihomoYaml, /name: "plain-ss"/);
assert.match(duplicateResult.mihomoYaml, /name: "plain-ss 2"/);
assert.match(duplicateResult.warnings.join('\n'), /节点名重复/);

const baseConfig = `mixed-port: 7890
proxies:
  - name: "old-node"
    type: "ss"
    server: "old.example.com"
    port: 8388
    cipher: "aes-128-gcm"
    password: "old"
proxy-groups:
  - name: "Remnawave"
    type: "select"
    proxies:
      - "old-node"
rules:
  - MATCH,→ Remnawave`;
const mergedResult = converter.convertShareLinks(vless, {
    baseConfig,
    name: 'merged-node',
});
assert.match(mergedResult.fullMihomoYaml, /name: "old-node"/);
assert.match(mergedResult.fullMihomoYaml, /name: "merged-node"/);
assert.match(mergedResult.fullMihomoYaml, /- "old-node"/);
assert.match(mergedResult.fullMihomoYaml, /- "merged-node"/);
assert.doesNotMatch(mergedResult.fullMihomoYaml, /MATCH,→ Remnawave/);
assert.match(mergedResult.fullMihomoYaml, /MATCH,Remnawave/);

const ssLegacy = 'ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAZXhhbXBsZS5vcmc6ODM4OA#legacy-ss';
const ssLegacyOverride = converter.convertShareLink(ssLegacy, {
    entryHost: '203.0.113.10',
    name: 'legacy-name',
});
assert.match(ssLegacyOverride.mihomoYaml, /server: "203.0.113.10"/);
assert.match(ssLegacyOverride.xrayRaw, /^ss:\/\//);
assert.match(ssLegacyOverride.xrayRaw, /#legacy-name$/);

assert.throws(
    () => converter.convertShareLink(vless, { entryHost: 'https://edge.example.org' }),
    /不要带协议/,
);
assert.throws(() => converter.convertShareLink(vless, { entryHost: 'edge.example.org:443' }), /不要带端口/);
assert.throws(() => converter.convertShareLink(vless, { entryPort: 'abc' }), /端口/);
assert.throws(
    () =>
        converter.convertShareLinks(vless, {
            itemOverrides: [{ entryPort: 70000 }],
        }),
    /端口/,
);
assert.throws(() => converter.convertShareLink('{"protocol":"wireguard","settings":{"peers":[]}}'), /peers/);
assert.throws(
    () =>
        converter.convertShareLink(
            '{"protocol":"wireguard","settings":{"secretKey":"PRIVATE","peers":[{"endpoint":"example.com:51820"}]}}',
        ),
    /publicKey/,
);
assert.throws(
    () =>
        converter.convertShareLink(
            '{"protocol":"wireguard","settings":{"secretKey":"PRIVATE","mtu":"1420abc","peers":[{"endpoint":"example.com:51820","publicKey":"PUBLIC"}]}}',
        ),
    /mtu/,
);
assert.throws(() => converter.convertShareLink('https://example.com'), /暂不支持该协议/);

console.log('subscription-converter tests passed');
