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

const vlessResult = converter.convertShareLink(vless);
assert.match(vlessResult.mihomoYaml, /type: "vless"/);
assert.match(vlessResult.mihomoYaml, /uuid: "11111111-1111-4111-8111-111111111111"/);
assert.match(vlessResult.mihomoYaml, /ws-opts:/);
assert.match(vlessResult.mihomoYaml, /max-early-data: 2048/);
assert.match(vlessResult.mihomoYaml, /Host: "cdn.example.com"/);
assert.match(vlessResult.ruleSnippet, /rules:/);
assert.match(vlessResult.ruleSnippet, /MATCH,demo-vless/);

const trojanResult = converter.convertShareLink(trojan);
assert.match(trojanResult.mihomoYaml, /type: "trojan"/);
assert.match(trojanResult.mihomoYaml, /password: "secret"/);
assert.match(trojanResult.mihomoYaml, /grpc-opts:/);
assert.match(trojanResult.mihomoYaml, /grpc-service-name: "svc"/);

const ssResult = converter.convertShareLink(ss);
assert.match(ssResult.mihomoYaml, /type: "ss"/);
assert.match(ssResult.mihomoYaml, /cipher: "aes-256-gcm"/);
assert.match(ssResult.mihomoYaml, /password: "password"/);
assert.match(ssResult.ruleSnippet, /MATCH,demo-ss/);

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
assert.match(ssOverrideResult.ruleSnippet, /MATCH,ss-name/);

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

assert.strictEqual(vlessResult.xrayRaw, vless);

const overrideResult = converter.convertShareLink(vless, {
    entryHost: 'edge.example.org',
    name: '专用节点',
});
assert.match(overrideResult.mihomoYaml, /name: "专用节点"/);
assert.match(overrideResult.mihomoYaml, /server: "edge.example.org"/);
assert.match(overrideResult.groupSnippet, /- "专用节点"/);
assert.match(overrideResult.xrayRaw, /^vless:\/\/11111111-1111-4111-8111-111111111111@edge\.example\.org:443/);
assert.match(overrideResult.xrayRaw, /#%E4%B8%93%E7%94%A8%E8%8A%82%E7%82%B9$/);

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
assert.throws(() => converter.convertShareLink('https://example.com'), /暂不支持该协议/);

console.log('subscription-converter tests passed');
