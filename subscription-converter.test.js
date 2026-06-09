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

const trojanResult = converter.convertShareLink(trojan);
assert.match(trojanResult.mihomoYaml, /type: "trojan"/);
assert.match(trojanResult.mihomoYaml, /password: "secret"/);
assert.match(trojanResult.mihomoYaml, /grpc-opts:/);
assert.match(trojanResult.mihomoYaml, /grpc-service-name: "svc"/);

const ssResult = converter.convertShareLink(ss);
assert.match(ssResult.mihomoYaml, /type: "ss"/);
assert.match(ssResult.mihomoYaml, /cipher: "aes-256-gcm"/);
assert.match(ssResult.mihomoYaml, /password: "password"/);

const ssPlainResult = converter.convertShareLink(ssPlain);
assert.match(ssPlainResult.mihomoYaml, /cipher: "chacha20-ietf-poly1305"/);
assert.match(ssPlainResult.mihomoYaml, /password: "plain-pass"/);

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

assert.throws(() => converter.convertShareLink('https://example.com'), /Unsupported protocol/);

console.log('subscription-converter tests passed');
