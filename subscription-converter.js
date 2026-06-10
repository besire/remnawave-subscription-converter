(function (root) {
    'use strict';

    const SUPPORTED_PROTOCOLS = new Set(['vless', 'trojan', 'ss']);
    const DEFAULT_GROUP_NAME = 'Remnawave';

    function convertShareLink(input, options = {}) {
        const raw = normalizeSingleInput(input);
        return convertRawLinks([raw], options);
    }

    function convertShareLinks(input, options = {}) {
        return convertRawLinks(normalizeMultipleInput(input), options);
    }

    function convertRawLinks(rawLinks, options = {}) {
        const overrides = normalizeOverrides(options);
        const usedNames = new Map();
        const items = rawLinks.map((raw, index) => {
            const parsed = parseShareLink(raw);
            const itemOverride = resolveItemOverride(overrides, index);
            const itemName =
                itemOverride.name || resolveItemName(parsed.name, overrides.name, index, rawLinks.length);
            const withOverrides = applyOverrides(parsed, {
                entryHost: itemOverride.entryHost || overrides.entryHost,
                entryPort: itemOverride.entryPort || overrides.entryPort,
                name: itemName,
            });
            const uniqueName = ensureUniqueName(withOverrides.name, usedNames);
            const finalParsed = { ...withOverrides, name: uniqueName.name };
            const mihomoProxy = toMihomoProxy(finalParsed);
            const rawNameOverride =
                itemOverride.name || overrides.name || uniqueName.changed ? finalParsed.name : '';
            const xrayRaw = renderRawShareLink(raw, finalParsed, {
                entryHost: itemOverride.entryHost || overrides.entryHost,
                entryPort: itemOverride.entryPort || overrides.entryPort,
                name: rawNameOverride,
            });

            return {
                raw,
                parsed: finalParsed,
                mihomoProxy,
                xrayRaw,
                warnings: [
                    ...finalParsed.warnings,
                    ...(uniqueName.changed ? [`节点名重复，已重命名为 ${uniqueName.name}。`] : []),
                ],
            };
        });

        const mihomoProxies = items.map((item) => item.mihomoProxy);
        const proxyNames = mihomoProxies.map((proxy) => proxy.name);
        const groupName = overrides.groupName;
        const mihomoYaml = renderYamlList(mihomoProxies);
        const groupSnippet = renderGroupSnippet(proxyNames, groupName);
        const ruleSnippet = renderRuleSnippet(groupName);
        const fullMihomoYaml = renderMergedMihomoConfig(
            overrides.baseConfig,
            mihomoProxies,
            groupName,
        );
        const xrayRaw = items.map((item) => item.xrayRaw).join('\n');
        const warnings = items.flatMap((item, index) =>
            item.warnings.map((warning) => `第 ${index + 1} 条：${warning}`),
        );

        return {
            parsed: items[0].parsed,
            mihomoProxy: items[0].mihomoProxy,
            items,
            groupName,
            mihomoYaml,
            groupSnippet,
            ruleSnippet,
            fullMihomoYaml,
            xrayRaw,
            warnings,
        };
    }

    function normalizeOverrides(options) {
        const source = isPlainObject(options) ? options : {};
        return {
            entryHost: normalizeHostOverride(source.entryHost),
            entryPort: normalizePortOverride(source.entryPort),
            name: normalizeNameOverride(source.name),
            groupName: normalizeGroupNameOverride(source.groupName),
            baseConfig: normalizeBaseConfig(source.baseConfig),
            itemOverrides: normalizeItemOverrides(source.itemOverrides),
        };
    }

    function normalizeHostOverride(value) {
        const host = String(value || '').trim();
        if (!host) {
            return '';
        }

        if (/^[a-z][a-z0-9+.-]*:\/\//i.test(host)) {
            throw new Error('入口地址只填写 IP 或域名，不要带协议。');
        }
        if (/[/?#@]/.test(host) || /\s/.test(host)) {
            throw new Error('入口地址只填写 IP 或域名，不要带路径或参数。');
        }

        const bracketedIpv6 = host.match(/^\[([^\]]+)]$/);
        const normalized = bracketedIpv6 ? bracketedIpv6[1] : host;
        if (!normalized || /[\[\]]/.test(normalized)) {
            throw new Error('入口地址格式不正确。');
        }
        if (normalized.includes(':') && !isLikelyIpv6(normalized)) {
            throw new Error('入口地址不要带端口。');
        }

        return normalized;
    }

    function normalizeNameOverride(value) {
        return String(value || '').trim();
    }

    function normalizePortOverride(value) {
        const portText = String(value || '').trim();
        if (!portText) {
            return 0;
        }

        if (!/^\d+$/.test(portText)) {
            throw new Error('端口必须是 1-65535 之间的数字。');
        }

        const port = Number.parseInt(portText, 10);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            throw new Error('端口必须是 1-65535 之间的数字。');
        }

        return port;
    }

    function normalizeGroupNameOverride(value) {
        return String(value || '').trim() || DEFAULT_GROUP_NAME;
    }

    function normalizeBaseConfig(value) {
        return String(value || '').trim();
    }

    function normalizeItemOverrides(value) {
        if (!Array.isArray(value)) {
            return [];
        }

        return value.map((item) => {
            const source = isPlainObject(item) ? item : {};
            return {
                entryHost: normalizeHostOverride(source.entryHost),
                entryPort: normalizePortOverride(source.entryPort),
                name: normalizeNameOverride(source.name),
            };
        });
    }

    function resolveItemOverride(overrides, index) {
        return overrides.itemOverrides[index] || {};
    }

    function applyOverrides(parsed, overrides) {
        const next = {
            ...parsed,
            params: { ...parsed.params },
            warnings: [...parsed.warnings],
        };

        if (overrides.entryHost) {
            next.host = overrides.entryHost;
        }
        if (overrides.entryPort) {
            next.port = overrides.entryPort;
        }
        if (overrides.name) {
            next.name = overrides.name;
        }

        return next;
    }

    function normalizeSingleInput(input) {
        const lines = String(input || '')
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean);

        if (lines.length === 0) {
            throw new Error('请粘贴一条代理分享链接。');
        }

        if (lines.length > 1) {
            throw new Error('当前一次只支持转换一条链接。');
        }

        return lines[0];
    }

    function normalizeMultipleInput(input) {
        const lines = String(input || '')
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean);

        if (lines.length === 0) {
            throw new Error('请至少粘贴一条代理分享链接。');
        }

        return lines;
    }

    function resolveItemName(originalName, overrideName, index, total) {
        if (!overrideName) {
            return originalName;
        }

        return total > 1 ? `${overrideName} ${index + 1}` : overrideName;
    }

    function ensureUniqueName(name, usedNames) {
        const baseName = name || 'custom';
        const currentCount = usedNames.get(baseName) || 0;
        usedNames.set(baseName, currentCount + 1);

        if (currentCount === 0) {
            return { name: baseName, changed: false };
        }

        const uniqueName = `${baseName} ${currentCount + 1}`;
        usedNames.set(uniqueName, 1);

        return { name: uniqueName, changed: true };
    }

    function parseShareLink(raw) {
        const protocol = getProtocol(raw);

        if (!SUPPORTED_PROTOCOLS.has(protocol)) {
            throw new Error(`暂不支持该协议：${protocol || '未知'}。`);
        }

        if (protocol === 'ss') {
            return parseShadowsocks(raw);
        }

        return parseUrlBased(raw, protocol);
    }

    function getProtocol(raw) {
        const match = String(raw).match(/^([a-z0-9+.-]+):\/\//i);
        return match ? match[1].toLowerCase() : '';
    }

    function parseUrlBased(raw, protocol) {
        let url;
        try {
            url = new URL(raw);
        } catch {
            throw new Error('分享链接 URL 格式不正确。');
        }

        const params = collectParams(url.searchParams);
        const host = stripIpv6Brackets(url.hostname);
        const port = parsePort(url.port);
        const name = decodeMaybe(url.hash ? url.hash.slice(1) : '') || `${protocol}-${host}`;
        const warnings = [];

        if (!host) {
            throw new Error('缺少服务器地址。');
        }
        if (!port) {
            throw new Error('缺少服务器端口，或端口格式不正确。');
        }

        const user = decodeMaybe(url.username);
        if (!user) {
            throw new Error(protocol === 'vless' ? '缺少 VLESS UUID。' : '缺少 Trojan 密码。');
        }

        return {
            protocol,
            format: 'url',
            name,
            host,
            port,
            auth: user,
            params,
            warnings,
        };
    }

    function parseShadowsocks(raw) {
        let url;
        try {
            url = new URL(raw);
        } catch {
            return parseLegacyShadowsocks(raw);
        }

        const params = collectParams(url.searchParams);
        const name = decodeMaybe(url.hash ? url.hash.slice(1) : '') || 'ss-custom';
        const host = stripIpv6Brackets(url.hostname);
        const port = parsePort(url.port);
        const warnings = [];

        if (host && port && url.username) {
            const credentials = decodeSsCredentials(url.username, url.password);
            return {
                protocol: 'ss',
                format: 'url',
                name,
                host,
                port,
                method: credentials.method,
                password: credentials.password,
                params,
                warnings,
            };
        }

        return parseLegacyShadowsocks(raw);
    }

    function parseLegacyShadowsocks(raw) {
        const withoutScheme = raw.replace(/^ss:\/\//i, '');
        const hashIndex = withoutScheme.indexOf('#');
        const bodyWithQuery = hashIndex >= 0 ? withoutScheme.slice(0, hashIndex) : withoutScheme;
        const name = hashIndex >= 0 ? decodeMaybe(withoutScheme.slice(hashIndex + 1)) : 'ss-custom';
        const queryIndex = bodyWithQuery.indexOf('?');
        const body = queryIndex >= 0 ? bodyWithQuery.slice(0, queryIndex) : bodyWithQuery;
        const query = queryIndex >= 0 ? bodyWithQuery.slice(queryIndex + 1) : '';
        const params = collectParams(new URLSearchParams(query));
        const decoded = base64UrlDecodeSafe(body);
        const source = decoded.includes('@') ? decoded : decodeMaybe(body);
        const atIndex = source.lastIndexOf('@');

        if (atIndex < 0) {
            throw new Error('Shadowsocks 链接格式不正确。');
        }

        const credentialsPart = source.slice(0, atIndex);
        const serverPart = source.slice(atIndex + 1);
        const credentials = splitCredentials(credentialsPart);
        const server = splitHostPort(serverPart);

        return {
            protocol: 'ss',
            format: 'legacy',
            name: name || 'ss-custom',
            host: server.host,
            port: server.port,
            method: credentials.method,
            password: credentials.password,
            params,
            warnings: [],
        };
    }

    function decodeSsCredentials(rawUserInfo, rawPassword) {
        const decodedUserInfo = rawPassword
            ? `${decodeMaybe(rawUserInfo)}:${decodeMaybe(rawPassword)}`
            : decodeMaybe(rawUserInfo);
        const maybeBase64 = base64UrlDecodeSafe(decodedUserInfo);
        const source = maybeBase64.includes(':') ? maybeBase64 : decodedUserInfo;
        return splitCredentials(source);
    }

    function splitCredentials(value) {
        const index = value.indexOf(':');
        if (index <= 0) {
            throw new Error('缺少 Shadowsocks 加密方式或密码。');
        }

        const method = value.slice(0, index);
        const password = value.slice(index + 1);
        if (!method || !password) {
            throw new Error('缺少 Shadowsocks 加密方式或密码。');
        }

        return { method, password };
    }

    function splitHostPort(value) {
        const bracketMatch = value.match(/^\[([^\]]+)]:(\d+)$/);
        if (bracketMatch) {
            return { host: bracketMatch[1], port: parsePort(bracketMatch[2]) };
        }

        const index = value.lastIndexOf(':');
        if (index <= 0) {
            throw new Error('缺少服务器地址或端口。');
        }

        const host = value.slice(0, index);
        const port = parsePort(value.slice(index + 1));

        if (!host || !port) {
            throw new Error('缺少服务器地址或端口。');
        }

        return { host, port };
    }

    function toMihomoProxy(parsed) {
        if (parsed.protocol === 'ss') {
            const node = {
                name: parsed.name,
                type: 'ss',
                server: parsed.host,
                port: parsed.port,
                cipher: parsed.method,
                password: parsed.password,
                udp: true,
            };

            applySsPlugin(node, parsed.params, parsed.warnings);
            return node;
        }

        const node = {
            name: parsed.name,
            type: parsed.protocol,
            server: parsed.host,
            port: parsed.port,
            udp: true,
        };

        if (parsed.protocol === 'vless') {
            node.uuid = parsed.auth;
            node['packet-encoding'] = 'xudp';
            const encryption = pick(parsed.params, ['encryption']);
            if (encryption && encryption !== 'none') {
                node.encryption = encryption;
            }
            const flow = pick(parsed.params, ['flow']);
            if (flow) {
                node.flow = flow;
            }
        }

        if (parsed.protocol === 'trojan') {
            node.password = parsed.auth;
        }

        applyNetwork(node, parsed);
        applySecurity(node, parsed);

        return node;
    }

    function renderRawShareLink(raw, parsed, overrides) {
        if (!overrides.entryHost && !overrides.entryPort && !overrides.name) {
            return raw;
        }

        if (parsed.protocol === 'ss' && parsed.format === 'legacy') {
            return renderLegacyShadowsocksLink(parsed);
        }

        try {
            const url = new URL(raw);
            if (overrides.entryHost) {
                url.hostname = formatHostForUrl(overrides.entryHost);
            }
            if (overrides.entryPort) {
                url.port = String(overrides.entryPort);
            }
            if (overrides.name) {
                url.hash = encodeURIComponent(overrides.name);
            }
            return url.href;
        } catch {
            return raw;
        }
    }

    function renderLegacyShadowsocksLink(parsed) {
        const credentials = `${parsed.method}:${parsed.password}`;
        const server = `${formatHostForAuthority(parsed.host)}:${parsed.port}`;
        const body = base64UrlEncode(`${credentials}@${server}`).replace(/=+$/, '');
        const query = new URLSearchParams(parsed.params).toString();
        const hash = parsed.name ? `#${encodeURIComponent(parsed.name)}` : '';

        return `ss://${body}${query ? `?${query}` : ''}${hash}`;
    }

    function applyNetwork(node, parsed) {
        const params = parsed.params;
        const rawType = (pick(params, ['type', 'network']) || 'tcp').toLowerCase();

        if (rawType === 'httpupgrade') {
            node.network = 'ws';
            node['ws-opts'] = buildWsLikeOptions(params, true);
            return;
        }

        if (rawType === 'ws' || rawType === 'websocket') {
            node.network = 'ws';
            const options = buildWsLikeOptions(params, false);
            if (Object.keys(options).length > 0) {
                node['ws-opts'] = options;
            }
            return;
        }

        if (rawType === 'grpc') {
            node.network = 'grpc';
            node['grpc-opts'] = {
                'grpc-service-name': pick(params, ['serviceName', 'service', 'grpc-service-name']) || '',
            };
            return;
        }

        if (rawType === 'tcp' || rawType === 'raw') {
            node.network = 'tcp';
            return;
        }

        parsed.warnings.push(`暂未映射传输类型 "${rawType}"，已按 tcp 输出。`);
        node.network = 'tcp';
    }

    function buildWsLikeOptions(params, isHttpUpgrade) {
        const options = {};
        const rawPath = pick(params, ['path']) || '';
        const parsedPath = parseEarlyDataPath(rawPath);
        const host = pick(params, ['host']);

        if (parsedPath.path) {
            options.path = parsedPath.path;
        }
        if (host) {
            options.headers = { Host: host };
        }
        if (parsedPath.maxEarlyData !== null) {
            options['max-early-data'] = parsedPath.maxEarlyData;
            options['early-data-header-name'] = 'Sec-WebSocket-Protocol';
        }
        if (isHttpUpgrade) {
            options['v2ray-http-upgrade'] = true;
            options['v2ray-http-upgrade-fast-open'] = true;
        }

        return options;
    }

    function parseEarlyDataPath(path) {
        const marker = '?ed=';
        const index = path.indexOf(marker);
        if (index < 0) {
            return { path, maxEarlyData: null };
        }

        const pathPart = path.slice(0, index);
        const edPart = path.slice(index + marker.length).split(/[/?&#]/)[0];
        const parsed = Number.parseInt(edPart, 10);

        return {
            path: pathPart,
            maxEarlyData: Number.isFinite(parsed) ? parsed : null,
        };
    }

    function applySecurity(node, parsed) {
        const params = parsed.params;
        const security = (pick(params, ['security']) || '').toLowerCase();
        const sni = pick(params, ['sni', 'servername', 'serverName', 'peer']);
        const fingerprint = pick(params, ['fp', 'fingerprint', 'client-fingerprint']);
        const alpn = pick(params, ['alpn']);

        if (security === 'tls' || security === 'reality') {
            node.tls = true;
        }

        if (parsed.protocol === 'trojan') {
            if (sni) {
                node.sni = sni;
            }
        } else if (sni) {
            node.servername = sni;
        }

        if (alpn) {
            node.alpn = alpn
                .split(',')
                .map((item) => item.trim())
                .filter(Boolean);
        }

        if (fingerprint) {
            node['client-fingerprint'] = fingerprint;
        } else if (security === 'tls' || security === 'reality') {
            node['client-fingerprint'] = 'chrome';
        }

        if (isTruthy(pick(params, ['allowInsecure', 'skip-cert-verify', 'insecure']))) {
            node['skip-cert-verify'] = true;
        }

        if (security === 'reality') {
            const realityOptions = {};
            const publicKey = pick(params, ['pbk', 'public-key', 'publicKey']);
            const shortId = pick(params, ['sid', 'short-id', 'shortId']);

            if (publicKey) {
                realityOptions['public-key'] = publicKey;
            }
            if (shortId) {
                realityOptions['short-id'] = shortId;
            }

            if (Object.keys(realityOptions).length > 0) {
                node['reality-opts'] = realityOptions;
            } else {
                parsed.warnings.push('Reality 链接缺少 public key 参数。');
            }
        }
    }

    function applySsPlugin(node, params, warnings) {
        const plugin = pick(params, ['plugin']);
        if (!plugin) {
            return;
        }

        const decodedPlugin = decodeMaybe(plugin);
        if (!decodedPlugin.startsWith('v2ray-plugin')) {
            warnings.push('暂不支持该 Shadowsocks plugin，已忽略。');
            return;
        }

        const optionsText = decodedPlugin.split(';').slice(1);
        const options = {};
        for (const item of optionsText) {
            const index = item.indexOf('=');
            if (index < 0) {
                options[item] = 'true';
            } else {
                options[item.slice(0, index)] = item.slice(index + 1);
            }
        }

        if (options.mode === 'websocket' || options.mode === 'ws') {
            node.network = 'ws';
            node['ws-opts'] = {};
            if (options.path) {
                node['ws-opts'].path = options.path;
            }
            if (options.host) {
                node['ws-opts'].headers = { Host: options.host };
            }
        }

        if (options.tls === 'true' || options.tls === '1') {
            node.tls = true;
        }
    }

    function renderGroupSnippet(proxyNames, groupName = DEFAULT_GROUP_NAME) {
        const proxies = Array.isArray(proxyNames) ? proxyNames : [proxyNames];

        return renderYamlObject({
            'proxy-groups': [
                {
                    name: groupName,
                    type: 'select',
                    proxies,
                },
            ],
        });
    }

    function renderRuleSnippet(groupName = DEFAULT_GROUP_NAME) {
        return renderYamlObject({
            rules: [`MATCH,${groupName}`],
        });
    }

    function renderMihomoConfig(proxies, groupName = DEFAULT_GROUP_NAME) {
        return renderYamlObject({
            'mixed-port': 7890,
            'socks-port': 7891,
            'redir-port': 7892,
            'allow-lan': true,
            mode: 'global',
            'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            dns: {
                enable: true,
                'use-hosts': true,
                'enhanced-mode': 'fake-ip',
                'fake-ip-range': '198.18.0.1/16',
                'default-nameserver': ['1.1.1.1', '8.8.8.8'],
                nameserver: ['1.1.1.1', '8.8.8.8'],
                'fake-ip-filter': [
                    '*.lan',
                    'stun.*.*.*',
                    'stun.*.*',
                    'time.windows.com',
                    'time.nist.gov',
                    'time.apple.com',
                    'time.asia.apple.com',
                    '*.openwrt.pool.ntp.org',
                    'pool.ntp.org',
                    'ntp.ubuntu.com',
                    'time1.apple.com',
                    'time2.apple.com',
                    'time3.apple.com',
                    'time4.apple.com',
                    'time5.apple.com',
                    'time6.apple.com',
                    'time7.apple.com',
                    'time1.google.com',
                    'time2.google.com',
                    'time3.google.com',
                    'time4.google.com',
                    'api.joox.com',
                    'joox.com',
                    '*.xiami.com',
                    '*.msftconnecttest.com',
                    '*.msftncsi.com',
                    '+.xboxlive.com',
                    '*.*.stun.playstation.net',
                    'xbox.*.*.microsoft.com',
                    '*.ipv6.microsoft.com',
                    'speedtest.cros.wr.pvp.net',
                ],
            },
            proxies,
            'proxy-groups': [
                {
                    name: groupName,
                    type: 'select',
                    proxies: proxies.map((proxy) => proxy.name),
                },
            ],
            rules: [`MATCH,${groupName}`],
        });
    }

    function renderMergedMihomoConfig(baseConfig, proxies, groupName = DEFAULT_GROUP_NAME) {
        const cleanBaseConfig = normalizeBaseConfig(baseConfig);
        if (!cleanBaseConfig) {
            return renderMihomoConfig(proxies, groupName);
        }

        let mergedConfig = repairKnownGroupRuleMismatch(cleanBaseConfig, groupName);
        mergedConfig = appendProxiesToConfig(mergedConfig, proxies);
        mergedConfig = mergeProxyGroupIntoConfig(mergedConfig, proxies, groupName);
        mergedConfig = ensureRuleInConfig(mergedConfig, groupName);

        return mergedConfig.trim();
    }

    function repairKnownGroupRuleMismatch(config, groupName) {
        if (groupName !== DEFAULT_GROUP_NAME) {
            return config;
        }

        return config.replace(/MATCH,\s*→\s*Remnawave/g, `MATCH,${DEFAULT_GROUP_NAME}`);
    }

    function appendProxiesToConfig(config, proxies) {
        return appendToTopLevelListSection(config, 'proxies', renderYamlList(proxies));
    }

    function mergeProxyGroupIntoConfig(config, proxies, groupName) {
        const section = findTopLevelSection(config, 'proxy-groups');
        if (!section) {
            return appendToTopLevelListSection(
                config,
                'proxy-groups',
                renderProxyGroupItem(proxies, groupName),
            );
        }

        const lines = config.split('\n');
        const group = findProxyGroup(lines, section, groupName);
        if (!group) {
            return insertLinesAt(
                lines,
                section.end,
                splitLines(renderProxyGroupItem(proxies, groupName)),
            );
        }

        const existingNames = collectProxyNamesFromGroup(lines, group);
        const namesToInsert = proxies
            .map((proxy) => proxy.name)
            .filter((name) => !existingNames.has(name));

        if (namesToInsert.length === 0) {
            return config;
        }

        const insertIndex = group.proxiesEndIndex ?? group.end;
        const indent = group.proxyItemIndent ?? '      ';
        const linesToInsert = namesToInsert.map((name) => `${indent}- ${renderScalar(name)}`);

        return insertLinesAt(lines, insertIndex, linesToInsert);
    }

    function ensureRuleInConfig(config, groupName) {
        const rule = `MATCH,${groupName}`;
        if (config.includes(rule)) {
            return config;
        }

        return appendToTopLevelListSection(config, 'rules', `- ${renderScalar(rule)}`);
    }

    function appendToTopLevelListSection(config, sectionName, listYaml) {
        const section = findTopLevelSection(config, sectionName);
        if (!section) {
            const separator = config.trim() ? '\n\n' : '';
            return `${config.trimEnd()}${separator}${sectionName}:\n${listYaml}`;
        }

        const lines = config.split('\n');
        return insertLinesAt(lines, section.end, splitLines(listYaml));
    }

    function renderProxyGroupItem(proxies, groupName) {
        return renderYamlList([
            {
                name: groupName,
                type: 'select',
                proxies: proxies.map((proxy) => proxy.name),
            },
        ]);
    }

    function findTopLevelSection(config, sectionName) {
        const lines = config.split('\n');
        const sectionPattern = new RegExp(`^${escapeRegExp(sectionName)}\\s*:`);
        let start = -1;

        for (let index = 0; index < lines.length; index += 1) {
            if (sectionPattern.test(lines[index])) {
                start = index;
                break;
            }
        }

        if (start < 0) {
            return null;
        }

        let end = lines.length;
        for (let index = start + 1; index < lines.length; index += 1) {
            if (/^[A-Za-z0-9_-][A-Za-z0-9_-]*\s*:/.test(lines[index])) {
                end = index;
                break;
            }
        }

        return { start, end };
    }

    function findProxyGroup(lines, section, groupName) {
        const quotedPattern = new RegExp(
            '^\\s*-\\s+name:\\s*' + escapeRegExp(renderScalar(groupName)) + '\\s*$',
        );
        const barePattern = new RegExp(
            '^\\s*-\\s+name:\\s*' + escapeRegExp(groupName) + '\\s*$',
        );

        for (let index = section.start + 1; index < section.end; index += 1) {
            const line = lines[index];
            if (!quotedPattern.test(line) && !barePattern.test(line)) {
                continue;
            }

            let end = section.end;
            for (let next = index + 1; next < section.end; next += 1) {
                if (/^\s*-\s+name:/.test(lines[next])) {
                    end = next;
                    break;
                }
            }

            const proxiesLineIndex = findNestedKeyLine(lines, index + 1, end, 'proxies');
            if (proxiesLineIndex < 0) {
                return { start: index, end, proxiesStartIndex: -1, proxiesEndIndex: end };
            }

            const proxiesEndIndex = findNestedListEnd(lines, proxiesLineIndex + 1, end);
            const proxyItemIndent = inferListItemIndent(lines, proxiesLineIndex, proxiesEndIndex);

            return {
                start: index,
                end,
                proxiesStartIndex: proxiesLineIndex + 1,
                proxiesEndIndex,
                proxyItemIndent,
            };
        }

        return null;
    }

    function findNestedKeyLine(lines, start, end, key) {
        const keyPattern = new RegExp(`^\\s+${escapeRegExp(key)}\\s*:`);
        for (let index = start; index < end; index += 1) {
            if (keyPattern.test(lines[index])) {
                return index;
            }
        }
        return -1;
    }

    function findNestedListEnd(lines, start, end) {
        for (let index = start; index < end; index += 1) {
            if (/^\s{4}[A-Za-z0-9_-]+\s*:/.test(lines[index])) {
                return index;
            }
        }
        return end;
    }

    function inferListItemIndent(lines, proxiesLineIndex, proxiesEndIndex) {
        for (let index = proxiesLineIndex + 1; index < proxiesEndIndex; index += 1) {
            const match = lines[index].match(/^(\s*)-/);
            if (match) {
                return match[1];
            }
        }
        return '      ';
    }

    function collectProxyNamesFromGroup(lines, group) {
        const names = new Set();
        if (group.proxiesStartIndex < 0 || group.proxiesEndIndex === undefined) {
            return names;
        }

        for (let index = group.proxiesStartIndex; index < group.proxiesEndIndex; index += 1) {
            const match = lines[index].match(/^\s*-\s*(.+?)\s*$/);
            if (!match) {
                continue;
            }
            names.add(unquoteYamlScalar(match[1]));
        }

        return names;
    }

    function insertLinesAt(lines, index, linesToInsert) {
        const nextLines = [...lines];
        nextLines.splice(index, 0, ...linesToInsert);
        return nextLines.join('\n');
    }

    function splitLines(value) {
        return String(value || '')
            .split('\n')
            .filter((line) => line.length > 0);
    }

    function unquoteYamlScalar(value) {
        const trimmed = String(value || '').trim();
        if (
            (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
            (trimmed.startsWith("'") && trimmed.endsWith("'"))
        ) {
            return trimmed.slice(1, -1);
        }
        return trimmed;
    }

    function escapeRegExp(value) {
        return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    function renderYamlList(items) {
        return items.map((item) => renderYamlListItem(item, 0)).join('\n');
    }

    function renderYamlObject(object) {
        return renderYamlMap(object, 0);
    }

    function renderYamlListItem(item, indent) {
        const spaces = ' '.repeat(indent);
        const entries = Object.entries(item);
        if (entries.length === 0) {
            return `${spaces}- {}`;
        }

        const [firstKey, firstValue] = entries[0];
        const lines = [`${spaces}- ${firstKey}: ${renderScalar(firstValue)}`];

        for (const [key, value] of entries.slice(1)) {
            appendYamlValue(lines, key, value, indent + 2);
        }

        return lines.join('\n');
    }

    function renderYamlMap(object, indent) {
        const lines = [];
        for (const [key, value] of Object.entries(object)) {
            appendYamlValue(lines, key, value, indent);
        }
        return lines.join('\n');
    }

    function appendYamlValue(lines, key, value, indent) {
        const spaces = ' '.repeat(indent);

        if (Array.isArray(value)) {
            lines.push(`${spaces}${key}:`);
            if (value.length === 0) {
                return;
            }
            for (const item of value) {
                if (isPlainObject(item)) {
                    lines.push(renderYamlListItem(item, indent + 2));
                } else {
                    lines.push(`${' '.repeat(indent + 2)}- ${renderScalar(item)}`);
                }
            }
            return;
        }

        if (isPlainObject(value)) {
            lines.push(`${spaces}${key}:`);
            lines.push(renderYamlMap(value, indent + 2));
            return;
        }

        lines.push(`${spaces}${key}: ${renderScalar(value)}`);
    }

    function renderScalar(value) {
        if (typeof value === 'number' || typeof value === 'boolean') {
            return String(value);
        }
        if (value === null || value === undefined) {
            return 'null';
        }
        return JSON.stringify(String(value));
    }

    function isPlainObject(value) {
        return value !== null && typeof value === 'object' && !Array.isArray(value);
    }

    function collectParams(searchParams) {
        const params = {};
        for (const [key, value] of searchParams.entries()) {
            params[key] = value;
        }
        return params;
    }

    function pick(params, names) {
        for (const name of names) {
            if (params[name] !== undefined && params[name] !== '') {
                return params[name];
            }
        }
        return '';
    }

    function parsePort(value) {
        const port = Number.parseInt(value, 10);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            return 0;
        }
        return port;
    }

    function stripIpv6Brackets(host) {
        return String(host || '').replace(/^\[/, '').replace(/]$/, '');
    }

    function formatHostForUrl(host) {
        return isLikelyIpv6(host) ? `[${stripIpv6Brackets(host)}]` : host;
    }

    function formatHostForAuthority(host) {
        return isLikelyIpv6(host) ? `[${stripIpv6Brackets(host)}]` : host;
    }

    function isLikelyIpv6(host) {
        return stripIpv6Brackets(host).split(':').length > 2;
    }

    function decodeMaybe(value) {
        try {
            return decodeURIComponent(String(value || ''));
        } catch {
            return String(value || '');
        }
    }

    function base64UrlDecodeSafe(value) {
        const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
        const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');

        try {
            if (typeof Buffer !== 'undefined') {
                return Buffer.from(padded, 'base64').toString('utf8');
            }
            return decodeURIComponent(
                Array.prototype.map
                    .call(atob(padded), (char) =>
                        `%${char.charCodeAt(0).toString(16).padStart(2, '0')}`,
                    )
                    .join(''),
            );
        } catch {
            return '';
        }
    }

    function base64UrlEncode(value) {
        let encoded;
        if (typeof Buffer !== 'undefined') {
            encoded = Buffer.from(String(value), 'utf8').toString('base64');
        } else {
            encoded = btoa(
                encodeURIComponent(String(value)).replace(/%([0-9A-F]{2})/g, (_, hex) =>
                    String.fromCharCode(Number.parseInt(hex, 16)),
                ),
            );
        }

        return encoded.replace(/\+/g, '-').replace(/\//g, '_');
    }

    function isTruthy(value) {
        return ['1', 'true', 'yes'].includes(String(value || '').toLowerCase());
    }

    const api = {
        convertShareLink,
        convertShareLinks,
        normalizeHostOverride,
        parseShareLink,
        renderMergedMihomoConfig,
        renderMihomoConfig,
        toMihomoProxy,
        renderYamlList,
        renderYamlObject,
    };

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }

    root.SubscriptionConverter = api;
})(typeof window !== 'undefined' ? window : globalThis);
