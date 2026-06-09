(function (root) {
    'use strict';

    const SUPPORTED_PROTOCOLS = new Set(['vless', 'trojan', 'ss']);

    function convertShareLink(input) {
        const raw = normalizeSingleInput(input);
        const parsed = parseShareLink(raw);
        const mihomoProxy = toMihomoProxy(parsed);
        const mihomoYaml = renderYamlList([mihomoProxy]);
        const groupSnippet = renderGroupSnippet(mihomoProxy.name);

        return {
            parsed,
            mihomoProxy,
            mihomoYaml,
            groupSnippet,
            xrayRaw: raw,
            warnings: parsed.warnings,
        };
    }

    function normalizeSingleInput(input) {
        const lines = String(input || '')
            .split(/\r?\n/)
            .map((line) => line.trim())
            .filter(Boolean);

        if (lines.length === 0) {
            throw new Error('Paste one proxy share link.');
        }

        if (lines.length > 1) {
            throw new Error('This tool converts one link at a time.');
        }

        return lines[0];
    }

    function parseShareLink(raw) {
        const protocol = getProtocol(raw);

        if (!SUPPORTED_PROTOCOLS.has(protocol)) {
            throw new Error(`Unsupported protocol: ${protocol || 'unknown'}.`);
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
            throw new Error('Invalid share link URL.');
        }

        const params = collectParams(url.searchParams);
        const host = stripIpv6Brackets(url.hostname);
        const port = parsePort(url.port);
        const name = decodeMaybe(url.hash ? url.hash.slice(1) : '') || `${protocol}-${host}`;
        const warnings = [];

        if (!host) {
            throw new Error('Missing server host.');
        }
        if (!port) {
            throw new Error('Missing or invalid server port.');
        }

        const user = decodeMaybe(url.username);
        if (!user) {
            throw new Error(protocol === 'vless' ? 'Missing VLESS UUID.' : 'Missing Trojan password.');
        }

        return {
            protocol,
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
            throw new Error('Invalid Shadowsocks link.');
        }

        const credentialsPart = source.slice(0, atIndex);
        const serverPart = source.slice(atIndex + 1);
        const credentials = splitCredentials(credentialsPart);
        const server = splitHostPort(serverPart);

        return {
            protocol: 'ss',
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
            throw new Error('Missing Shadowsocks method or password.');
        }

        const method = value.slice(0, index);
        const password = value.slice(index + 1);
        if (!method || !password) {
            throw new Error('Missing Shadowsocks method or password.');
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
            throw new Error('Missing server host or port.');
        }

        const host = value.slice(0, index);
        const port = parsePort(value.slice(index + 1));

        if (!host || !port) {
            throw new Error('Missing server host or port.');
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

        parsed.warnings.push(`Transport "${rawType}" is not mapped; using tcp.`);
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
                parsed.warnings.push('Reality link is missing public key parameters.');
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
            warnings.push('Unsupported Shadowsocks plugin was ignored.');
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

    function renderGroupSnippet(proxyName) {
        return renderYamlObject({
            'proxy-groups': [
                {
                    name: 'Remnawave',
                    type: 'select',
                    proxies: [proxyName],
                },
            ],
        });
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

    function isTruthy(value) {
        return ['1', 'true', 'yes'].includes(String(value || '').toLowerCase());
    }

    const api = {
        convertShareLink,
        parseShareLink,
        toMihomoProxy,
        renderYamlList,
        renderYamlObject,
    };

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = api;
    }

    root.SubscriptionConverter = api;
})(typeof window !== 'undefined' ? window : globalThis);
