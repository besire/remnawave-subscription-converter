# Subscription Converter

Open `subscription-converter.html` in a browser. The tool runs locally and does not call a backend.

Input one `vless://`, `trojan://`, or `ss://` share link. Copy the generated Mihomo proxy YAML into the `proxies:` section of a Remnawave Mihomo subscription template, then add the generated proxy name to the desired `proxy-groups` entry.

Run the parser checks with:

```bash
node tools/subscription-converter.test.js
```

## Deploy With Dokploy

Create a GitHub repository from this `tools/` directory, then create a Dokploy app from that repository.

Dokploy settings:

- Build type: Dockerfile
- Dockerfile path: `Dockerfile`
- Container port: `80`
- Domain: your converter domain, for example `subconv.example.com`
- HTTPS: enable through Dokploy/Traefik

Local build check:

```bash
docker build -t subscription-converter .
docker run --rm -p 8088:80 subscription-converter
```
