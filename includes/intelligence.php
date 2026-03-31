<?php
// includes/intelligence.php
// Domain Intelligence / OSINT module
// Surse: DNS nativ PHP, crt.sh, ipinfo.io, HackerTarget, port scan direct

function getDomainIntelligence(string $domain): array {
    return [
        'dns'     => getDnsRecords($domain),
        'ssl'     => getSslInfo($domain),
        'email'   => getEmailSecurity($domain),
        'hosting' => getHostingInfo($domain),
        'subdoms' => getSubdomains($domain),
        'ports'   => getOpenPorts($domain),
    ];
}

// -------------------------------------------------------
// DNS Records
// -------------------------------------------------------
function getDnsRecords(string $domain): array {
    $out = ['a'=>[],'aaaa'=>[],'mx'=>[],'ns'=>[],'txt'=>[],'caa'=>[],'soa'=>null];

    try {
        $a = @dns_get_record($domain, DNS_A);
        if ($a) foreach ($a as $r) $out['a'][] = $r['ip'];

        $aaaa = @dns_get_record($domain, DNS_AAAA);
        if ($aaaa) foreach ($aaaa as $r) $out['aaaa'][] = $r['ipv6'];

        $mx = @dns_get_record($domain, DNS_MX);
        if ($mx) {
            usort($mx, fn($a,$b) => $a['pri'] <=> $b['pri']);
            foreach ($mx as $r) $out['mx'][] = ['host' => $r['target'], 'priority' => $r['pri'], 'provider' => detectMxProvider($r['target'])];
        }

        $ns = @dns_get_record($domain, DNS_NS);
        if ($ns) foreach ($ns as $r) $out['ns'][] = ['host' => $r['target'], 'provider' => detectNsProvider($r['target'])];

        $txt = @dns_get_record($domain, DNS_TXT);
        if ($txt) foreach ($txt as $r) {
            $val = is_array($r['txt']) ? implode('', $r['txt']) : ($r['txt'] ?? '');
            $out['txt'][] = ['value' => $val, 'type' => classifyTxt($val)];
        }

        $caa = @dns_get_record($domain, DNS_CAA);
        if ($caa) foreach ($caa as $r) $out['caa'][] = $r['value'] ?? ($r['tag'] ?? '');

        $soa = @dns_get_record($domain, DNS_SOA);
        if ($soa && isset($soa[0])) $out['soa'] = $soa[0]['mname'] ?? null;

    } catch (Exception $e) {}

    return $out;
}

function detectMxProvider(string $host): string {
    $h = strtolower($host);
    if (str_contains($h, 'google') || str_contains($h, 'aspmx') || str_contains($h, 'googlemail')) return 'Google Workspace';
    if (str_contains($h, 'outlook') || str_contains($h, 'microsoft') || str_contains($h, 'office365')) return 'Microsoft 365';
    if (str_contains($h, 'mailchimp') || str_contains($h, 'mandrillapp')) return 'Mailchimp';
    if (str_contains($h, 'sendgrid')) return 'SendGrid';
    if (str_contains($h, 'amazonses') || str_contains($h, 'amazonaws')) return 'Amazon SES';
    if (str_contains($h, 'protonmail') || str_contains($h, 'proton')) return 'ProtonMail';
    if (str_contains($h, 'zoho')) return 'Zoho Mail';
    if (str_contains($h, 'mailgun')) return 'Mailgun';
    if (str_contains($h, 'cloudflare')) return 'Cloudflare Email';
    if (str_contains($h, 'yandex')) return 'Yandex Mail';
    if (str_contains($h, 'rdslink') || str_contains($h, 'rds.ro')) return 'RDS & RCS (Digi Romania)';
    if (str_ends_with(strtolower($host), '.ro')) return 'Hosting .ro';
    return 'Custom/Unknown';
}

function detectNsProvider(string $host): string {
    $h = strtolower($host);
    if (str_contains($h, 'cloudflare'))   return 'Cloudflare DNS (CDN/Security global)';
    if (str_contains($h, 'amazonaws') || str_contains($h, 'awsdns')) return 'Amazon Route 53 (AWS)';
    if (str_contains($h, 'googledomains') || str_contains($h, 'google')) return 'Google Cloud DNS';
    if (str_contains($h, 'azure') || str_contains($h, 'microsoft')) return 'Microsoft Azure DNS';
    if (str_contains($h, 'namecheap') || str_contains($h, 'registrar-servers')) return 'Namecheap DNS';
    if (str_contains($h, 'godaddy') || str_contains($h, 'domaincontrol')) return 'GoDaddy DNS';
    if (str_contains($h, 'hetzner'))      return 'Hetzner Online DNS (Germania)';
    if (str_contains($h, 'digitalocean')) return 'DigitalOcean DNS';
    if (str_contains($h, 'rdslink') || str_contains($h, 'rds.ro'))
        return 'RDS & RCS (Digi Romania) — cel mai mare ISP din Romania';
    if (str_contains($h, 'rotld') || str_contains($h, 'nic.ro'))
        return 'ROTLD — Registrul .ro (ICI Bucuresti), administratorul domeniilor .ro';
    if (str_contains($h, 'voxility'))
        return 'Voxility Romania — hosting si anti-DDoS romanesc';
    if (str_contains($h, 'm247'))
        return 'M247 Romania — provider de hosting si connectivity';
    if (str_contains($h, 'chroot'))
        return 'Chroot Security Romania — hosting si securitate';
    if (str_contains($h, 'xservers') || str_contains($h, 'xserver.ro'))
        return 'xServers Romania — hosting romanesc';
    if (str_contains($h, 'hostway'))
        return 'Hostway Romania — hosting romanesc';
    if (str_ends_with($h, '.ro'))
        return 'DNS hostat in Romania (nameserver cu TLD .ro)';
    if (str_contains($h, 'cpanel') || str_contains($h, 'whm')) return 'cPanel/WHM DNS (hosting shared)';
    return 'DNS personalizat — ' . $host;
}

function classifyTxt(string $val): string {
    $v = strtolower($val);
    if (str_starts_with($v, 'v=spf1')) return 'SPF';
    if (str_contains($v, 'v=dkim1') || str_contains($v, 'k=rsa') || str_contains($v, 'k=ed25519')) return 'DKIM';
    if (str_starts_with($v, 'v=dmarc1')) return 'DMARC';
    if (str_contains($v, 'google-site-verification')) return 'Google Verify';
    if (str_contains($v, 'facebook-domain-verification')) return 'Facebook Verify';
    if (str_contains($v, 'ms=ms') || str_contains($v, 'ms=')) return 'Microsoft Verify';
    if (str_contains($v, 'docusign')) return 'DocuSign';
    if (str_contains($v, 'globalsign')) return 'GlobalSign SSL';
    if (str_contains($v, 'atlassian-domain')) return 'Atlassian';
    return 'TXT';
}

// -------------------------------------------------------
// Email Security (SPF, DKIM, DMARC)
// -------------------------------------------------------
function getEmailSecurity(string $domain): array {
    $out = ['spf' => null, 'dmarc' => null, 'dkim_hint' => null, 'score' => 0, 'issues' => []];

    $txt = @dns_get_record($domain, DNS_TXT);
    if ($txt) {
        foreach ($txt as $r) {
            $val = is_array($r['txt']) ? implode('', $r['txt']) : ($r['txt'] ?? '');
            if (str_starts_with(strtolower($val), 'v=spf1')) {
                $out['spf'] = ['raw' => $val, 'summary' => parseSPF($val)];
                $out['score']++;
            }
        }
    }
    if (!$out['spf']) $out['issues'][] = 'SPF lipseste — emailurile pot fi falsificate';

    $dmarc = @dns_get_record('_dmarc.' . $domain, DNS_TXT);
    if ($dmarc) {
        foreach ($dmarc as $r) {
            $val = is_array($r['txt']) ? implode('', $r['txt']) : ($r['txt'] ?? '');
            if (str_contains(strtolower($val), 'v=dmarc1')) {
                $out['dmarc'] = ['raw' => $val, 'summary' => parseDMARC($val)];
                $out['score']++;
            }
        }
    }
    if (!$out['dmarc']) $out['issues'][] = 'DMARC lipseste — domeniu vulnerabil la spoofing';

    $selectors = ['default', 'google', 'k1', 'k2', 'mail', 'selector1', 'selector2', 'dkim', 's1', 's2'];
    foreach ($selectors as $sel) {
        $dkim = @dns_get_record($sel . '._domainkey.' . $domain, DNS_TXT);
        if ($dkim) {
            foreach ($dkim as $r) {
                $val = is_array($r['txt']) ? implode('', $r['txt']) : ($r['txt'] ?? '');
                if (str_contains(strtolower($val), 'v=dkim1') || str_contains($val, 'k=rsa') || str_contains($val, 'p=')) {
                    $out['dkim_hint'] = "Selector: $sel";
                    $out['score']++;
                    break 2;
                }
            }
        }
    }
    if (!$out['dkim_hint']) $out['issues'][] = 'DKIM nu a putut fi detectat automat';

    return $out;
}

function parseSPF(string $val): string {
    $parts = [];
    if (preg_match('/\+?all\b/', $val)) $parts[] = '⚠️ Permissive (+all)';
    if (preg_match('/~all\b/', $val))   $parts[] = 'SoftFail (~all)';
    if (preg_match('/-all\b/', $val))   $parts[] = '✓ Strict (-all)';
    if (str_contains($val, 'include:google')) $parts[] = 'Google';
    if (str_contains($val, 'include:_spf.google')) $parts[] = 'Google Workspace';
    if (str_contains($val, 'include:spf.protection.outlook')) $parts[] = 'Microsoft 365';
    if (str_contains($val, 'include:sendgrid')) $parts[] = 'SendGrid';
    if (str_contains($val, 'include:mailchimp') || str_contains($val, 'include:servers.mcsv')) $parts[] = 'Mailchimp';
    if (str_contains($val, 'include:amazonses')) $parts[] = 'Amazon SES';
    if (str_contains($val, 'include:_spf.mailgun')) $parts[] = 'Mailgun';
    if (preg_match_all('/ip4:([^\s]+)/', $val, $m)) {
        foreach (array_slice($m[1], 0, 3) as $ip) $parts[] = "IP: $ip";
    }
    return implode(', ', $parts) ?: 'Configurat';
}

function parseDMARC(string $val): string {
    $parts = [];
    if (preg_match('/p=(\w+)/', $val, $m)) {
        $p = $m[1];
        if ($p === 'none')           $parts[] = '⚠️ Policy: none (monitoring only)';
        elseif ($p === 'quarantine') $parts[] = '✓ Policy: quarantine';
        elseif ($p === 'reject')     $parts[] = '✓✓ Policy: reject (strict)';
    }
    if (preg_match('/rua=mailto:([^\s;]+)/', $val, $m)) $parts[] = "Rapoarte: {$m[1]}";
    if (preg_match('/pct=(\d+)/', $val, $m) && $m[1] < 100) $parts[] = "Aplica pe {$m[1]}%";
    return implode(', ', $parts) ?: 'Configurat';
}

// -------------------------------------------------------
// SSL Info
// -------------------------------------------------------
function getSslInfo(string $domain): array {
    $out = ['valid' => false, 'issuer' => null, 'expires' => null, 'days_left' => null, 'sans' => [], 'error' => null];

    $ctx = stream_context_create(['ssl' => [
        'capture_peer_cert' => true,
        'verify_peer'       => false,
        'verify_peer_name'  => false,
    ]]);

    $fp = @stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) { $out['error'] = 'Port 443 inaccesibil sau SSL invalid'; return $out; }

    $cert = stream_context_get_params($fp)['options']['ssl']['peer_certificate'] ?? null;
    fclose($fp);

    if (!$cert) { $out['error'] = 'Certificat SSL negasit'; return $out; }

    $info = openssl_x509_parse($cert);
    $out['valid'] = true;

    $issuerO  = $info['issuer']['O'] ?? '';
    $issuerCN = $info['issuer']['CN'] ?? '';
    if (str_contains(strtolower($issuerO . $issuerCN), "let's encrypt") || str_contains(strtolower($issuerCN), 'r3') || str_contains(strtolower($issuerCN), 'e1')) {
        $out['issuer'] = "Let's Encrypt (gratuit, auto-reinnoit)";
    } elseif (str_contains(strtolower($issuerO . $issuerCN), 'cloudflare')) {
        $out['issuer'] = 'Cloudflare SSL';
    } elseif (str_contains(strtolower($issuerO), 'comodo') || str_contains(strtolower($issuerO), 'sectigo')) {
        $out['issuer'] = 'Sectigo/Comodo';
    } elseif (str_contains(strtolower($issuerO), 'digicert')) {
        $out['issuer'] = 'DigiCert';
    } elseif (str_contains(strtolower($issuerO), 'godaddy')) {
        $out['issuer'] = 'GoDaddy SSL';
    } elseif (str_contains(strtolower($issuerO), 'globalsign')) {
        $out['issuer'] = 'GlobalSign';
    } else {
        $out['issuer'] = trim($issuerO ?: $issuerCN) ?: 'Unknown CA';
    }

    $validTo = $info['validTo_time_t'] ?? 0;
    if ($validTo) {
        $out['expires']   = date('Y-m-d', $validTo);
        $out['days_left'] = (int)ceil(($validTo - time()) / 86400);
    }

    $sans = [];
    if (isset($info['extensions']['subjectAltName'])) {
        preg_match_all('/DNS:([^\s,]+)/', $info['extensions']['subjectAltName'], $m);
        $sans = array_slice($m[1] ?? [], 0, 15);
    }
    $out['sans'] = $sans;

    return $out;
}

// -------------------------------------------------------
// Hosting / ASN / IP Info
// -------------------------------------------------------
function getHostingInfo(string $domain): array {
    $out = ['ip' => null, 'asn' => null, 'org' => null, 'country' => null, 'city' => null, 'shared_count' => null, 'reverse_dns' => null];

    $ip = @gethostbyname($domain);
    if (!$ip || $ip === $domain) return $out;
    $out['ip'] = $ip;

    $rdns = @gethostbyaddr($ip);
    if ($rdns && $rdns !== $ip) $out['reverse_dns'] = $rdns;

    $ctx = stream_context_create(['http' => ['timeout' => 5, 'header' => 'User-Agent: DomainWatch/1.0']]);
    $raw = @file_get_contents("https://ipinfo.io/{$ip}/json", false, $ctx);
    if ($raw) {
        $data = json_decode($raw, true);
        if ($data) {
            $out['country'] = $data['country'] ?? null;
            $out['city']    = $data['city'] ?? null;
            if (preg_match('/^(AS\d+)\s+(.+)$/', $data['org'] ?? '', $m)) {
                $out['asn'] = $m[1];
                $out['org'] = humanizeOrg($m[2]);
            } else {
                $out['org'] = $data['org'] ?? null;
            }
        }
    }

    $raw2 = @file_get_contents("https://api.hackertarget.com/reverseiplookup/?q={$ip}", false, $ctx);
    if ($raw2 && !str_contains($raw2, 'error') && !str_contains($raw2, 'API count')) {
        $domains = array_filter(explode("\n", trim($raw2)));
        $out['shared_count'] = count($domains);
    }

    return $out;
}

function humanizeOrg(string $org): string {
    $map = [
        'HETZNER'      => 'Hetzner Online GmbH (Germania)',
        'OVH'          => 'OVH SAS (Franta)',
        'AMAZON'       => 'Amazon AWS',
        'MICROSOFT'    => 'Microsoft Azure',
        'GOOGLE'       => 'Google Cloud',
        'DIGITALOCEAN' => 'DigitalOcean',
        'LINODE'       => 'Akamai/Linode',
        'CLOUDFLARE'   => 'Cloudflare',
        'FASTLY'       => 'Fastly CDN',
        'VULTR'        => 'Vultr',
        'CONTABO'      => 'Contabo GmbH',
        'RCS&RDS'      => 'RCS&RDS (Digi Romania)',
        'DIGI'         => 'Digi Romania',
        'UPC'          => 'Liberty Global/UPC',
        'TELEKOM'      => 'Deutsche Telekom',
    ];
    $orgUpper = strtoupper($org);
    foreach ($map as $key => $val) {
        if (str_contains($orgUpper, $key)) return $val;
    }
    return $org;
}

// -------------------------------------------------------
// Subdomenii — 3 surse cu fallback automat
// -------------------------------------------------------
function getSubdomains(string $domain): array {
    $result = _subdomainsFromCrtSh($domain);
    if ($result !== null) return $result;

    $result = _subdomainsFromHackerTarget($domain);
    if ($result !== null) return $result;

    $result = _subdomainsFromSsl($domain);
    if ($result !== null) return $result;

    return [
        'list'       => [],
        'count'      => 0,
        'first_seen' => null,
        'source'     => null,
        'error'      => 'Serviciile externe (crt.sh, HackerTarget) sunt inaccesibile de pe acest server de hosting.',
        'fallback'   => true,
    ];
}

function _subdomainsFromCrtSh(string $domain): ?array {
    $ctx = stream_context_create([
        'http' => ['timeout' => 10, 'ignore_errors' => true,
                   'header'  => "User-Agent: Mozilla/5.0 DomainWatch/1.0\r\n"],
        'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);

    $raw = @file_get_contents("https://crt.sh/?q=%25.{$domain}&output=json", false, $ctx);
    if (!$raw || strlen($raw) < 10) return null;

    $data = json_decode($raw, true);
    if (!$data || !is_array($data)) return null;

    $subs = [];
    foreach ($data as $entry) {
        $names = explode("\n", $entry['name_value'] ?? '');
        foreach ($names as $name) {
            $name = strtolower(trim(ltrim($name, '*.')));
            if ($name && str_ends_with($name, $domain) && $name !== $domain) {
                $subs[$name] = true;
            }
        }
    }

    if (empty($subs)) return null;

    ksort($subs);
    $list = array_keys($subs);

    $firstSeen = null;
    foreach ($data as $entry) {
        $ts = strtotime($entry['not_before'] ?? '');
        if ($ts && (!$firstSeen || $ts < $firstSeen)) $firstSeen = $ts;
    }

    return [
        'list'       => $list,
        'count'      => count($list),
        'first_seen' => $firstSeen ? date('d.m.Y', $firstSeen) : null,
        'cert_count' => count($data),
        'source'     => 'crt.sh (Certificate Transparency Logs)',
    ];
}

function _subdomainsFromHackerTarget(string $domain): ?array {
    $ctx = stream_context_create([
        'http' => ['timeout' => 8, 'ignore_errors' => true,
                   'header' => "User-Agent: DomainWatch/1.0\r\n"],
    ]);

    $raw = @file_get_contents("https://api.hackertarget.com/hostsearch/?q={$domain}", false, $ctx);
    if (!$raw || str_contains($raw, 'error') || str_contains($raw, 'API count') || strlen($raw) < 5) return null;

    $subs = [];
    foreach (explode("\n", $raw) as $line) {
        $line  = trim($line);
        if (!$line) continue;
        $parts = explode(',', $line);
        $host  = strtolower(trim($parts[0]));
        if (str_ends_with($host, '.' . $domain) && $host !== $domain) {
            $subs[$host] = true;
        }
    }

    if (empty($subs)) return null;

    ksort($subs);
    return [
        'list'       => array_keys($subs),
        'count'      => count($subs),
        'first_seen' => null,
        'cert_count' => 0,
        'source'     => 'HackerTarget DNS Search',
    ];
}

function _subdomainsFromSsl(string $domain): ?array {
    $ctx = stream_context_create([
        'ssl'    => ['capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false],
        'socket' => ['timeout' => 5],
    ]);

    $fp = @stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) return null;

    $cert   = stream_context_get_params($fp)['options']['ssl']['peer_certificate'] ?? null;
    fclose($fp);

    if (!$cert) return null;
    $parsed = openssl_x509_parse($cert);
    if (!$parsed || empty($parsed['extensions']['subjectAltName'])) return null;

    preg_match_all('/DNS:([^\s,]+)/', $parsed['extensions']['subjectAltName'], $m);
    $subs = [];
    foreach (($m[1] ?? []) as $name) {
        $name = strtolower(trim($name));
        if (str_ends_with($name, '.' . $domain) && $name !== $domain) {
            $subs[$name] = true;
        }
    }

    if (empty($subs)) return null;

    ksort($subs);
    return [
        'list'       => array_keys($subs),
        'count'      => count($subs),
        'first_seen' => null,
        'cert_count' => 1,
        'source'     => 'SSL Certificate SAN (certificatul activ)',
        'note'       => 'Date limitate — doar subdomenii din certificatul SSL curent',
    ];
}

// -------------------------------------------------------
// Port Scan
// -------------------------------------------------------
function getOpenPorts(string $domain): array {
    $ip = @gethostbyname($domain);
    if (!$ip || $ip === $domain) return [];

    $ports = [
        21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP',
        53 => 'DNS', 80 => 'HTTP', 110 => 'POP3', 143 => 'IMAP',
        443 => 'HTTPS', 465 => 'SMTPS', 587 => 'SMTP Submission',
        993 => 'IMAPS', 995 => 'POP3S', 3306 => 'MySQL',
        5432 => 'PostgreSQL', 6379 => 'Redis', 8080 => 'HTTP Alt',
        8443 => 'HTTPS Alt', 27017 => 'MongoDB',
    ];

    $open = [];
    foreach ($ports as $port => $name) {
        $fp = @fsockopen($ip, $port, $e, $s, 1.5);
        if ($fp) { fclose($fp); $open[] = ['port' => $port, 'name' => $name, 'risk' => getRisk($port)]; }
    }
    return $open;
}

function getRisk(int $port): string {
    if (in_array($port, [21, 23, 3306, 5432, 6379, 27017])) return 'high';
    if (in_array($port, [22, 25, 110, 143]))                 return 'medium';
    return 'low';
}

// -------------------------------------------------------
// Punct 5: Technology Fingerprinting din HTTP headers
// -------------------------------------------------------
function getTechFingerprint(string $domain): array {
    $out = [
        'server'      => null,
        'powered_by'  => null,
        'cms'         => null,
        'cdn'         => null,
        'waf'         => null,
        'language'    => null,
        'headers'     => [],
        'tech_stack'  => [],
        'redirect'    => null,
        'status_code' => null,
        'error'       => null,
    ];

    $ctx = stream_context_create([
        'http' => [
            'timeout'         => 8,
            'ignore_errors'   => true,
            'follow_location' => false, // nu urma redirect-uri ca sa vedem headerele originale
            'method'          => 'GET',
            'header'          => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n" .
                                  "Accept: text/html,application/xhtml+xml\r\n" .
                                  "Accept-Language: en-US,en;q=0.9\r\n",
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);

    // Incearca HTTPS mai intai, fallback HTTP
    foreach (["https://{$domain}", "http://{$domain}"] as $url) {
        $body = @file_get_contents($url, false, $ctx);
        if ($body !== false || !empty($http_response_header)) break;
    }

    if (empty($http_response_header)) {
        $out['error'] = 'Nu s-a putut conecta la server';
        return $out;
    }

    // Parse HTTP response headers
    $headers = [];
    foreach ($http_response_header as $h) {
        if (preg_match('/^HTTP\/\d\.?\d?\s+(\d+)/i', $h, $m)) {
            $out['status_code'] = (int)$m[1];
            if (in_array($out['status_code'], [301, 302, 307, 308])) {
                $out['redirect'] = 'Da (HTTP ' . $out['status_code'] . ')';
            }
            continue;
        }
        if (strpos($h, ':') === false) continue;
        [$name, $val] = array_map('trim', explode(':', $h, 2));
        $headers[strtolower($name)] = $val;
    }
    $out['headers'] = $headers;

    // Server
    if (!empty($headers['server'])) {
        $out['server'] = $headers['server'];
    }

    // X-Powered-By
    if (!empty($headers['x-powered-by'])) {
        $out['powered_by'] = $headers['x-powered-by'];
        $xpb = strtolower($headers['x-powered-by']);
        if (str_contains($xpb, 'php'))    $out['language'] = 'PHP ' . (preg_match('/php\/(\S+)/i', $headers['x-powered-by'], $m) ? $m[1] : '');
        if (str_contains($xpb, 'asp'))    $out['language'] = 'ASP.NET';
        if (str_contains($xpb, 'node'))   $out['language'] = 'Node.js';
        if (str_contains($xpb, 'python')) $out['language'] = 'Python';
    }

    // CDN Detection
    $techStack = [];
    $serverLow = strtolower($headers['server'] ?? '');
    if (!empty($headers['cf-ray']) || str_contains($serverLow, 'cloudflare')) {
        $out['cdn'] = 'Cloudflare';
        $techStack[] = 'Cloudflare CDN/WAF';
    } elseif (!empty($headers['x-amz-cf-id']) || !empty($headers['x-amz-id-2'])) {
        $out['cdn'] = 'Amazon CloudFront';
        $techStack[] = 'AWS CloudFront';
    } elseif (!empty($headers['x-fastly-request-id'])) {
        $out['cdn'] = 'Fastly';
        $techStack[] = 'Fastly CDN';
    } elseif (!empty($headers['x-vercel-id'])) {
        $out['cdn'] = 'Vercel';
        $techStack[] = 'Vercel Edge';
    } elseif (!empty($headers['x-netlify-id']) || str_contains($serverLow, 'netlify')) {
        $out['cdn'] = 'Netlify';
        $techStack[] = 'Netlify';
    } elseif (str_contains($serverLow, 'nginx')) {
        $techStack[] = 'Nginx';
    } elseif (str_contains($serverLow, 'apache')) {
        $techStack[] = 'Apache';
    } elseif (str_contains($serverLow, 'litespeed')) {
        $techStack[] = 'LiteSpeed';
    } elseif (str_contains($serverLow, 'iis')) {
        $techStack[] = 'Microsoft IIS';
    } elseif (str_contains($serverLow, 'openresty')) {
        $techStack[] = 'OpenResty (Nginx+Lua)';
    }

    // WAF Detection
    if (!empty($headers['x-sucuri-id']))                  $out['waf'] = 'Sucuri WAF';
    elseif (!empty($headers['x-firewall-protection']))    $out['waf'] = 'Firewall';
    elseif (!empty($headers['x-waf-event-info']))         $out['waf'] = 'WAF activ';
    elseif (!empty($headers['x-protected-by']))           $out['waf'] = $headers['x-protected-by'];

    // CMS Detection din headers si body
    if ($body !== false) {
        $bodyLow = strtolower(substr($body, 0, 8000));
        if (str_contains($bodyLow, 'wp-content') || str_contains($bodyLow, 'wp-includes')) {
            $out['cms'] = 'WordPress';
            $techStack[] = 'WordPress';
            // Detecteaza versiunea WP
            if (preg_match('/wp-includes\/js\/wp-embed\.min\.js\?ver=([\d.]+)/i', $body, $m)) {
                $out['cms'] = 'WordPress ' . $m[1];
            }
        } elseif (str_contains($bodyLow, 'joomla') || str_contains($bodyLow, '/media/jui/')) {
            $out['cms'] = 'Joomla';
            $techStack[] = 'Joomla';
        } elseif (str_contains($bodyLow, 'drupal') || !empty($headers['x-drupal-cache'])) {
            $out['cms'] = 'Drupal';
            $techStack[] = 'Drupal';
        } elseif (str_contains($bodyLow, 'shopify')) {
            $out['cms'] = 'Shopify';
            $techStack[] = 'Shopify';
        } elseif (str_contains($bodyLow, 'wix.com') || str_contains($bodyLow, '_wix_')) {
            $out['cms'] = 'Wix';
            $techStack[] = 'Wix';
        } elseif (str_contains($bodyLow, 'squarespace')) {
            $out['cms'] = 'Squarespace';
            $techStack[] = 'Squarespace';
        } elseif (str_contains($bodyLow, 'ghost.org') || str_contains($bodyLow, 'ghost-url')) {
            $out['cms'] = 'Ghost';
            $techStack[] = 'Ghost CMS';
        } elseif (str_contains($bodyLow, 'next.js') || str_contains($bodyLow, '__next')) {
            $techStack[] = 'Next.js';
        } elseif (str_contains($bodyLow, 'nuxt') || str_contains($bodyLow, '__nuxt')) {
            $techStack[] = 'Nuxt.js';
        } elseif (str_contains($bodyLow, 'laravel') || !empty($headers['set-cookie']) && str_contains($headers['set-cookie'], 'laravel')) {
            $techStack[] = 'Laravel (PHP)';
        }
        // Analytics
        if (str_contains($bodyLow, 'google-analytics') || str_contains($bodyLow, 'gtag(')) $techStack[] = 'Google Analytics';
        if (str_contains($bodyLow, 'googletagmanager'))  $techStack[] = 'Google Tag Manager';
        if (str_contains($bodyLow, 'facebook.net/en_US/fbevents')) $techStack[] = 'Facebook Pixel';
        if (str_contains($bodyLow, 'hotjar'))             $techStack[] = 'Hotjar';
        if (str_contains($bodyLow, 'clarity.ms'))         $techStack[] = 'Microsoft Clarity';
    }

    // Security headers
    $secHeaders = [];
    if (!empty($headers['strict-transport-security'])) $secHeaders[] = 'HSTS';
    if (!empty($headers['content-security-policy']))   $secHeaders[] = 'CSP';
    if (!empty($headers['x-frame-options']))           $secHeaders[] = 'X-Frame-Options';
    if (!empty($headers['x-content-type-options']))    $secHeaders[] = 'X-Content-Type';
    if (!empty($headers['permissions-policy']))        $secHeaders[] = 'Permissions-Policy';
    if (!empty($secHeaders)) $techStack[] = 'Security headers: ' . implode(', ', $secHeaders);

    $out['tech_stack'] = array_unique($techStack);
    return $out;
}

// -------------------------------------------------------
// Punct 4: Infrastructura comuna — cauta in DB domeniile
// tale care sunt pe acelasi IP sau NS
// -------------------------------------------------------
function getDbInfraMatches(string $domain, PDO $db): array {
    $out = [
        'same_ip'   => [],
        'same_ns'   => [],
        'current_ip' => null,
        'current_ns' => [],
    ];

    // IP curent
    $ip = @gethostbyname($domain);
    if ($ip && $ip !== $domain) {
        $out['current_ip'] = $ip;
        // Cauta in DB domenii cu acelasi IP
        $all = $db->query("SELECT id, domain, current_status, domain_type FROM domains WHERE monitoring_active=1 ORDER BY domain")->fetchAll();
        foreach ($all as $row) {
            if ($row['domain'] === $domain) continue;
            $rowIp = @gethostbyname($row['domain']);
            if ($rowIp && $rowIp === $ip) {
                $out['same_ip'][] = [
                    'domain' => $row['domain'],
                    'status' => $row['current_status'],
                    'type'   => $row['domain_type'],
                ];
            }
        }
    }

    // NS curent
    $nsRecs = @dns_get_record($domain, DNS_NS);
    if ($nsRecs) {
        foreach ($nsRecs as $r) {
            $out['current_ns'][] = strtolower($r['target']);
        }
        sort($out['current_ns']);

        // Cauta in DB domenii cu aceiasi NS
        $all = $all ?? $db->query("SELECT id, domain, current_status, domain_type FROM domains WHERE monitoring_active=1 ORDER BY domain")->fetchAll();
        foreach ($all as $row) {
            if ($row['domain'] === $domain) continue;
            $rowNs = @dns_get_record($row['domain'], DNS_NS);
            if (!$rowNs) continue;
            $rowNsList = [];
            foreach ($rowNs as $r) $rowNsList[] = strtolower($r['target']);
            sort($rowNsList);
            // Match daca cel putin un NS e comun
            $common = array_intersect($out['current_ns'], $rowNsList);
            if (!empty($common)) {
                $out['same_ns'][] = [
                    'domain'     => $row['domain'],
                    'status'     => $row['current_status'],
                    'type'       => $row['domain_type'],
                    'common_ns'  => array_values($common),
                ];
            }
        }
    }

    return $out;
}

// -------------------------------------------------------
// Istoric Domeniu (History)
// Surse: Wayback Machine CDX API, crt.sh timeline,
//        HackerTarget IP history, VirusTotal public,
//        RDAP/WHOIS registration data
// -------------------------------------------------------
function getDomainHistory(string $domain): array {
    return [
        'wayback'    => _historyWayback($domain),
        'ip_history' => _historyIpTimeline($domain),
        'cert_timeline' => _historyCertTimeline($domain),
        'virustotal' => _historyVirusTotal($domain),
        'rdap'       => _historyRdap($domain),
    ];
}

// --- Wayback Machine (web.archive.org CDX API) ---
function _historyWayback(string $domain): array {
    $ctx = stream_context_create([
        'http' => [
            'timeout'       => 12,
            'ignore_errors' => true,
            'header'        => "User-Agent: Mozilla/5.0 (compatible; DomainWatch/1.0)\r\n",
        ],
        'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);

    $out = [
        'available'       => false,
        'first_snapshot'  => null,
        'last_snapshot'   => null,
        'total_snapshots' => null,
        'archive_url'     => "https://web.archive.org/web/*/{$domain}",
        'years_active'    => [],
    ];

    // Pas 1: Prima captare (cronologic, limit=1)
    $rawFirst = @file_get_contents(
        "https://web.archive.org/cdx/search/cdx?url={$domain}&output=json&fl=timestamp&limit=1&collapse=timestamp:4",
        false, $ctx
    );
    if ($rawFirst) {
        $data = json_decode($rawFirst, true);
        // CDX returneaza [["timestamp"],["20xxxxxxxx"]] — primul rand e header
        if (is_array($data) && count($data) >= 2) {
            $ts = $data[1][0] ?? null;
            if ($ts && strlen($ts) >= 8) {
                $out['first_snapshot'] = [
                    'date' => substr($ts,0,4).'-'.substr($ts,4,2).'-'.substr($ts,6,2),
                    'year' => (int)substr($ts,0,4),
                    'url'  => "https://web.archive.org/web/{$ts}/{$domain}",
                ];
                $out['available'] = true;
            }
        }
    }

    // Pas 2: Ultima captare (reverse=true, limit=1)
    $rawLast = @file_get_contents(
        "https://web.archive.org/cdx/search/cdx?url={$domain}&output=json&fl=timestamp,statuscode&limit=1&reverse=true",
        false, $ctx
    );
    if ($rawLast) {
        $data = json_decode($rawLast, true);
        if (is_array($data) && count($data) >= 2) {
            $ts     = $data[1][0] ?? null;
            $status = $data[1][1] ?? '200';
            if ($ts && strlen($ts) >= 8) {
                $out['last_snapshot'] = [
                    'date'       => substr($ts,0,4).'-'.substr($ts,4,2).'-'.substr($ts,6,2),
                    'year'       => (int)substr($ts,0,4),
                    'statuscode' => $status,
                    'url'        => "https://web.archive.org/web/{$ts}/{$domain}",
                ];
                $out['available'] = true;
            }
        }
    }

    // Pas 3: Numar total + distributie pe ani (collapse=timestamp:4 = un record per an per url)
    $rawYears = @file_get_contents(
        "https://web.archive.org/cdx/search/cdx?url={$domain}&output=json&fl=timestamp&collapse=timestamp:6&limit=2000",
        false, $ctx
    );
    if ($rawYears) {
        $data = json_decode($rawYears, true);
        if (is_array($data) && count($data) > 1) {
            $years = [];
            foreach (array_slice($data, 1) as $row) {
                if (!empty($row[0]) && strlen($row[0]) >= 4) {
                    $y = (int)substr($row[0], 0, 4);
                    if ($y > 1990 && $y <= 2030) {
                        $years[$y] = ($years[$y] ?? 0) + 1;
                    }
                }
            }
            if (!empty($years)) {
                ksort($years);
                $out['years_active']    = $years;
                $out['total_snapshots'] = array_sum($years);
                $out['available']       = true;
            }
        }
    }

    // Pas 4: Daca inca nu avem date, incearca URL-ul fara www
    if (!$out['available'] && !str_starts_with($domain, 'www.')) {
        $wwwDomain = 'www.' . $domain;
        $rawWww = @file_get_contents(
            "https://web.archive.org/cdx/search/cdx?url={$wwwDomain}&output=json&fl=timestamp&limit=1",
            false, $ctx
        );
        if ($rawWww) {
            $data = json_decode($rawWww, true);
            if (is_array($data) && count($data) >= 2) {
                $ts = $data[1][0] ?? null;
                if ($ts && strlen($ts) >= 8) {
                    $out['available']      = true;
                    $out['archive_url']    = "https://web.archive.org/web/*/{$wwwDomain}";
                    $out['first_snapshot'] = [
                        'date' => substr($ts,0,4).'-'.substr($ts,4,2).'-'.substr($ts,6,2),
                        'year' => (int)substr($ts,0,4),
                        'url'  => "https://web.archive.org/web/{$ts}/{$wwwDomain}",
                    ];
                }
            }
        }
    }

    return $out;
}

// --- Istoric IP din HackerTarget ---
function _historyIpTimeline(string $domain): array {
    $ctx = stream_context_create([
        'http' => ['timeout' => 8, 'ignore_errors' => true,
                   'header'  => "User-Agent: DomainWatch/1.0\r\n"],
    ]);

    $raw = @file_get_contents("https://api.hackertarget.com/dnslookup/?q={$domain}", false, $ctx);

    $out = [
        'current_ip' => null,
        'records'    => [],
        'error'      => null,
    ];

    $ip = @gethostbyname($domain);
    if ($ip && $ip !== $domain) $out['current_ip'] = $ip;

    if (!$raw || str_contains($raw, 'error') || str_contains($raw, 'API count')) {
        $out['error'] = 'HackerTarget indisponibil';
        return $out;
    }

    // Parseaza raspunsul DNS
    $lines = array_filter(array_map('trim', explode("\n", $raw)));
    foreach ($lines as $line) {
        if (preg_match('/^(\S+)\s+\d+\s+IN\s+(\w+)\s+(.+)$/', $line, $m)) {
            $out['records'][] = [
                'host'  => $m[1],
                'type'  => $m[2],
                'value' => trim($m[3]),
            ];
        }
    }

    return $out;
}

// --- Timeline certificate SSL (din crt.sh) ---
function _historyCertTimeline(string $domain): array {
    $ctx = stream_context_create([
        'http' => ['timeout' => 12, 'ignore_errors' => true,
                   'header'  => "User-Agent: Mozilla/5.0 DomainWatch/1.0\r\n"],
        'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);

    $raw = @file_get_contents("https://crt.sh/?q={$domain}&output=json", false, $ctx);

    if (!$raw || strlen($raw) < 10) {
        return ['available' => false, 'error' => 'crt.sh inaccesibil', 'certs' => []];
    }

    $data = json_decode($raw, true);
    if (!$data || !is_array($data)) {
        return ['available' => false, 'error' => 'Niciun certificat gasit', 'certs' => []];
    }

    // Grupam pe ani
    $byYear  = [];
    $issuers = [];
    $certs   = [];

    foreach ($data as $entry) {
        $notBefore = $entry['not_before'] ?? '';
        $issuer    = $entry['issuer_name'] ?? '';
        $id        = $entry['id'] ?? null;

        $year = (int)substr($notBefore, 0, 4);
        if ($year > 1990 && $year <= 2030) {
            $byYear[$year] = ($byYear[$year] ?? 0) + 1;
        }

        // Detecteaza issuer-ul principal
        if (str_contains(strtolower($issuer), "let's encrypt")) $issuers["Let's Encrypt"] = ($issuers["Let's Encrypt"] ?? 0) + 1;
        elseif (str_contains(strtolower($issuer), 'cloudflare'))  $issuers['Cloudflare'] = ($issuers['Cloudflare'] ?? 0) + 1;
        elseif (str_contains(strtolower($issuer), 'sectigo') || str_contains(strtolower($issuer), 'comodo')) $issuers['Sectigo/Comodo'] = ($issuers['Sectigo/Comodo'] ?? 0) + 1;
        elseif (str_contains(strtolower($issuer), 'digicert'))    $issuers['DigiCert'] = ($issuers['DigiCert'] ?? 0) + 1;
        elseif (str_contains(strtolower($issuer), 'godaddy'))     $issuers['GoDaddy'] = ($issuers['GoDaddy'] ?? 0) + 1;
        else $issuers['Altele'] = ($issuers['Altele'] ?? 0) + 1;

        // Ultimele 5 certificate
        if (count($certs) < 5) {
            $certs[] = [
                'id'         => $id,
                'not_before' => substr($notBefore, 0, 10),
                'not_after'  => substr($entry['not_after'] ?? '', 0, 10),
                'issuer'     => _shortIssuer($issuer),
                'san'        => substr($entry['name_value'] ?? '', 0, 60),
                'url'        => $id ? "https://crt.sh/?id={$id}" : null,
            ];
        }
    }

    ksort($byYear);
    arsort($issuers);

    return [
        'available'    => true,
        'total_certs'  => count($data),
        'by_year'      => $byYear,
        'issuers'      => $issuers,
        'recent_certs' => $certs,
        'first_cert'   => $byYear ? min(array_keys($byYear)) : null,
    ];
}

function _shortIssuer(string $issuer): string {
    if (str_contains(strtolower($issuer), "let's encrypt")) return "Let's Encrypt";
    if (str_contains(strtolower($issuer), 'cloudflare'))    return 'Cloudflare';
    if (str_contains(strtolower($issuer), 'sectigo') || str_contains(strtolower($issuer), 'comodo')) return 'Sectigo';
    if (str_contains(strtolower($issuer), 'digicert'))      return 'DigiCert';
    if (str_contains(strtolower($issuer), 'godaddy'))       return 'GoDaddy';
    if (str_contains(strtolower($issuer), 'globalsign'))    return 'GlobalSign';
    if (preg_match('/O=([^,]+)/', $issuer, $m))             return trim($m[1]);
    return substr($issuer, 0, 40);
}

// --- VirusTotal cu API key ---
define('VT_API_KEY', 'd5f3bfe6f4e5b7817b0b9985cde8777425b43571c05e5e86df587ac04cac853e');

function _historyVirusTotal(string $domain): array {
    $ctx = stream_context_create([
        'http' => [
            'timeout'       => 10,
            'ignore_errors' => true,
            'header'        => "x-apikey: " . VT_API_KEY . "\r\nAccept: application/json\r\nUser-Agent: DomainWatch/1.0\r\n",
        ],
        'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);

    $raw = @file_get_contents("https://www.virustotal.com/api/v3/domains/{$domain}", false, $ctx);

    $out = [
        'available'        => false,
        'reputation'       => null,
        'malicious_votes'  => 0,
        'harmless_votes'   => 0,
        'suspicious_votes' => 0,
        'categories'       => [],
        'registrar'        => null,
        'creation_date'    => null,
        'last_analysis'    => null,
        'tags'             => [],
        'error'            => null,
        'vt_url'           => "https://www.virustotal.com/gui/domain/{$domain}",
    ];

    if (!$raw) {
        $out['error'] = 'VirusTotal API inaccesibil de pe acest server';
        return $out;
    }

    $data = json_decode($raw, true);
    if (!$data || isset($data['error'])) {
        $out['error'] = 'VirusTotal: ' . ($data['error']['message'] ?? 'Eroare API');
        return $out;
    }

    $attrs = $data['data']['attributes'] ?? [];
    $out['available']        = true;
    $out['reputation']       = $attrs['reputation'] ?? null;
    $out['categories']       = $attrs['categories'] ?? [];
    $out['registrar']        = $attrs['registrar'] ?? null;
    $out['tags']             = $attrs['tags'] ?? [];

    if (!empty($attrs['creation_date'])) {
        $out['creation_date'] = date('Y-m-d', $attrs['creation_date']);
    }
    if (!empty($attrs['last_analysis_date'])) {
        $out['last_analysis'] = date('Y-m-d H:i', $attrs['last_analysis_date']);
    }

    $stats = $attrs['last_analysis_stats'] ?? [];
    $out['malicious_votes']  = $stats['malicious']  ?? 0;
    $out['harmless_votes']   = $stats['harmless']   ?? 0;
    $out['suspicious_votes'] = $stats['suspicious'] ?? 0;

    return $out;
}

// --- WHOIS Deep Parse (inlocuieste RDAP — WHOIS merge pe port 43 de pe orice hosting) ---
// Extrage date structurate complete din raspunsul WHOIS brut
function _historyRdap(string $domain): array {
    $tld = strtolower(ltrim(strrchr($domain, '.'), '.'));

    $whoisServers = [
        'ro'  => 'whois.rotld.ro',
        'com' => 'whois.verisign-grs.com',
        'net' => 'whois.verisign-grs.com',
        'org' => 'whois.pir.org',
        'eu'  => 'whois.eu',
        'io'  => 'whois.nic.io',
        'co'  => 'whois.nic.co',
        'uk'  => 'whois.nic.uk',
        'de'  => 'whois.denic.de',
        'fr'  => 'whois.nic.fr',
        'nl'  => 'whois.domain-registry.nl',
        'it'  => 'whois.nic.it',
        'pl'  => 'whois.dns.pl',
        'app' => 'whois.nic.google',
        'dev' => 'whois.nic.google',
        'info'=> 'whois.afilias.net',
    ];

    $server = $whoisServers[$tld] ?? "whois.nic.{$tld}";

    $out = [
        'available'      => false,
        'registered_on'  => null,
        'expires_on'     => null,
        'updated_on'     => null,
        'registrar'      => null,
        'registrar_url'  => null,
        'registrant'     => null,
        'registrant_country' => null,
        'admin_contact'  => null,
        'nameservers'    => [],
        'status'         => [],
        'dnssec'         => null,
        'source'         => 'WHOIS',
        'error'          => null,
    ];

    // Conectare WHOIS pe portul 43 (TCP direct — merge de pe orice hosting)
    $fp = @fsockopen($server, 43, $errno, $errstr, 10);
    if (!$fp) {
        // Incearca server alternativ
        $fp = @fsockopen('whois.iana.org', 43, $errno, $errstr, 8);
        if (!$fp) {
            $out['error'] = "WHOIS ({$server}:43) inaccesibil";
            return $out;
        }
    }

    stream_set_timeout($fp, 10);
    fwrite($fp, $domain . "\r\n");
    $raw = '';
    while (!feof($fp) && strlen($raw) < 65536) {
        $chunk = fread($fp, 2048);
        if ($chunk === false) break;
        $raw .= $chunk;
        if (stream_get_meta_data($fp)['timed_out']) break;
    }
    fclose($fp);

    if (empty($raw) || strlen($raw) < 20) {
        $out['error'] = 'Raspuns WHOIS gol';
        return $out;
    }

    // Domeniu indisponibil / not found
    $lraw = strtolower($raw);
    if (str_contains($lraw, 'no entries found') || str_contains($lraw, 'no match for') ||
        str_contains($lraw, 'not found') || str_contains($lraw, 'no data found')) {
        $out['error'] = 'Domeniu negasit in WHOIS (posibil neînregistrat)';
        return $out;
    }

    $out['available'] = true;

    // --- Parser universal WHOIS ---
    $lines = explode("\n", $raw);
    $ns    = [];
    $statuses = [];

    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line) || str_starts_with($line, '%') || str_starts_with($line, '#')) continue;

        // Separa key: value
        if (!str_contains($line, ':')) continue;
        [$key, $val] = array_map('trim', explode(':', $line, 2));
        $key = strtolower($key);
        if (empty($val)) continue;

        // Date de inregistrare
        if (in_array($key, ['creation date', 'registered on', 'registration date', 'created'])) {
            $out['registered_on'] = $out['registered_on'] ?? _parseWhoisDate($val);
        }
        // Data expirare
        if (in_array($key, ['registry expiry date', 'expiry date', 'expiration date', 'expires on', 'paid-till', 'renewal date'])) {
            $out['expires_on'] = $out['expires_on'] ?? _parseWhoisDate($val);
        }
        // Data modificare
        if (in_array($key, ['updated date', 'last updated', 'last modified', 'changed', 'modified'])) {
            $out['updated_on'] = $out['updated_on'] ?? _parseWhoisDate($val);
        }
        // Registrar
        if ($key === 'registrar') {
            $out['registrar'] = $out['registrar'] ?? $val;
        }
        if ($key === 'registrar url' || $key === 'registrar whois server') {
            $out['registrar_url'] = $out['registrar_url'] ?? $val;
        }
        // Registrant
        if (in_array($key, ['registrant', 'registrant name', 'registrant organization', 'org'])) {
            $out['registrant'] = $out['registrant'] ?? $val;
        }
        if (in_array($key, ['registrant country', 'country'])) {
            $out['registrant_country'] = $out['registrant_country'] ?? $val;
        }
        // Admin contact
        if (in_array($key, ['admin name', 'admin contact', 'administrative contact'])) {
            $out['admin_contact'] = $out['admin_contact'] ?? $val;
        }
        // Nameservers
        if (in_array($key, ['name server', 'nameserver', 'nserver', 'ns'])) {
            $nsClean = strtolower(explode(' ', $val)[0]);
            if ($nsClean && !in_array($nsClean, $ns)) $ns[] = $nsClean;
        }
        // Status
        if ($key === 'domain status') {
            $statusClean = explode(' ', $val)[0]; // ia doar primul cuvant (fara URL)
            if ($statusClean && !in_array($statusClean, $statuses)) $statuses[] = $statusClean;
        }
        // DNSSEC
        if ($key === 'dnssec') {
            $out['dnssec'] = $val;
        }
    }

    $out['nameservers'] = $ns;
    $out['status']      = $statuses;

    return $out;
}

function _parseWhoisDate(string $val): ?string {
    $val = trim(preg_replace('/\s*\(.*?\)/', '', $val)); // scoate paranteze
    $val = preg_replace('/[tT].*$/', '', $val);          // scoate ora dupa T
    $val = preg_replace('/Z$/', '', trim($val));          // scoate Z final
    $val = preg_replace('/[\.\/]/', '-', trim($val));    // normalizeaza separatori
    $ts  = @strtotime(trim($val));
    if (!$ts || $ts <= 0) return null;
    $year = (int)date('Y', $ts);
    if ($year < 1985 || $year > 2100) return null;
    return date('Y-m-d', $ts);
}
