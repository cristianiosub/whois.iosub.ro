<?php
// includes/intel.php
// Domain Intelligence / OSINT module
// Surse: DNS nativ PHP, crt.sh (gratuit), ipinfo.io (gratuit), port scan direct

function getDomainIntel(string $domain): array {
    $domain = strtolower(trim($domain));
    $ip     = gethostbyname($domain);
    $hasIp  = ($ip !== $domain);
    return [
        'dns'        => getDnsRecords($domain),
        'ip'         => $hasIp ? getIpInfo($ip) : null,
        'ssl'        => getSslInfo($domain),
        'subdomains' => getSubdomains($domain),
        'ports'      => scanPorts($ip, $hasIp),
        'email_sec'  => getEmailSecurity($domain),
        'hosting'    => $hasIp ? detectHosting($ip) : null,
        'shared_ip'  => $hasIp ? getSharedIp($ip) : null,
    ];
}

// -------------------------------------------------------
// DNS Records
// -------------------------------------------------------
function getDnsRecords(string $domain): array {
    $result = ['a'=>[],'aaaa'=>[],'mx'=>[],'ns'=>[],'txt'=>[],'cname'=>[],'soa'=>null,'caa'=>[]];

    $a = @dns_get_record($domain, DNS_A);
    if ($a) foreach ($a as $r) $result['a'][] = $r['ip'];

    $aaaa = @dns_get_record($domain, DNS_AAAA);
    if ($aaaa) foreach ($aaaa as $r) $result['aaaa'][] = $r['ipv6'];

    $mx = @dns_get_record($domain, DNS_MX);
    if ($mx) {
        usort($mx, fn($a,$b) => $a['pri'] <=> $b['pri']);
        foreach ($mx as $r) {
            $result['mx'][] = [
                'host'     => $r['target'],
                'priority' => $r['pri'],
                'provider' => detectMxProvider($r['target']),
            ];
        }
    }

    $ns = @dns_get_record($domain, DNS_NS);
    if ($ns) {
        foreach ($ns as $r) {
            $result['ns'][] = [
                'host'     => $r['target'],
                'provider' => detectNsProvider($r['target']),
            ];
        }
    }

    $txt = @dns_get_record($domain, DNS_TXT);
    if ($txt) {
        foreach ($txt as $r) {
            $val = is_array($r['txt']) ? implode('', $r['txt']) : ($r['txt'] ?? '');
            $result['txt'][] = [
                'value'  => $val,
                'type'   => classifyTxt($val),
                'parsed' => parseTxtRecord($val),
            ];
        }
    }

    $soa = @dns_get_record($domain, DNS_SOA);
    if ($soa) {
        $result['soa'] = [
            'mname'  => $soa[0]['mname'] ?? '',
            'rname'  => $soa[0]['rname'] ?? '',
            'serial' => $soa[0]['serial'] ?? '',
        ];
    }

    $caa = @dns_get_record($domain, DNS_CAA);
    if ($caa) {
        foreach ($caa as $r) {
            $result['caa'][] = ['tag' => $r['tag'] ?? '', 'value' => $r['value'] ?? ''];
        }
    }

    return $result;
}

function detectMxProvider(string $host): array {
    $h = strtolower($host);
    if (str_contains($h, 'google') || str_contains($h, 'googlemail') || str_contains($h, 'aspmx'))
        return ['name' => 'Google Workspace', 'icon' => '🔵', 'color' => '#4285f4'];
    if (str_contains($h, 'outlook') || str_contains($h, 'microsoft') || str_contains($h, 'protection.outlook'))
        return ['name' => 'Microsoft 365 / Outlook', 'icon' => '🔷', 'color' => '#0078d4'];
    if (str_contains($h, 'yahoo'))
        return ['name' => 'Yahoo Mail', 'icon' => '🟣', 'color' => '#6001d2'];
    if (str_contains($h, 'mailchimp') || str_contains($h, 'mandrill'))
        return ['name' => 'Mailchimp / Mandrill', 'icon' => '🐒', 'color' => '#ffe01b'];
    if (str_contains($h, 'sendgrid'))
        return ['name' => 'SendGrid', 'icon' => '📧', 'color' => '#1a82e2'];
    if (str_contains($h, 'amazonses') || str_contains($h, 'amazonaws'))
        return ['name' => 'Amazon SES', 'icon' => '🟠', 'color' => '#ff9900'];
    if (str_contains($h, 'mailgun'))
        return ['name' => 'Mailgun', 'icon' => '📨', 'color' => '#f06b26'];
    if (str_contains($h, 'protonmail') || str_contains($h, 'proton'))
        return ['name' => 'ProtonMail', 'icon' => '🔒', 'color' => '#6d4aff'];
    if (str_contains($h, 'zoho'))
        return ['name' => 'Zoho Mail', 'icon' => '🟡', 'color' => '#f5a623'];
    if (str_contains($h, 'cloudflare'))
        return ['name' => 'Cloudflare Email Routing', 'icon' => '🟠', 'color' => '#f48120'];
    if (str_contains($h, 'icloud') || str_contains($h, 'apple'))
        return ['name' => 'Apple iCloud Mail', 'icon' => '🍎', 'color' => '#555555'];
    if (str_contains($h, 'rdslink') || str_contains($h, 'rds.ro'))
        return ['name' => 'RDS & RCS (Digi Romania)', 'icon' => '🇷🇴', 'color' => '#003DA5'];
    if (str_ends_with(strtolower($host), '.ro'))
        return ['name' => 'Hosting Romania', 'icon' => '🇷🇴', 'color' => '#003DA5'];
    return ['name' => $host, 'icon' => '📬', 'color' => '#64748b'];
}

function detectNsProvider(string $host): string {
    $h = strtolower($host);

    // Provideri internationali mari
    if (str_contains($h, 'cloudflare'))   return 'Cloudflare DNS (CDN/Security global)';
    if (str_contains($h, 'awsdns') || str_contains($h, 'amazonaws')) return 'Amazon Route 53 (AWS)';
    if (str_contains($h, 'google'))       return 'Google Cloud DNS';
    if (str_contains($h, 'azure') || str_contains($h, 'msft')) return 'Microsoft Azure DNS';
    if (str_contains($h, 'digitalocean')) return 'DigitalOcean DNS';
    if (str_contains($h, 'hetzner'))      return 'Hetzner Online DNS (Germania)';
    if (str_contains($h, 'godaddy') || str_contains($h, 'domaincontrol')) return 'GoDaddy DNS';
    if (str_contains($h, 'namecheap') || str_contains($h, 'registrar-servers')) return 'Namecheap DNS';
    if (str_contains($h, 'ovh'))          return 'OVHcloud DNS (Franta)';
    if (str_contains($h, 'linode') || str_contains($h, 'akamai')) return 'Akamai / Linode DNS';

    // Provideri romani — detectare specifica
    if (str_contains($h, 'rdslink') || str_contains($h, 'rds.ro'))
        return 'RDS & RCS (Digi Romania) — cel mai mare ISP din Romania';
    if (str_contains($h, 'rotld') || str_contains($h, 'nic.ro'))
        return 'ROTLD — Registrul .ro (ICI Bucuresti), administratorul domeniilor .ro';
    if (str_contains($h, 'voxility'))
        return 'Voxility Romania — hosting si anti-DDoS romanesc';
    if (str_contains($h, 'm247') || str_contains($h, 'memoranda'))
        return 'M247 Romania — provider de hosting si connectivity';
    if (str_contains($h, 'idc.ro') || str_contains($h, 'idcromania'))
        return 'IDC Romania — provider de hosting romanesc';
    if (str_contains($h, 'hostway') || str_contains($h, 'hostazor'))
        return 'Hostway Romania — hosting romanesc';
    if (str_contains($h, 'xservers') || str_contains($h, 'xserver.ro'))
        return 'xServers Romania — hosting romanesc';
    if (str_contains($h, 'chroot') || str_contains($h, 'chroot.ro'))
        return 'Chroot Security Romania — hosting si securitate';
    if (str_contains($h, 'gsp.ro') || str_contains($h, 'gspartners'))
        return 'GS Partners Romania — hosting romanesc';
    if (str_contains($h, 'netim'))
        return 'Netim — registrar european cu DNS inclus';
    if (str_contains($h, 'eurid') || str_ends_with($h, '.eu'))
        return 'EURid — registrul domeniilor .eu';

    // Detectie generica Romania dupa TLD
    if (str_ends_with($h, '.ro'))
        return 'DNS hostat in Romania (nameserver cu TLD .ro)';

    // cPanel/WHM
    if (str_contains($h, 'cpanel') || str_contains($h, 'whm')) return 'cPanel/WHM DNS (hosting shared)';

    return 'DNS personalizat — ' . $host;
}

function classifyTxt(string $val): string {
    $v = strtolower($val);
    if (str_starts_with($v, 'v=spf'))   return 'spf';
    if (str_starts_with($v, 'v=dmarc')) return 'dmarc';
    if (str_contains($v, 'dkim') || preg_match('/p=[a-z0-9+\/=]{20,}/i', $val)) return 'dkim';
    if (str_contains($v, 'google-site-verification')) return 'google';
    if (str_contains($v, 'ms=ms') || str_contains($v, 'msvalidate')) return 'microsoft';
    if (str_contains($v, 'facebook-domain-verification')) return 'facebook';
    if (str_contains($v, 'docusign')) return 'docusign';
    if (str_contains($v, 'atlassian-domain')) return 'atlassian';
    return 'other';
}

function parseTxtRecord(string $val): string {
    $v = strtolower($val);
    if (str_starts_with($v, 'v=spf')) {
        $providers = [];
        if (str_contains($v, 'google')) $providers[] = 'Google';
        if (str_contains($v, 'microsoft') || str_contains($v, 'protection.outlook')) $providers[] = 'Microsoft';
        if (str_contains($v, 'mailchimp') || str_contains($v, 'mandrill')) $providers[] = 'Mailchimp';
        if (str_contains($v, 'sendgrid')) $providers[] = 'SendGrid';
        if (str_contains($v, 'amazonses') || str_contains($v, 'amazonaws')) $providers[] = 'Amazon SES';
        if (str_contains($v, 'mailgun')) $providers[] = 'Mailgun';
        $allStr = $providers ? ' prin ' . implode(', ', $providers) : '';
        if (str_contains($v, '-all'))  return "SPF configurat — emailuri false respinse (strict)$allStr";
        if (str_contains($v, '~all'))  return "SPF configurat — emailuri false marcate spam (soft)$allStr";
        if (str_contains($v, '+all'))  return "⚠️ SPF permisiv — oricine poate trimite email (risc)";
        return "SPF prezent$allStr";
    }
    if (str_starts_with($v, 'v=dmarc')) {
        if (str_contains($v, 'p=reject'))      return 'DMARC: emailuri false respinse complet (politica stricta)';
        if (str_contains($v, 'p=quarantine'))  return 'DMARC: emailuri false trimise in spam (politica medie)';
        if (str_contains($v, 'p=none'))        return '⚠️ DMARC prezent dar fara protectie (p=none, monitorizare)';
        return 'DMARC configurat';
    }
    if (str_contains($v, 'google-site-verification')) return 'Verificare Google Search Console';
    if (str_contains($v, 'msvalidate') || str_contains($v, 'ms=ms')) return 'Verificare Microsoft / Office 365';
    if (str_contains($v, 'facebook-domain-verification')) return 'Verificare Facebook Business';
    if (str_contains($v, 'docusign')) return 'DocuSign domain verification';
    if (str_contains($v, 'atlassian')) return 'Atlassian / Jira domain claim';
    return substr($val, 0, 80) . (strlen($val) > 80 ? '...' : '');
}

// -------------------------------------------------------
// IP Info (ipinfo.io)
// -------------------------------------------------------
function getIpInfo(string $ip): array {
    $ctx = stream_context_create(['http' => ['timeout' => 5, 'ignore_errors' => true]]);
    $raw = @file_get_contents("https://ipinfo.io/{$ip}/json", false, $ctx);
    if (!$raw) return ['ip' => $ip, 'org' => null, 'city' => null, 'country' => null, 'hostname' => null];
    $data = json_decode($raw, true) ?? [];
    return [
        'ip'       => $ip,
        'org'      => $data['org'] ?? null,
        'city'     => $data['city'] ?? null,
        'region'   => $data['region'] ?? null,
        'country'  => $data['country'] ?? null,
        'hostname' => $data['hostname'] ?? null,
        'timezone' => $data['timezone'] ?? null,
        'loc'      => $data['loc'] ?? null,
    ];
}

function detectHosting(string $ip): array {
    $ctx = stream_context_create(['http' => ['timeout' => 5, 'ignore_errors' => true]]);
    $raw = @file_get_contents("https://ipinfo.io/{$ip}/json", false, $ctx);
    $data = $raw ? (json_decode($raw, true) ?? []) : [];
    $org  = strtolower($data['org'] ?? '');

    $providers = [
        'amazon'       => ['Amazon Web Services (AWS)', '#ff9900'],
        'cloudflare'   => ['Cloudflare', '#f48120'],
        'google'       => ['Google Cloud', '#4285f4'],
        'digitalocean' => ['DigitalOcean', '#0080ff'],
        'hetzner'      => ['Hetzner Online (Germania)', '#d50c2d'],
        'linode'       => ['Akamai / Linode', '#00b159'],
        'vultr'        => ['Vultr', '#007bfc'],
        'ovh'          => ['OVHcloud (Franta)', '#123f6d'],
        'microsoft'    => ['Microsoft Azure', '#0078d4'],
        'rds'          => ['RDS & RCS (Digi Romania)', '#003DA5'],
        'rdslink'      => ['RDS & RCS (Digi Romania)', '#003DA5'],
        'idc'          => ['IDC Romania', '#003DA5'],
        'hostway'      => ['Hostway Romania', '#333'],
        'fastly'       => ['Fastly CDN', '#ff282d'],
        'voxility'     => ['Voxility Romania', '#003DA5'],
        'm247'         => ['M247 Romania', '#003DA5'],
    ];

    foreach ($providers as $key => $info) {
        if (str_contains($org, $key)) {
            return ['name' => $info[0], 'color' => $info[1], 'org' => $data['org'] ?? ''];
        }
    }

    return [
        'name'  => $data['org'] ?? 'Unknown',
        'color' => '#64748b',
        'org'   => $data['org'] ?? '',
    ];
}

// -------------------------------------------------------
// Shared hosting (hackertarget) — pana la 50 vecini
// -------------------------------------------------------
function getSharedIp(string $ip): array {
    $ctx = stream_context_create(['http' => ['timeout' => 6, 'ignore_errors' => true]]);
    $raw = @file_get_contents("https://api.hackertarget.com/reverseiplookup/?q={$ip}", false, $ctx);
    if (!$raw || str_contains($raw, 'error') || str_contains($raw, 'API count')) {
        return ['count' => null, 'domains' => []];
    }
    $lines = array_filter(array_map('trim', explode("\n", $raw)));
    return [
        'count'   => count($lines),
        'domains' => array_slice($lines, 0, 50), // pana la 50 vecini
    ];
}

// -------------------------------------------------------
// SSL Certificate info
// -------------------------------------------------------
function getSslInfo(string $domain): array {
    $result = ['valid' => false, 'error' => null, 'issuer' => null, 'expires' => null,
               'days_left' => null, 'sans' => [], 'subject' => null];

    $ctx = stream_context_create([
        'ssl'    => ['capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false],
        'socket' => ['timeout' => 6],
    ]);

    $fp = @stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 6, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) {
        $result['error'] = 'Nu s-a putut conecta pe portul 443';
        return $result;
    }

    $cert = stream_context_get_params($fp);
    fclose($fp);

    if (empty($cert['options']['ssl']['peer_certificate'])) {
        $result['error'] = 'Certificat SSL absent';
        return $result;
    }

    $parsed = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
    if (!$parsed) {
        $result['error'] = 'Nu s-a putut parsa certificatul';
        return $result;
    }

    $result['valid']   = true;
    $result['subject'] = $parsed['subject']['CN'] ?? null;
    $result['issuer']  = $parsed['issuer']['O'] ?? ($parsed['issuer']['CN'] ?? null);

    $validTo = $parsed['validTo_time_t'] ?? 0;
    if ($validTo) {
        $result['expires']   = date('d.m.Y', $validTo);
        $result['days_left'] = (int)ceil(($validTo - time()) / 86400);
    }

    $sans = [];
    if (!empty($parsed['extensions']['subjectAltName'])) {
        preg_match_all('/DNS:([^\s,]+)/', $parsed['extensions']['subjectAltName'], $m);
        $sans = $m[1] ?? [];
    }
    $result['sans'] = array_unique($sans);

    $issuerLow = strtolower($result['issuer'] ?? '');
    if (str_contains($issuerLow, "let's encrypt") || str_contains($issuerLow, 'letsencrypt'))
        $result['issuer_type'] = "Let's Encrypt (gratuit, auto-reinnoit)";
    elseif (str_contains($issuerLow, 'sectigo') || str_contains($issuerLow, 'comodo'))
        $result['issuer_type'] = 'Sectigo / Comodo (comercial)';
    elseif (str_contains($issuerLow, 'digicert'))
        $result['issuer_type'] = 'DigiCert (comercial premium)';
    elseif (str_contains($issuerLow, 'globalsign'))
        $result['issuer_type'] = 'GlobalSign (comercial)';
    elseif (str_contains($issuerLow, 'google'))
        $result['issuer_type'] = 'Google Trust Services';
    elseif (str_contains($issuerLow, 'amazon') || str_contains($issuerLow, 'aws'))
        $result['issuer_type'] = 'Amazon Certificate Manager';
    else
        $result['issuer_type'] = $result['issuer'];

    return $result;
}

// -------------------------------------------------------
// Subdomenii din Certificate Transparency (crt.sh)
// -------------------------------------------------------
function getSubdomains(string $domain): array {
    $ctx = stream_context_create(['http' => ['timeout' => 8, 'ignore_errors' => true,
        'header' => "User-Agent: DomainWatch/1.0\r\n"]]);
    $raw = @file_get_contents("https://crt.sh/?q=%.{$domain}&output=json", false, $ctx);

    if (!$raw) return ['count' => 0, 'list' => [], 'error' => 'crt.sh indisponibil'];
    $data = json_decode($raw, true);
    if (!$data) return ['count' => 0, 'list' => [], 'error' => 'Raspuns invalid'];

    $subs = [];
    foreach ($data as $entry) {
        $names = array_merge(
            explode("\n", $entry['name_value'] ?? ''),
            explode("\n", $entry['common_name'] ?? '')
        );
        foreach ($names as $name) {
            $name = strtolower(trim($name));
            if ($name && (str_ends_with($name, '.' . $domain) || $name === $domain)) {
                $sub = str_replace('.' . $domain, '', $name);
                if ($sub && $sub !== '*' && !str_contains($sub, '*')) {
                    $subs[$sub] = true;
                }
            }
        }
    }

    $list = array_keys($subs);
    sort($list);

    $firstSeen = null;
    foreach ($data as $entry) {
        $ts = strtotime($entry['not_before'] ?? '');
        if ($ts && (!$firstSeen || $ts < $firstSeen)) $firstSeen = $ts;
    }

    return [
        'count'      => count($list),
        'list'       => array_slice($list, 0, 30),
        'first_seen' => $firstSeen ? date('d.m.Y', $firstSeen) : null,
        'cert_count' => count($data),
    ];
}

// -------------------------------------------------------
// Email Security Score
// -------------------------------------------------------
function getEmailSecurity(string $domain): array {
    $score = 0;
    $max   = 3;
    $spf = $dmarc = $dkim = null;

    $txt = @dns_get_record($domain, DNS_TXT);
    if ($txt) {
        foreach ($txt as $r) {
            $val = is_array($r['txt']) ? implode('', $r['txt']) : ($r['txt'] ?? '');
            if (str_starts_with(strtolower($val), 'v=spf'))   { $spf = $val; $score++; }
            if (str_starts_with(strtolower($val), 'v=dmarc')) {
                $dmarc = $val;
                if (!str_contains(strtolower($val), 'p=none')) $score++;
            }
        }
    }

    $dkimSelectors = ['default','google','k1','k2','mail','dkim','selector1','selector2','s1','s2'];
    foreach ($dkimSelectors as $sel) {
        $dkimRec = @dns_get_record("{$sel}._domainkey.{$domain}", DNS_TXT);
        if ($dkimRec) {
            foreach ($dkimRec as $r) {
                $val = is_array($r['txt']) ? implode('', $r['txt']) : ($r['txt'] ?? '');
                if (str_contains(strtolower($val), 'p=')) {
                    $dkim = ['selector' => $sel, 'value' => substr($val, 0, 60) . '...'];
                    $score++;
                    break 2;
                }
            }
        }
    }

    return [
        'score'  => $score,
        'max'    => $max,
        'spf'    => $spf,
        'dmarc'  => $dmarc,
        'dkim'   => $dkim,
        'rating' => $score >= 3 ? 'secure' : ($score >= 2 ? 'partial' : 'vulnerable'),
    ];
}

// -------------------------------------------------------
// Port Scan
// -------------------------------------------------------
function scanPorts(string $ip, bool $hasIp): array {
    if (!$hasIp || !$ip) return [];

    $ports = [
        80   => 'HTTP',
        443  => 'HTTPS',
        21   => 'FTP',
        22   => 'SSH',
        25   => 'SMTP',
        587  => 'SMTP (TLS)',
        993  => 'IMAP SSL',
        3306 => 'MySQL',
        5432 => 'PostgreSQL',
        8080 => 'HTTP Alt',
        8443 => 'HTTPS Alt',
    ];

    $risks = [
        21   => 'risc mediu — FTP nesecurizat',
        22   => 'atentie — SSH expus public',
        25   => 'risc mediu — SMTP direct',
        3306 => 'RISC MAJOR — MySQL expus public!',
        5432 => 'RISC MAJOR — PostgreSQL expus public!',
    ];

    $results = [];
    foreach ($ports as $port => $name) {
        $fp   = @fsockopen($ip, $port, $e, $s, 1.5);
        $open = (bool)$fp;
        if ($fp) fclose($fp);
        $results[] = [
            'port' => $port,
            'name' => $name,
            'open' => $open,
            'risk' => $open ? ($risks[$port] ?? null) : null,
        ];
    }
    return $results;
}
