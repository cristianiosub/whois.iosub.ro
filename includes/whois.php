<?php
// includes/whois.php

function checkDomain(string $domain): array {
    $domain = strtolower(trim($domain));
    $tld    = strtolower(ltrim(strrchr($domain, '.'), '.'));

    $whoisServers = [
        'ro'  => 'whois.rotld.ro',
        'com' => 'whois.verisign-grs.com',
        'net' => 'whois.verisign-grs.com',
        'org' => 'whois.pir.org',
        'info'=> 'whois.afilias.net',
        'eu'  => 'whois.eu',
        'uk'  => 'whois.nic.uk',
        'de'  => 'whois.denic.de',
        'fr'  => 'whois.nic.fr',
        'nl'  => 'whois.domain-registry.nl',
        'it'  => 'whois.nic.it',
        'pl'  => 'whois.dns.pl',
        'io'  => 'whois.nic.io',
        'co'  => 'whois.nic.co',
        'app' => 'whois.nic.google',
        'dev' => 'whois.nic.google',
    ];

    $server = $whoisServers[$tld] ?? "whois.nic.$tld";

    $raw = queryWhoisServer($server, $domain);

    if ($raw === false) {
        $raw = queryWhoisServer('whois.iana.org', $domain);
        if ($raw === false) {
            return [
                'status'          => 'error',
                'raw'             => 'WHOIS query failed - serverul nu raspunde',
                'registrar'       => null,
                'registered_on'   => null,
                'expires_on'      => null,
                'whois_statuses'  => [],
            ];
        }
    }

    return parseWhoisResponse($raw, $tld, $domain);
}

function queryWhoisServer(string $server, string $domain, int $timeout = 10) {
    $errno  = 0;
    $errstr = '';
    $fp     = @fsockopen($server, 43, $errno, $errstr, $timeout);
    if (!$fp) return false;

    stream_set_timeout($fp, $timeout);
    fwrite($fp, "$domain\r\n");

    $response = '';
    $maxLen   = 65536;
    while (!feof($fp) && strlen($response) < $maxLen) {
        $chunk = fread($fp, 1024);
        if ($chunk === false) break;
        $response .= $chunk;
        $info = stream_get_meta_data($fp);
        if ($info['timed_out']) break;
    }
    fclose($fp);
    return $response;
}

/**
 * Sanitizeaza o data din WHOIS si returneaza format YYYY-MM-DD sau null
 */
function sanitizeWhoisDate(?string $raw): ?string {
    if ($raw === null || trim($raw) === '') return null;

    $raw = trim($raw);

    // Cazuri speciale: 'Before 2001', 'before 1999' etc.
    if (preg_match('/before\s+(\d{4})/i', $raw, $m)) {
        return $m[1] . '-01-01';
    }

    $clean      = substr($raw, 0, 30);
    $normalized = preg_replace('/[\/\.]/', '-', $clean);

    $ts = @strtotime($normalized);
    if ($ts && $ts > 0 && $ts < 2147483647) {
        $year = (int)date('Y', $ts);
        if ($year >= 1985 && $year <= 2100) {
            return date('Y-m-d', $ts);
        }
    }

    if (preg_match('/(\d{4})-(\d{2})-(\d{2})/', $raw, $m)) {
        $year = (int)$m[1];
        if ($year >= 1985 && $year <= 2100) {
            return $m[1] . '-' . $m[2] . '-' . $m[3];
        }
    }

    return null;
}

/**
 * Extrage toate valorile "Domain Status:" dintr-un raspuns WHOIS
 * Returneaza array de stringuri, ex: ['DeleteProhibited', 'Hold', 'Locked']
 */
function extractWhoisStatuses(string $raw): array {
    $statuses = [];
    // Cauta toate liniile "Domain Status: Ceva"
    preg_match_all('/Domain Status:\s*(\S+)/i', $raw, $matches);
    if (!empty($matches[1])) {
        foreach ($matches[1] as $s) {
            $s = trim($s);
            if ($s !== '') {
                $statuses[] = $s;
            }
        }
    }
    return array_unique($statuses);
}

/**
 * Determina statusul aplicatiei pe baza statusurilor ROTLD
 *
 * Logica de prioritate:
 * - Daca contine PendingDelete → pending_delete
 * - Daca e gol (niciun Domain Status) dar are Domain Name → registered
 * - Altfel (orice alt status: OK, Hold, Locked, etc.) → registered
 */
function mapRotldStatuses(array $statuses, bool $hasDomainName): string {
    foreach ($statuses as $s) {
        if (stripos($s, 'PendingDelete') !== false || stripos($s, 'Pending-Delete') !== false) {
            return 'pending_delete';
        }
    }
    if ($hasDomainName || !empty($statuses)) {
        return 'registered';
    }
    return 'unknown';
}

function parseWhoisResponse(string $raw, string $tld, string $domain): array {
    $result = [
        'status'         => 'registered',
        'raw'            => $raw,
        'registrar'      => null,
        'registered_on'  => null,
        'expires_on'     => null,
        'whois_statuses' => [],  // array cu statusurile WHOIS originale
    ];

    // -------------------------------------------------------
    // .ro specific logic (ROTLD format)
    // -------------------------------------------------------
    if ($tld === 'ro') {
        // Domeniu inexistent
        if (strpos($raw, 'No entries found') !== false || strpos($raw, '% No entries found') !== false) {
            $result['status'] = 'available';
            return $result;
        }

        // Extrage toate statusurile WHOIS
        $statuses = extractWhoisStatuses($raw);
        $result['whois_statuses'] = $statuses;

        $hasDomainName = strpos($raw, 'Domain Name:') !== false;
        $result['status'] = mapRotldStatuses($statuses, $hasDomainName);

        if (preg_match('/Registrar:\s*(.+)/i', $raw, $m))     $result['registrar']    = trim($m[1]);
        if (preg_match('/Registered On:\s*(.+)/i', $raw, $m)) $result['registered_on'] = sanitizeWhoisDate(trim($m[1]));
        if (preg_match('/Expires On:\s*(.+)/i', $raw, $m))    $result['expires_on']    = sanitizeWhoisDate(trim($m[1]));

        return $result;
    }

    // -------------------------------------------------------
    // Generic logic pentru alte TLD-uri
    // -------------------------------------------------------
    $lraw = strtolower($raw);

    $availablePatterns = [
        'no match for', 'not found', 'no entries found', 'no data found',
        'object does not exist', 'domain not found', 'status: free',
        'is available', 'available for registration', 'no object found',
    ];
    foreach ($availablePatterns as $p) {
        if (strpos($lraw, $p) !== false) {
            $result['status'] = 'available';
            return $result;
        }
    }

    // Extrage statusuri WHOIS generice
    $statuses = extractWhoisStatuses($raw);
    $result['whois_statuses'] = $statuses;

    foreach ($statuses as $s) {
        if (stripos($s, 'pendingdelete') !== false || stripos($s, 'pending-delete') !== false) {
            $result['status'] = 'pending_delete';
            break;
        }
    }

    if (preg_match('/Registrar:\s*(.+)/i', $raw, $m)) {
        $result['registrar'] = trim($m[1]);
    }

    $datePatterns = [
        '/Creation Date:\s*(.+)/i',
        '/Created On:\s*(.+)/i',
        '/Registered On:\s*(.+)/i',
        '/Registration Date:\s*(.+)/i',
    ];
    foreach ($datePatterns as $p) {
        if (preg_match($p, $raw, $m)) {
            $result['registered_on'] = sanitizeWhoisDate(trim($m[1]));
            break;
        }
    }

    $expiryPatterns = [
        '/Registry Expiry Date:\s*(.+)/i',
        '/Expiration Date:\s*(.+)/i',
        '/Expiry Date:\s*(.+)/i',
        '/Expires On:\s*(.+)/i',
    ];
    foreach ($expiryPatterns as $p) {
        if (preg_match($p, $raw, $m)) {
            $result['expires_on'] = sanitizeWhoisDate(trim($m[1]));
            break;
        }
    }

    return $result;
}

function extractTld(string $domain): string {
    $parts = explode('.', strtolower(trim($domain)));
    return end($parts);
}

function isValidDomain(string $domain): bool {
    $domain = strtolower(trim($domain));
    return (bool) preg_match('/^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/', $domain);
}
