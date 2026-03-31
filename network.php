<?php
require_once 'config.php';
require_once 'includes/auth.php';
require_once 'includes/db.php';
requireLogin();

$db        = getDB();
$csrfToken = getCsrfToken();
$pageTitle = 'IP / NS Lookup';

// -------------------------------------------------------
// AJAX handlers — INAINTE de orice output HTML
// -------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $action = $_POST['action'] ?? '';

    // --- Quick values: IP-uri si NS-uri stocate in settings ---
    if ($action === 'quick_values') {
        $ips = [];
        $nsFlat = [];
        try {
            $stmt = $db->query("SELECT key_value FROM settings WHERE key_name LIKE 'domain_ip_%' AND key_value != '' AND key_value NOT LIKE '%,%'");
            foreach ($stmt->fetchAll() as $row) {
                $ip = trim($row['key_value']);
                if ($ip) $ips[$ip] = ($ips[$ip] ?? 0) + 1;
            }
            $stmt2 = $db->query("SELECT key_value FROM settings WHERE key_name LIKE 'domain_ns_%' AND key_value != ''");
            foreach ($stmt2->fetchAll() as $row) {
                foreach (explode(',', $row['key_value']) as $n) {
                    $n = trim($n);
                    if ($n) $nsFlat[$n] = ($nsFlat[$n] ?? 0) + 1;
                }
            }
            arsort($ips);
            arsort($nsFlat);
            $ipList = array_map(fn($ip, $cnt) => ['ip' => $ip, 'count' => $cnt], array_keys($ips), array_values($ips));
            $nsList = array_map(fn($n,  $cnt) => ['ns' => $n,  'count' => $cnt], array_keys($nsFlat), array_values($nsFlat));
            echo json_encode(['ips' => array_slice($ipList, 0, 20), 'ns' => array_slice($nsList, 0, 20)]);
        } catch (Exception $e) {
            echo json_encode(['ips' => [], 'ns' => [], 'error' => $e->getMessage()]);
        }
        exit;
    }

    // --- Search: cauta dupa IP sau NS ---
    if ($action === 'search') {
        $query  = trim($_POST['query'] ?? '');
        $isIp   = (bool)preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $query);
        $result = ['db_matches' => [], 'external_matches' => [], 'external_error' => null];

        if (empty($query)) { echo json_encode($result); exit; }

        try {
            $allDomains = $db->query("SELECT id, domain, current_status, domain_type FROM domains WHERE monitoring_active=1 ORDER BY domain")->fetchAll();

            if ($isIp) {
                // 1. Cauta in settings stocate de cron (rapid, fara DNS)
                $stmt = $db->prepare(
                    "SELECT d.id, d.domain, d.current_status, d.domain_type
                     FROM settings s
                     JOIN domains d ON d.id = CAST(REPLACE(s.key_name,'domain_ip_','') AS UNSIGNED)
                     WHERE s.key_name LIKE 'domain_ip_%' AND s.key_value = ?"
                );
                $stmt->execute([$query]);
                $found = [];
                foreach ($stmt->fetchAll() as $row) {
                    $found[$row['id']] = true;
                    $result['db_matches'][] = [
                        'id'          => $row['id'],
                        'domain'      => $row['domain'],
                        'status'      => $row['current_status'],
                        'domain_type' => $row['domain_type'],
                        'match_type'  => 'ip',
                        'match_value' => $query,
                    ];
                }
                // 2. DNS live pentru domeniile care nu au IP stocat
                foreach ($allDomains as $row) {
                    if (isset($found[$row['id']])) continue;
                    $ip = @gethostbyname($row['domain']);
                    if ($ip && $ip === $query) {
                        $result['db_matches'][] = [
                            'id'          => $row['id'],
                            'domain'      => $row['domain'],
                            'status'      => $row['current_status'],
                            'domain_type' => $row['domain_type'],
                            'match_type'  => 'ip',
                            'match_value' => $ip,
                        ];
                    }
                }

                // External: HackerTarget Reverse IP
                $ctx = stream_context_create(['http' => [
                    'timeout'       => 8,
                    'ignore_errors' => true,
                    'header'        => "User-Agent: DomainWatch/1.0\r\n",
                ]]);
                $raw = @file_get_contents("https://api.hackertarget.com/reverseiplookup/?q={$query}", false, $ctx);
                if (!$raw || str_contains($raw, 'API count') || str_contains(strtolower($raw), 'error')) {
                    $result['external_error'] = 'HackerTarget indisponibil de pe acest server.';
                } else {
                    $lines = array_values(array_filter(array_map('trim', explode("\n", $raw))));
                    $result['external_matches'] = $lines;
                }

            } else {
                // Cauta dupa NS
                $queryLow = strtolower($query);
                foreach ($allDomains as $row) {
                    $matched   = false;
                    $matchedNs = '';

                    // 1. Cauta in settings stocate
                    $stmt = $db->prepare("SELECT key_value FROM settings WHERE key_name = ?");
                    $stmt->execute(["domain_ns_{$row['id']}"]);
                    $stored = $stmt->fetchColumn();
                    if ($stored) {
                        foreach (explode(',', $stored) as $ns) {
                            $ns = trim($ns);
                            if ($ns && str_contains(strtolower($ns), $queryLow)) {
                                $matched   = true;
                                $matchedNs = $ns;
                                break;
                            }
                        }
                    }

                    // 2. Fallback: DNS lookup live
                    if (!$matched) {
                        $nsRecs = @dns_get_record($row['domain'], DNS_NS);
                        if ($nsRecs) {
                            foreach ($nsRecs as $r) {
                                if (str_contains(strtolower($r['target']), $queryLow)) {
                                    $matched   = true;
                                    $matchedNs = $r['target'];
                                    break;
                                }
                            }
                        }
                    }

                    if ($matched) {
                        $result['db_matches'][] = [
                            'id'          => $row['id'],
                            'domain'      => $row['domain'],
                            'status'      => $row['current_status'],
                            'domain_type' => $row['domain_type'],
                            'match_type'  => 'ns',
                            'match_value' => $matchedNs,
                        ];
                    }
                }

                // Reverse NS extern — multiple surse
                $result['external_ns'] = _reverseNsLookup($query);
            }
        } catch (Exception $e) {
            $result['error'] = $e->getMessage();
        }

        echo json_encode($result);
        exit;
    }

    echo json_encode(['error' => 'Actiune invalida']);
    exit;
}

// -------------------------------------------------------
// Reverse NS Lookup — surse externe multiple
// -------------------------------------------------------
function _reverseNsLookup(string $ns): array {
    $out = [
        'domains'  => [],
        'sources'  => [],
        'errors'   => [],
        'total'    => 0,
    ];

    $ctx = stream_context_create([
        'http' => [
            'timeout'       => 10,
            'ignore_errors' => true,
            'header'        => "User-Agent: Mozilla/5.0 (compatible; DomainWatch/1.0)\r\nAccept: application/json,text/html\r\n",
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);

    $allDomains = [];

    // ---- Sursa 1: HackerTarget NS hostsearch ----
    // Cauta domenii care au NS-ul respectiv in DNS
    $raw = @file_get_contents("https://api.hackertarget.com/hostsearch/?q={$ns}", false, $ctx);
    if ($raw && !str_contains($raw, 'API count') && !str_contains(strtolower($raw), 'error') && strlen($raw) > 5) {
        $lines = array_filter(array_map('trim', explode("\n", $raw)));
        foreach ($lines as $line) {
            $parts = explode(',', $line);
            $domain = trim($parts[0]);
            if ($domain && preg_match('/^[a-z0-9][a-z0-9._-]+\.[a-z]{2,}$/i', $domain)) {
                $allDomains[$domain] = true;
            }
        }
        if (!empty($allDomains)) {
            $out['sources'][] = 'HackerTarget';
        }
    } else {
        $out['errors'][] = 'HackerTarget: indisponibil';
    }

    // ---- Sursa 2: ViewDNS.info Reverse NS ----
    // API gratuit, 250 req/zi, returneaza JSON
    $viewdnsUrl = "https://api.viewdns.info/reversens/?ns=" . urlencode($ns) . "&apikey=freeapi&output=json";
    $raw2 = @file_get_contents($viewdnsUrl, false, $ctx);
    if ($raw2) {
        $data2 = json_decode($raw2, true);
        $domains2 = $data2['response']['domains'] ?? [];
        if (is_array($domains2)) {
            foreach ($domains2 as $entry) {
                $d = $entry['name'] ?? '';
                if ($d) $allDomains[$d] = true;
            }
            if (!empty($domains2)) {
                $out['sources'][] = 'ViewDNS.info';
            }
        }
    } else {
        $out['errors'][] = 'ViewDNS.info: indisponibil';
    }

    // ---- Sursa 3: SecurityTrails (fara key, endpoint public limitat) ----
    $stUrl = "https://api.securitytrails.com/v1/search/list?apikey=&query=ns%3D" . urlencode($ns);
    // Nota: fara API key returneaza date limitate dar utile
    $raw3 = @file_get_contents($stUrl, false, $ctx);
    if ($raw3) {
        $data3 = json_decode($raw3, true);
        $records3 = $data3['records'] ?? [];
        foreach ($records3 as $entry) {
            $d = $entry['hostname'] ?? '';
            if ($d) $allDomains[$d] = true;
        }
        if (!empty($records3)) {
            $out['sources'][] = 'SecurityTrails';
        }
    }

    // ---- Sursa 4: crt.sh — domenii care au certificat SSL cu acest NS in SANs ----
    // Indirect: cauta domenii care au NS-ul ca subdomain (ex: ns1.hosting.ro -> *.hosting.ro)
    // Extrage domeniu de baza din NS si cauta certificate
    $nsParts = explode('.', strtolower($ns));
    if (count($nsParts) >= 2) {
        // ia ultimele 2 parti: hosting.ro din ns1.hosting.ro
        $nsDomain = implode('.', array_slice($nsParts, -2));
        $crtUrl   = "https://crt.sh/?q=%25.{$nsDomain}&output=json";
        $raw4 = @file_get_contents($crtUrl, false, $ctx);
        if ($raw4 && strlen($raw4) > 10) {
            $data4 = json_decode($raw4, true);
            if (is_array($data4)) {
                foreach ($data4 as $entry) {
                    $names = explode("\n", $entry['name_value'] ?? '');
                    foreach ($names as $name) {
                        $name = strtolower(trim(ltrim($name, '*.')));
                        // Adauga doar daca e un domeniu valid si nu e subdomeniu al NS-ului insusi
                        if ($name && !str_ends_with($name, '.' . $nsDomain) && $name !== $nsDomain
                            && preg_match('/^[a-z0-9][a-z0-9._-]+\.[a-z]{2,}$/i', $name)) {
                            // Verifica daca domeniu chiar foloseste NS-ul respectiv
                            // (nu face DNS live ca e prea lent, le includem ca suggestii)
                            $allDomains[$name] = true;
                        }
                    }
                }
                if (!empty($data4)) {
                    $out['sources'][] = 'crt.sh (CT Logs)';
                }
            }
        } else {
            $out['errors'][] = 'crt.sh: indisponibil';
        }
    }

    // Deduplica si sorteaza
    ksort($allDomains);
    $out['domains'] = array_keys($allDomains);
    $out['total']   = count($out['domains']);

    return $out;
}

// -------------------------------------------------------
// Pagina HTML — doar pentru GET
// -------------------------------------------------------
include 'includes/header.php';
?>

<style>
.network-hero{background:linear-gradient(135deg,rgba(245,158,11,.08),rgba(239,68,68,.05));border:1px solid var(--border);border-radius:16px;padding:32px 36px;margin-bottom:24px;text-align:center}
.network-hero h2{font-size:1.3rem;font-weight:700;margin-bottom:6px}
.network-hero p{color:var(--text2);font-size:.9rem;margin-bottom:20px}
.network-input-wrap{display:flex;gap:10px;max-width:560px;margin:0 auto}
.network-input{flex:1;background:var(--surface);border:1.5px solid var(--border);border-radius:12px;padding:12px 18px;color:var(--text);font-size:.95rem;font-family:monospace;transition:.2s}
.network-input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.network-btn{padding:12px 24px;background:var(--accent);border:none;border-radius:12px;color:#fff;font-size:.9rem;font-weight:600;cursor:pointer;font-family:inherit;transition:.2s;white-space:nowrap}
.network-btn:hover{background:#2563eb}
.network-btn:disabled{opacity:.6;cursor:not-allowed}
.result-section{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:16px;animation:fadeUp .2s ease}
@keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.result-section-header{padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.result-section-title{font-weight:600;font-size:.9rem}
.result-section-body{padding:16px 20px}
.domain-row{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;margin-bottom:5px;background:var(--surface2);transition:.15s}
.domain-row:hover{background:rgba(59,130,246,.08)}
.domain-row:last-child{margin-bottom:0}
.ns-tag{display:inline-block;padding:2px 8px;background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.2);border-radius:4px;font-size:.72rem;color:#fbbf24;font-family:monospace}
.spinner-sm{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.2);border-top-color:var(--accent2);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
.empty-net{text-align:center;padding:32px;color:var(--text3);font-size:.88rem}
.query-chip{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:999px;font-size:.78rem;font-family:monospace;cursor:pointer;transition:.15s;margin:3px}
.query-chip:hover{border-color:var(--accent);color:var(--accent2)}
</style>

<div class="page-header">
    <h1>&#127760; IP / NS Lookup</h1>
    <p>Cauta toate domeniile din lista ta care au un IP sau NS specific</p>
</div>

<div class="network-hero">
    <h2>Cauta dupa IP sau Nameserver</h2>
    <p>Introduce un IP (ex: 1.2.3.4) sau un nameserver (ex: ns1.example.com) pentru a vedea toate domeniile asociate</p>
    <div class="network-input-wrap">
        <input type="text" id="queryInput" class="network-input"
               placeholder="1.2.3.4 sau ns1.example.com"
               autocomplete="off" spellcheck="false" maxlength="255"
               onkeydown="if(event.key==='Enter')doSearch()">
        <button class="network-btn" id="searchBtn" onclick="doSearch()">
            <span id="searchBtnTxt">Cauta</span>
        </button>
    </div>
    <div style="margin-top:14px;color:var(--text3);font-size:.78rem">
        IP: Reverse lookup via HackerTarget &nbsp;·&nbsp; NS: Reverse lookup via HackerTarget + ViewDNS + crt.sh
    </div>
</div>

<div class="card" id="quickPanel">
    <div class="card-header"><div class="card-title">&#128204; Valori rapide din lista ta</div></div>
    <div id="quickContent" style="padding:4px 0">
        <div style="color:var(--text3);font-size:.85rem">Se incarca...</div>
    </div>
</div>

<div id="resultsWrap" style="display:none"></div>

<script>
const CSRF = <?= json_encode($csrfToken) ?>;

async function loadQuick() {
    try {
        const fd = new FormData();
        fd.append('csrf_token', CSRF);
        fd.append('action', 'quick_values');
        const resp = await fetch('/network', {method:'POST', body:fd});
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const data = await resp.json();
        renderQuick(data);
    } catch(e) {
        document.getElementById('quickContent').innerHTML = '<div class="text-muted text-sm">Nu exista valori stocate inca. Ruleaza cron-ul pentru a popula IP-urile.</div>';
    }
}

function renderQuick(data) {
    const el = document.getElementById('quickContent');
    if (!(data.ips?.length) && !(data.ns?.length)) {
        el.innerHTML = '<div class="text-muted text-sm" style="padding:4px 0">Nicio valoare stocata inca. Ruleaza cron-ul pentru a popula IP-urile si NS-urile.</div>';
        return;
    }
    let html = '';
    if (data.ips?.length) {
        html += '<div style="margin-bottom:10px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:600">IP-uri detectate</div>';
        data.ips.forEach(({ip, count}) => {
            html += `<span class="query-chip" onclick="setAndSearch('${ip}')">&#128205; ${ip} <span style="color:var(--text3)">(${count})</span></span>`;
        });
        html += '</div>';
    }
    if (data.ns?.length) {
        html += '<div><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:600">Nameservere detectate</div>';
        data.ns.forEach(({ns, count}) => {
            html += `<span class="query-chip" onclick="setAndSearch('${ns}')">&#128279; ${ns} <span style="color:var(--text3)">(${count})</span></span>`;
        });
        html += '</div>';
    }
    el.innerHTML = html;
}

function setAndSearch(val) {
    document.getElementById('queryInput').value = val;
    doSearch();
}

async function doSearch() {
    const q = document.getElementById('queryInput').value.trim();
    if (!q) { document.getElementById('queryInput').focus(); return; }

    const btn = document.getElementById('searchBtn');
    const txt = document.getElementById('searchBtnTxt');
    btn.disabled = true;
    txt.innerHTML = '<span class="spinner-sm"></span> Cauta...';

    const wrap = document.getElementById('resultsWrap');
    wrap.style.display = '';
    wrap.innerHTML = `<div class="result-section"><div class="result-section-body"><div style="text-align:center;padding:20px;color:var(--text3)"><span class="spinner-sm"></span> Se cauta...</div></div></div>`;

    try {
        const fd = new FormData();
        fd.append('csrf_token', CSRF);
        fd.append('action', 'search');
        fd.append('query', q);
        const resp = await fetch('/network', {method:'POST', body:fd});
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const data = await resp.json();
        renderResults(data, q);
    } catch(e) {
        wrap.innerHTML = `<div class="alert alert-danger">Eroare: ${e.message}</div>`;
    } finally {
        btn.disabled = false;
        txt.textContent = 'Cauta';
    }
}

function renderResults(data, q) {
    const wrap = document.getElementById('resultsWrap');
    const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(q);
    let html = '';

    html += `<div style="margin-bottom:16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <span style="font-family:monospace;font-size:1.1rem;font-weight:700">${q}</span>
        <span class="intel-badge info">${isIp ? '&#128205; IP Address' : '&#128279; Nameserver'}</span>
        <span style="color:var(--text3);font-size:.82rem">— ${new Date().toLocaleString('ro-RO')}</span>
    </div>`;

    const dbMatches = data.db_matches || [];
    html += `<div class="result-section">
        <div class="result-section-header">
            <span style="font-size:18px">&#127968;</span>
            <div class="result-section-title">Din lista ta — ${dbMatches.length} domeniu${dbMatches.length !== 1 ? 'i' : ''}</div>
        </div>
        <div class="result-section-body">`;
    if (dbMatches.length === 0) {
        html += `<div class="empty-net">&#128269; Niciun domeniu din lista ta nu corespunde acestui ${isIp ? 'IP' : 'NS'}.</div>`;
    } else {
        dbMatches.forEach(row => {
            html += `<div class="domain-row">
                <span class="domain-name" style="font-size:.88rem;flex:1">${row.domain}</span>
                <span class="badge ${row.status}" style="font-size:.7rem;padding:2px 8px">${row.status}</span>
                ${row.match_type === 'ns' && row.match_value ? `<span class="ns-tag">${row.match_value}</span>` : ''}
                <span style="color:var(--text3);font-size:.75rem">${row.domain_type}</span>
                <a href="/lookup?domain=${encodeURIComponent(row.domain)}" class="btn btn-ghost btn-sm" style="padding:3px 8px">&#128270;</a>
                <a href="/history?domain=${encodeURIComponent(row.domain)}" class="btn btn-ghost btn-sm" style="padding:3px 8px">&#128203;</a>
            </div>`;
        });
    }
    html += `</div></div>`;

    if (isIp) {
        const extMatches = data.external_matches || [];
        const extError   = data.external_error || null;
        html += `<div class="result-section">
            <div class="result-section-header">
                <span style="font-size:18px">&#127758;</span>
                <div class="result-section-title">External — HackerTarget Reverse IP</div>
                ${extMatches.length ? `<span class="intel-badge info" style="margin-left:auto">${extMatches.length} domenii</span>` : ''}
            </div>
            <div class="result-section-body">`;
        if (extError) {
            html += `<div class="text-muted text-sm">${extError}</div>
                <a href="https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(q)}" target="_blank" class="btn btn-ghost btn-sm" style="margin-top:8px">&#128279; Verifica pe HackerTarget</a>`;
        } else if (extMatches.length === 0) {
            html += `<div class="empty-net">&#10003; Niciun domeniu gasit extern pe acest IP.</div>`;
        } else {
            const dbDomains = new Set(dbMatches.map(r => r.domain));
            extMatches.slice(0, 50).forEach(d => {
                html += `<div class="domain-row">
                    <span class="domain-name" style="font-size:.85rem;flex:1">${d}</span>
                    ${dbDomains.has(d) ? '<span class="intel-badge ok" style="font-size:.68rem">in lista ta</span>' : ''}
                    <a href="/lookup?domain=${encodeURIComponent(d)}" class="btn btn-ghost btn-sm" style="padding:3px 8px">&#128270;</a>
                </div>`;
            });
            if (extMatches.length > 50) {
                html += `<div style="padding:10px;color:var(--text3);font-size:.83rem;text-align:center">...si inca ${extMatches.length - 50} domenii. <a href="https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(q)}" target="_blank" style="color:var(--accent2)">Vezi toate &#8599;</a></div>`;
            }
        }
        html += `</div></div>`;
    }

    // Bloc NS extern
    if (!isIp && data.external_ns) {
        const ns = data.external_ns;
        const dbDomains = new Set(dbMatches.map(r => r.domain));
        html += `<div class="result-section">
            <div class="result-section-header">
                <span style="font-size:18px">&#127758;</span>
                <div class="result-section-title">Reverse NS extern</div>
                ${ns.total ? `<span class="intel-badge info" style="margin-left:auto">${ns.total} domenii</span>` : ''}
                ${ns.sources?.length ? `<span class="text-xs text-muted" style="margin-left:8px">Surse: ${ns.sources.join(', ')}</span>` : ''}
            </div>
            <div class="result-section-body">`;

        if (!ns.total && !ns.domains?.length) {
            html += `<div class="empty-net">&#128269; Niciun domeniu gasit extern pentru acest NS.<br>
                <div style="margin-top:10px;display:flex;gap:8px;justify-content:center;flex-wrap:wrap">
                    <a href="https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(q)}" target="_blank" class="btn btn-ghost btn-sm">&#128279; HackerTarget</a>
                    <a href="https://viewdns.info/reversens/?ns=${encodeURIComponent(q)}" target="_blank" class="btn btn-ghost btn-sm">&#128279; ViewDNS.info</a>
                </div>
            </div>`;
        } else {
            // Afiseaza primele 100, restul collapse
            const domains = ns.domains || [];
            const showLimit = 100;
            domains.slice(0, showLimit).forEach(d => {
                const inDb = dbDomains.has(d);
                html += `<div class="domain-row">
                    <span class="domain-name" style="font-size:.85rem;flex:1">${d}</span>
                    ${inDb ? '<span class="intel-badge ok" style="font-size:.68rem">&#10003; in lista ta</span>' : ''}
                    <a href="/lookup?domain=${encodeURIComponent(d)}" class="btn btn-ghost btn-sm" style="padding:3px 8px" title="Intelligence">&#128202;</a>
                    <a href="/network?q=${encodeURIComponent(d)}" class="btn btn-ghost btn-sm" style="padding:3px 8px" title="Lookup domeniu">&#128270;</a>
                </div>`;
            });
            if (domains.length > showLimit) {
                html += `<div id="nsMoreWrap" style="display:none">`;
                domains.slice(showLimit).forEach(d => {
                    const inDb = dbDomains.has(d);
                    html += `<div class="domain-row">
                        <span class="domain-name" style="font-size:.85rem;flex:1">${d}</span>
                        ${inDb ? '<span class="intel-badge ok" style="font-size:.68rem">&#10003; in lista ta</span>' : ''}
                        <a href="/lookup?domain=${encodeURIComponent(d)}" class="btn btn-ghost btn-sm" style="padding:3px 8px">&#128202;</a>
                        <a href="/network?q=${encodeURIComponent(d)}" class="btn btn-ghost btn-sm" style="padding:3px 8px">&#128270;</a>
                    </div>`;
                });
                html += `</div>
                <div style="text-align:center;margin-top:10px">
                    <button class="btn btn-ghost btn-sm" onclick="document.getElementById('nsMoreWrap').style.display='';this.style.display='none'">
                        + Arata inca ${domains.length - showLimit} domenii
                    </button>
                </div>`;
            }
            // Link-uri externe
            html += `<div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border);display:flex;gap:8px;flex-wrap:wrap">
                <a href="https://viewdns.info/reversens/?ns=${encodeURIComponent(q)}" target="_blank" class="btn btn-ghost btn-sm">&#128279; ViewDNS.info</a>
                <a href="https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(q)}" target="_blank" class="btn btn-ghost btn-sm">&#128279; HackerTarget</a>
                <a href="https://crt.sh/?q=${encodeURIComponent(q)}" target="_blank" class="btn btn-ghost btn-sm">&#128279; crt.sh</a>
            </div>`;
        }

        if (ns.errors?.length) {
            html += `<div style="margin-top:8px;font-size:.75rem;color:var(--text3)">&#9888; Unele surse au esuat: ${ns.errors.join(' · ')}</div>`;
        }
        html += `</div></div>`;
    }

    const extNsTotal = (!isIp && data.external_ns?.total) || 0;
    const total = dbMatches.length + (isIp ? (data.external_matches?.length || 0) : extNsTotal);
    html += `<div style="margin-top:8px;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:8px;font-size:.83rem;color:var(--text2)">
        <strong style="color:var(--text)">${dbMatches.length}</strong> in lista ta
        ${isIp && data.external_matches?.length ? ` &nbsp;·&nbsp; <strong style="color:var(--text)">${data.external_matches.length}</strong> externe (HackerTarget)` : ''}
        ${!isIp && extNsTotal ? ` &nbsp;·&nbsp; <strong style="color:var(--text)">${extNsTotal}</strong> externe (Reverse NS)` : ''}
        &nbsp;·&nbsp; <a href="javascript:void(0)" onclick="document.getElementById('queryInput').value='';document.getElementById('resultsWrap').style.display='none'" style="color:var(--accent2)">Cauta altul</a>
    </div>`;

    wrap.innerHTML = html;
}

// Init
loadQuick();

// Pre-fill din URL
const urlParams = new URLSearchParams(window.location.search);
const preQ = urlParams.get('q');
if (preQ) {
    document.getElementById('queryInput').value = preQ;
    doSearch();
}

document.getElementById('queryInput').focus();
</script>

<?php include 'includes/footer.php'; ?>
