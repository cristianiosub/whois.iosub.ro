<?php
// finder.php — Domain Finder / Content Site Brief Analyzer
require_once 'config.php';
require_once 'includes/auth.php';
require_once 'includes/db.php';
require_once 'includes/whois.php';
requireLogin();

$db        = getDB();
$csrfToken = getCsrfToken();
$pageTitle = 'Domain Finder';

/* ============================================================
   POST HANDLERS (JSON)
   ============================================================ */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // Actiunile care schimba starea necesita CSRF
    if ($action === 'add_to_monitor') {
        validateCsrf();
        $d       = strtolower(trim($_POST['domain'] ?? ''));
        $label   = in_array($_POST['label'] ?? '', array_keys(LABELS)) ? $_POST['label'] : null;
        $notes   = trim($_POST['notes'] ?? '');
        $dtype   = ($_POST['domain_type'] ?? 'monitor') === 'owned' ? 'owned' : 'monitor';
        $expires = !empty($_POST['expires_on']) ? $_POST['expires_on'] : null;
        $interval = $label ? LABELS[$label]['interval'] : 5;
        if (isValidDomain($d)) {
            try {
                $tld = extractTld($d);
                $db->prepare("INSERT INTO domains (domain, tld, notes, label, check_interval_minutes, domain_type, expires_on, added_by) VALUES (?,?,?,?,?,?,?,?)")
                   ->execute([$d, $tld, $notes, $label, $interval, $dtype, $expires, $_SESSION['user_id']]);
                header('Location: /domains');
                exit;
            } catch (PDOException $e) {
                $addError = ($e->getCode() === '23000') ? 'Domeniu deja in lista.' : 'Eroare la salvare.';
            }
        }
    }

    if ($action === 'check_candidate') {
        header('Content-Type: application/json');
        $d = strtolower(trim($_POST['domain'] ?? ''));
        $d = preg_replace('/^(https?:\/\/)?(www\.)?/', '', $d);
        $d = rtrim($d, '/');
        if (!isValidDomain($d)) {
            echo json_encode(['domain' => $d, 'error' => 'Format invalid']);
            exit;
        }
        $result = checkDomain($d);
        $chk = $db->prepare("SELECT id FROM domains WHERE domain=?");
        $chk->execute([$d]);
        $existing = $chk->fetch();
        echo json_encode([
            'domain'     => $d,
            'status'     => $result['status'],
            'registrar'  => $result['registrar'] ?? null,
            'expires_on' => $result['expires_on'] ?? null,
            'already_in' => $existing ? $d : false,
        ]);
        exit;
    }

    if ($action === 'debug_groq') {
        header('Content-Type: application/json');
        $ch = curl_init('https://api.groq.com/openai/v1/chat/completions');
        $payload = json_encode([
            'model'      => 'llama-3.3-70b-versatile',
            'messages'   => [['role' => 'user', 'content' => 'Reply with exactly this JSON array: ["test.com","hello.ro"]']],
            'max_tokens' => 100,
        ]);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . GROQ_API_KEY,
            ],
        ]);
        $resp   = curl_exec($ch);
        $http   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $cerr   = curl_error($ch);
        curl_close($ch);
        echo json_encode([
            'http'  => $http,
            'curl_error' => $cerr,
            'raw'   => $resp,
            'php'   => PHP_VERSION,
        ]);
        exit;
    }

    if ($action === 'find_alternatives_ai') {
        header('Content-Type: application/json');
        set_time_limit(30);
        $excluded = array_filter(array_map('trim', explode(',', $_POST['excluded_domains'] ?? '')));
        $brief = [
            'language'    => strtoupper(trim($_POST['language'] ?? 'EN')),
            'niche'       => strtolower(trim($_POST['niche'] ?? '')),
            'site_type'   => strtolower(trim($_POST['site_type'] ?? '')),
            'brand_name'  => trim($_POST['brand_name'] ?? ''),
            'positioning' => strtolower(trim($_POST['positioning'] ?? '')),
            'articles'    => strtolower(trim($_POST['articles'] ?? '')),
            'excluded'    => $excluded,
        ];
        echo json_encode(finderGenerateAlternativesGroq($brief));
        exit;
    }

    if ($action === 'find_alternatives') {
        header('Content-Type: application/json');
        set_time_limit(60);
        $excluded = array_filter(array_map('trim', explode(',', $_POST['excluded_domains'] ?? '')));
        $brief = [
            'language'      => strtoupper(trim($_POST['language'] ?? 'EN')),
            'niche'         => strtolower(trim($_POST['niche'] ?? '')),
            'site_type'     => strtolower(trim($_POST['site_type'] ?? '')),
            'brand_name'    => trim($_POST['brand_name'] ?? ''),
            'positioning'   => strtolower(trim($_POST['positioning'] ?? '')),
            'articles'      => strtolower(trim($_POST['articles'] ?? '')),
            'failed_domain' => strtolower(trim($_POST['failed_domain'] ?? '')),
            'seed_override' => strtolower(trim($_POST['seed_override'] ?? '')),
            'excluded'      => $excluded,
        ];
        echo json_encode(finderGenerateAlternatives($brief));
        exit;
    }

    if ($action === 'batch_check') {
        header('Content-Type: application/json');
        $d = strtolower(trim($_POST['domain'] ?? ''));
        $d = preg_replace('/^(https?:\/\/)?(www\.)?/', '', $d);
        $d = rtrim($d, '/');
        if (!isValidDomain($d)) {
            echo json_encode(['domain' => $d, 'error' => 'Invalid']);
            exit;
        }
        $result = checkDomain($d);
        $chk = $db->prepare("SELECT id FROM domains WHERE domain=?");
        $chk->execute([$d]);
        $existing = $chk->fetch();
        echo json_encode([
            'domain'     => $d,
            'status'     => $result['status'],
            'already_in' => $existing ? $d : false,
        ]);
        exit;
    }
}

/* ============================================================
   GENERATOR FUNCTIONS
   ============================================================ */

function finderStopWords(): array {
    return [
        'the','and','for','with','from','this','that','are','was','has','have',
        'been','your','our','their','more','very','also','some','into','over',
        'after','site','news','content','about','blog','page','post','most',
        'make','then','when','what','which','who','how','why','its','is','in',
        'on','at','to','of','a','an','it','be','by','we','as','do','if','or',
        // Romana
        'si','cu','pe','de','la','sau','mai','dar','din','ce','ca','sa','se',
        'nu','fie','prin','care','ale','cel','cei','cat','mult','daca','este',
        'sunt','prin','fara','intr','insa','chiar','acum','inca','doar','orice',
        // Generic web/marketing
        'web','site','online','digital','media','platform','service','services',
        'business','company','pro','plus','get','use','the','my','go',
    ];
}

function finderExtractKeywords(array $brief): array {
    $kws  = [];
    $stop = finderStopWords();

    // 1. Brand name — cea mai mare prioritate (split pe spatiu / cratima)
    foreach (preg_split('/[\s\-_]+/', strtolower($brief['brand_name'])) as $w) {
        $w = preg_replace('/[^a-z0-9]/', '', $w);
        if (strlen($w) >= 3 && !in_array($w, $stop)) $kws[] = $w;
    }

    // 2. Nisa
    foreach (preg_split('/[\s\/\-,]+/', $brief['niche']) as $w) {
        $w = preg_replace('/[^a-z0-9]/', '', $w);
        if (strlen($w) >= 4 && !in_array($w, $stop)) $kws[] = $w;
    }

    // 3. Pozitionare — cuvinte >= 5 litere
    foreach (preg_split('/[\s,;.]+/', $brief['positioning']) as $w) {
        $w = preg_replace('/[^a-z0-9]/', '', $w);
        if (strlen($w) >= 5 && !in_array($w, $stop)) $kws[] = $w;
    }

    // 4. Tipuri de articole — cuvinte >= 4 litere
    foreach (preg_split('/[\s,;]+/', $brief['articles']) as $w) {
        $w = preg_replace('/[^a-z0-9]/', '', strtolower($w));
        if (strlen($w) >= 4 && !in_array($w, $stop)) $kws[] = $w;
    }

    return array_values(array_unique(array_filter($kws)));
}

function finderDetectIndustry(array $brief): string {
    $text = strtolower(
        $brief['niche'] . ' ' . $brief['site_type'] . ' ' .
        $brief['positioning'] . ' ' . $brief['brand_name']
    );
    $map = [
        'beauty'  => ['beauty','frumusete','skincare','cosmet','makeup','hair',
                      'skin','ingrijire','rutina','glow','radiant','dermato'],
        'tech'    => ['tech','crypto','digital','software','code','cyber','web',
                      'blockchain','defi','programming','saas','cloud','pixel'],
        'finance' => ['fintech','finance','invest','money','banking','payments',
                      'financial','bani','fonduri','capital','trading','stock'],
        'food'    => ['food','recipe','cook','mancare','reteta','restaurant',
                      'gastro','cooking','culinar','kitchen','chef'],
        'health'  => ['health','medical','wellness','fitness','sport','sanatate',
                      'clinic','pharma','doctor','nutritie','vita'],
        'travel'  => ['travel','tourism','trip','hotel','flight','calator',
                      'turism','destination','voyage','explore'],
        'edu'     => ['education','learning','course','training','school',
                      'cursuri','tutorial','academy','mentor','study'],
        'news'    => ['news','stiri','journalism','media','press','international',
                      'analysis','briefing','report','coverage','editorial'],
    ];
    foreach ($map as $ind => $kws) {
        foreach ($kws as $kw) {
            if (str_contains($text, $kw)) return $ind;
        }
    }
    return 'general';
}

function finderGetSynonyms(string $industry): array {
    $map = [
        'beauty'  => ['glow','radiant','bloom','luminous','belle','aura','pura',
                      'vibes','grace','velvet','shimmer','lumi','skyn','glami',
                      'zest','fleur','ritual','serenity','bliss','elixir'],
        'tech'    => ['nexus','forge','craft','logic','pivot','launch','sprint',
                      'stack','node','flux','shift','pulse','grid','sync','proto',
                      'hub','wire','dev','build','ship'],
        'finance' => ['yield','capita','asset','profit','vest','prime','forte',
                      'equity','vault','ledger','current','flow','cash','fund',
                      'gain','slate','merit'],
        'food'    => ['plate','savor','bite','zest','spice','feast','kitchen',
                      'nourish','fresh','taste','table','dine','chef'],
        'health'  => ['vitae','forte','vigour','prime','elevate','thrive',
                      'revive','renew','pulse','core','vita','heal','boost'],
        'travel'  => ['roam','venture','wander','atlas','route','compass',
                      'horizon','trek','escape','voyage','journey','drift'],
        'edu'     => ['campus','mentor','spark','scholar','master','skill',
                      'learn','guide','tutor','nexus','quest','bright'],
        'news'    => ['brief','pulse','daily','report','wire','signal','watch',
                      'feed','hub','digest','radar','post','desk','scope'],
        'general' => ['hub','lab','studio','works','space','zone','base','core',
                      'peak','rise','edge','plus','pro','hq','sphere','depot'],
    ];
    return $map[$industry] ?? $map['general'];
}

function finderSmartTlds(string $base, string $lang, string $industry): array {
    $len = strlen(str_replace('-', '', $base));
    if ($lang === 'RO') {
        return ['ro', 'com', 'eu'];
    }
    // English — vary by length + industry
    if (in_array($industry, ['tech', 'finance'])) {
        return $len <= 7 ? ['com', 'io', 'co'] : ['com', 'io', 'net'];
    }
    if ($industry === 'news') {
        return ['com', 'net', 'co'];
    }
    if ($industry === 'edu') {
        return ['com', 'net', 'org'];
    }
    return $len <= 7 ? ['com', 'co', 'net'] : ['com', 'net', 'org'];
}

function finderGenerateAlternatives(array $brief): array {
    $lang       = $brief['language'];
    $industry   = finderDetectIndustry($brief);
    // Seed: use seed_override if set, otherwise failed_domain
    $seed       = !empty($brief['seed_override']) ? $brief['seed_override'] : $brief['failed_domain'];
    $dotPos     = strrpos($seed, '.');
    $failedBase = $dotPos !== false ? substr($seed, 0, $dotPos) : $seed;
    $seedTld    = $dotPos !== false ? substr($seed, $dotPos + 1) : '';
    // Smart TLD pool based on language + industry
    $tlds       = finderSmartTlds($failedBase ?: 'domain', $lang, $industry);
    $tldA       = $tlds[0];
    $tldB       = $tlds[1] ?? $tldA;
    $tldC       = $tlds[2] ?? $tldB;
    $failedTld  = $seedTld ?: $tldA;

    $kws       = finderExtractKeywords($brief);
    $synonyms  = finderGetSynonyms($industry);
    $primaryKw = $kws[0] ?? $failedBase;

    $cands = [];

    // 1. Acelasi base, toate TLD-urile smart pool
    foreach (array_unique([$tldA, $tldB, $tldC, 'eu', 'co', 'io']) as $t) {
        if ($t !== $failedTld && !empty($failedBase)) $cands[] = "$failedBase.$t";
    }

    // 2. Cuvinte-cheie individuale — 3 TLD-uri fiecare
    foreach (array_slice($kws, 0, 5) as $kw) {
        if ($kw !== $failedBase && strlen($kw) >= 4) {
            $cands[] = "$kw.$tldA";
            $cands[] = "$kw.$tldB";
            $cands[] = "$kw.$tldC";
        }
    }

    // 3. Prefixe + cuvinte-cheie
    $prefixes = ['my','get','go','pro','smart','the','use','top','best','try','read','now'];
    foreach (array_slice($kws, 0, 3) as $kw) {
        foreach ($prefixes as $px) {
            $v = $px . $kw;
            if (strlen($v) >= 5 && strlen($v) <= 16) {
                $cands[] = "$v.$tldA";
                $cands[] = "$v.$tldB";
            }
        }
    }

    // 4. Cuvinte-cheie + sufixe
    $suffixes = ['hub','lab','pro','app','hq','plus','now','co','studio',
                 'guide','daily','zone','works','desk','wire','brief','pulse'];
    foreach (array_slice($kws, 0, 3) as $kw) {
        foreach ($suffixes as $sx) {
            $v = $kw . $sx;
            if (strlen($v) >= 5 && strlen($v) <= 16) {
                $cands[] = "$v.$tldA";
                $cands[] = "$v.$tldB";
            }
        }
    }

    // 5. Combinatii de cuvinte-cheie (kw1+kw2, kw2+kw1, kw1-kw2)
    if (count($kws) >= 2) {
        for ($i = 0; $i < min(3, count($kws)); $i++) {
            for ($j = $i + 1; $j < min(5, count($kws)); $j++) {
                $a = $kws[$i]; $b = $kws[$j];
                foreach (["$a$b", "$b$a", "$a-$b"] as $v) {
                    if (strlen(str_replace('-', '', $v)) >= 5 && strlen($v) <= 18) {
                        $cands[] = "$v.$tldA";
                        $cands[] = "$v.$tldC";
                    }
                }
            }
        }
    }

    // 6. Sinonime + cuvant-cheie primar (2 TLD-uri)
    foreach (array_slice($synonyms, 0, 12) as $syn) {
        $v1 = $primaryKw . $syn;
        $v2 = $syn . $primaryKw;
        foreach ([$v1, $v2] as $v) {
            if (strlen($v) >= 5 && strlen($v) <= 15) {
                $cands[] = "$v.$tldA";
                $cands[] = "$v.$tldB";
            }
        }
        // Sinonim standalone (scurt)
        if (strlen($syn) >= 4 && strlen($syn) <= 8) {
            $cands[] = "$syn.$tldA";
            $cands[] = "$syn.$tldC";
        }
    }

    // 7. Al doilea cuvant-cheie + sinonime
    if (isset($kws[1])) {
        foreach (array_slice($synonyms, 0, 6) as $syn) {
            $v = $kws[1] . $syn;
            if (strlen($v) >= 5 && strlen($v) <= 14) {
                $cands[] = "$v.$tldA";
                $cands[] = "$v.$tldB";
            }
        }
    }

    // Filtreaza, scoreza, deduplicheaza
    $seen   = [];
    $scored = [];
    foreach (array_unique($cands) as $cand) {
        if ($cand === $seed) continue;
        if (!preg_match('/^[a-z0-9][a-z0-9\-]{1,20}[a-z0-9]\.[a-z]{2,}$/', $cand)) continue;
        [$cBase] = explode('.', $cand);
        if (str_contains($cBase, '--')) continue;
        if (strlen($cBase) < 3 || strlen($cBase) > 20) continue;
        if (!isset($seen[$cBase])) $seen[$cBase] = 0;
        if ($seen[$cBase] >= 3) continue;
        $seen[$cBase]++;

        [$sc, $reason] = finderScore($cand, $kws, $industry, $lang);
        $scored[] = ['domain' => $cand, 'score' => $sc, 'reason' => $reason, 'available' => null];
    }

    usort($scored, fn($a, $b) => $b['score'] <=> $a['score']);

    // Exclude domains already shown in other cards
    $excludeSet = array_flip($brief['excluded'] ?? []);
    if (!empty($excludeSet)) {
        $scored = array_values(array_filter($scored, fn($x) => !isset($excludeSet[$x['domain']])));
    }

    return array_values(array_slice($scored, 0, 20));
}

function finderScore(string $domain, array $keywords, string $industry, string $lang): array {
    [$base, $tld] = array_pad(explode('.', $domain, 2), 2, 'com');
    $len   = strlen($base);
    $score = 0;
    $parts = [];

    // Lungime (30 pts)
    if ($len <= 7)      { $score += 30; $parts[] = 'foarte scurt'; }
    elseif ($len <= 10) { $score += 22; $parts[] = 'scurt'; }
    elseif ($len <= 13) { $score += 13; $parts[] = 'mediu'; }
    else                { $score +=  4; $parts[] = 'lung'; }

    // Pronuntabilitate (25 pts)
    $vow   = preg_match_all('/[aeiouy]/i', $base);
    $ratio = $len > 0 ? $vow / $len : 0;
    if ($ratio >= 0.30 && $ratio <= 0.60)  { $score += 20; $parts[] = 'usor de pronuntat'; }
    elseif ($ratio >= 0.20)                { $score += 12; }
    else                                   { $score +=  4; $parts[] = 'greu de pronuntat'; }
    if (!preg_match('/[bcdfghjklmnpqrstvwxyz]{3}/i', $base)) $score += 5;

    // TLD (15 pts) — preferat in functie de limba
    $preferred = ($lang === 'RO') ? 'ro' : 'com';
    if ($tld === $preferred)                             { $score += 15; $parts[] = '.' . $tld; }
    elseif (in_array($tld, ['ro', 'com']))               { $score += 10; $parts[] = '.' . $tld; }
    elseif ($tld === 'eu')                               { $score +=  8; }
    elseif (in_array($tld, ['io','co','app','net']))     { $score +=  6; }
    else                                                 { $score +=  3; }

    // Relevanta cuvinte-cheie (15 pts)
    foreach ($keywords as $kw) {
        if (strlen($kw) >= 4 && str_contains($base, $kw)) {
            $score += 10; $parts[] = "contine '$kw'"; break;
        }
    }
    if ($industry !== 'general') $score += 5;

    // Brandabilitate (15 pts)
    if (!preg_match('/\d/', $base))  $score += 8;
    if (!str_contains($base, '-'))   $score += 4;
    if ($len >= 5 && $len <= 10)     $score += 3;

    $score = min(100, max(1, $score));
    return [$score, implode(', ', $parts) ?: 'standard'];
}

/* ============================================================
   GROQ AI — domain name generator
   ============================================================ */

function finderCallGroq(string $prompt): ?string {
    $ch = curl_init('https://api.groq.com/openai/v1/chat/completions');
    $payload = json_encode([
        'model'       => 'llama-3.3-70b-versatile',
        'messages'    => [['role' => 'user', 'content' => $prompt]],
        'max_tokens'  => 1024,
        'temperature' => 0.8,
    ]);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 20,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'Authorization: Bearer ' . GROQ_API_KEY,
        ],
    ]);
    $resp = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($http !== 200 || !$resp) return null;
    $data = json_decode($resp, true);
    return $data['choices'][0]['message']['content'] ?? null;
}

function finderBuildGroqPrompt(array $brief): string {
    $lang     = $brief['language'] === 'RO' ? 'Romanian' : 'English';
    $tld      = $brief['language'] === 'RO' ? '.ro or .com' : '.com, .io or .co';
    $excluded = implode(', ', array_slice($brief['excluded'] ?? [], 0, 30));

    $lines   = [];
    $lines[] = 'You are a creative domain name expert.';
    $lines[] = 'Generate exactly 20 domain name suggestions for a website with this brief:';
    $lines[] = "- Language: {$lang}";
    if (!empty($brief['niche']))       $lines[] = "- Niche: {$brief['niche']}";
    if (!empty($brief['site_type']))   $lines[] = "- Site type: {$brief['site_type']}";
    if (!empty($brief['brand_name']))  $lines[] = "- Brand name: {$brief['brand_name']}";
    if (!empty($brief['positioning'])) $lines[] = "- Positioning: {$brief['positioning']}";
    if (!empty($brief['articles']))    $lines[] = "- Content types: {$brief['articles']}";
    $lines[] = 'Requirements:';
    $lines[] = "- Use TLD {$tld}";
    $lines[] = '- Names must be short (5-14 chars), brandable, easy to spell';
    $lines[] = '- Mix creative combos: prefixes, suffixes, synonyms';
    if ($excluded) $lines[] = "- Do NOT suggest these (already used): {$excluded}";
    $lines[] = 'Return ONLY a valid JSON array of domain names, nothing else.';
    $lines[] = 'Example format: ["glowagenda.ro","glowhub.com","agendaglow.ro"]';

    return implode("\n", $lines);
}

function finderGenerateAlternativesGroq(array $brief): array {
    $prompt = finderBuildGroqPrompt($brief);
    $text   = finderCallGroq($prompt);
    if (!$text) return [];

    if (!preg_match('/(\[[\s\S]*?\])/s', $text, $m)) return [];
    $domains = json_decode($m[1], true);
    if (!is_array($domains)) return [];

    $kws      = finderExtractKeywords($brief);
    $industry = finderDetectIndustry($brief);
    $lang     = $brief['language'];
    $excluded = array_flip($brief['excluded'] ?? []);

    $results = [];
    foreach ($domains as $raw) {
        $d = strtolower(trim((string)$raw));
        $d = preg_replace('/^(https?:\/\/)?(www\.)?/', '', $d);
        $d = rtrim($d, '/');
        if (!isValidDomain($d)) continue;
        if (isset($excluded[$d])) continue;
        [$sc, $reason] = finderScore($d, $kws, $industry, $lang);
        $results[] = ['domain' => $d, 'score' => $sc, 'reason' => '✦ AI: ' . $reason, 'available' => null];
    }
    usort($results, fn($a, $b) => $b['score'] <=> $a['score']);
    return array_values(array_slice($results, 0, 20));
}

include 'includes/header.php';
?>

<style>
/* ---- FINDER PAGE STYLES ---- */
.finder-mode-bar{display:flex;gap:6px;margin-bottom:20px}
.finder-tab{padding:8px 18px;border-radius:8px;font-size:.85rem;font-weight:500;cursor:pointer;border:1px solid var(--border);background:transparent;color:var(--text2);font-family:inherit;transition:.15s}
.finder-tab.active{background:rgba(139,92,246,.15);color:var(--purple);border-color:rgba(139,92,246,.3)}
.finder-tab:hover:not(.active){background:var(--surface2);color:var(--text)}

.finder-hero{background:linear-gradient(135deg,rgba(139,92,246,.08),rgba(59,130,246,.06));border:1px solid rgba(139,92,246,.2);border-radius:16px;padding:28px 32px;margin-bottom:24px;position:relative;overflow:hidden}
.finder-hero::before{content:'';position:absolute;top:-60%;left:50%;transform:translateX(-50%);width:400px;height:400px;background:radial-gradient(circle,rgba(139,92,246,.06) 0%,transparent 70%);pointer-events:none}
.finder-hero h2{font-size:1.3rem;font-weight:700;margin-bottom:6px}
.finder-hero p{color:var(--text2);font-size:.88rem}

.fields-row{display:grid;gap:14px;margin-bottom:14px}
.fields-row.cols-3{grid-template-columns:100px 1fr 1fr}
.fields-row.cols-2{grid-template-columns:1fr 2fr}

.domain-inputs{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}
.candidate-list{display:flex;flex-direction:column;gap:0;margin-bottom:20px;border:1.5px solid var(--border);border-radius:12px;overflow:hidden}
.candidate-slot{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 16px;transition:background .2s}
.candidate-slot:last-child{border-bottom:none}
.candidate-slot.slot-available{background:rgba(16,185,129,.03)}
.candidate-slot.slot-taken{background:rgba(239,68,68,.02)}
.crow-main{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.cslot-domain{font-family:monospace;font-weight:700;font-size:.88rem;color:var(--text);min-width:180px}
.cslot-status{font-size:.8rem;flex:1}

.alt-section{border:1px solid rgba(139,92,246,.2);border-radius:10px;overflow:hidden;margin-top:10px}
.alt-section-header{background:linear-gradient(135deg,rgba(139,92,246,.1),rgba(59,130,246,.04));padding:8px 12px;border-bottom:1px solid rgba(139,92,246,.15);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:4px}
.alt-section-title{font-size:.78rem;font-weight:600;color:var(--purple);display:flex;align-items:center;gap:5px}
.alt-mini-table{width:100%;border-collapse:collapse}
.alt-mini-table th{text-align:left;font-size:.65rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.4px;padding:5px 8px;border-bottom:1px solid var(--border);white-space:nowrap}
.alt-mini-table td{padding:5px 8px;border-bottom:1px solid rgba(30,45,69,.35);font-size:.77rem;vertical-align:middle}
.alt-mini-table tr:last-child td{border-bottom:none}
.alt-mini-table tr.alt-avail td{background:rgba(16,185,129,.03)}
.score-bar-mini{display:flex;align-items:center;gap:4px}
.score-track{width:32px;height:3px;background:var(--surface2);border-radius:999px;overflow:hidden;flex-shrink:0}
.score-fill{height:100%;border-radius:999px}
.alt-hint-bar{padding:6px 10px;font-size:.7rem;color:var(--text3);background:var(--surface2);border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:8px}
.alt-load-more{background:none;border:none;color:var(--purple);font-size:.72rem;cursor:pointer;font-family:inherit;padding:0;text-decoration:underline}

.paste-area{width:100%;background:var(--surface2);border:1.5px solid rgba(139,92,246,.25);border-radius:12px;padding:14px 16px;color:var(--text);font-size:.85rem;font-family:monospace;min-height:80px;resize:vertical;transition:.2s;line-height:1.6}
.paste-area:focus{outline:none;border-color:var(--purple);box-shadow:0 0 0 3px rgba(139,92,246,.1)}
.paste-parsed-ok{background:rgba(16,185,129,.08);border:1px solid rgba(16,185,129,.25);border-radius:8px;padding:10px 14px;font-size:.82rem;color:#6ee7b7;margin-bottom:12px;display:none}

.analyze-btn{padding:13px 32px;background:linear-gradient(135deg,var(--purple),var(--accent));border:none;border-radius:12px;color:#fff;font-size:.95rem;font-weight:600;cursor:pointer;font-family:inherit;transition:.2s;display:inline-flex;align-items:center;gap:8px}
.analyze-btn:hover{opacity:.9;transform:translateY(-1px)}
.analyze-btn:disabled{opacity:.6;cursor:not-allowed;transform:none}

.results-section{margin-top:24px}
.results-header{margin-bottom:16px;display:flex;align-items:center;gap:10px}
.results-header h3{font-size:1rem;font-weight:600}

.spinner-sm{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.25);border-top-color:var(--accent2);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
.status-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:4px;vertical-align:middle}

@media(max-width:900px){
    .fields-row.cols-3{grid-template-columns:90px 1fr}
    .fields-row.cols-3 > *:last-child{grid-column:1/-1}
    .fields-row.cols-2{grid-template-columns:1fr}
    .domain-inputs{grid-template-columns:1fr 1fr}
}
@media(max-width:580px){
    .finder-hero{padding:18px 16px}
    .domain-inputs{grid-template-columns:1fr}
}

/* ---- BRIEF SUGGESTIONS SECTION ---- */
.brief-suggest-section{margin-top:24px;border:1px solid rgba(16,185,129,.25);border-radius:14px;overflow:hidden}
.brief-suggest-header{background:linear-gradient(135deg,rgba(16,185,129,.08),rgba(59,130,246,.04));padding:12px 16px;border-bottom:1px solid rgba(16,185,129,.15);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.brief-suggest-title{font-size:.85rem;font-weight:600;color:#10b981;display:flex;align-items:center;gap:6px}
.brief-suggest-progress{font-size:.78rem;color:var(--text3);display:flex;align-items:center;gap:6px}
.bs-found-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px;padding:14px}
.bs-card{background:var(--surface);border:1.5px solid rgba(16,185,129,.3);border-radius:10px;padding:12px 14px;transition:.2s}
.bs-card.bs-pending{border-color:rgba(245,158,11,.4);background:rgba(245,158,11,.03)}
.bs-card-domain{font-family:monospace;font-weight:700;font-size:.88rem;margin-bottom:8px;word-break:break-all}
.bs-card-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.bs-empty{padding:24px;text-align:center;color:var(--text3);font-size:.85rem;grid-column:1/-1}
</style>

<div class="page-header">
    <h1>&#127919; Domain Finder</h1>
    <p>Verifica domenii din brief si genereaza alternative inteligente bazate pe brand, nisa si pozitionare</p>
</div>

<!-- Hero intro -->
<div class="finder-hero">
    <h2>Gaseste domeniul perfect pentru orice proiect</h2>
    <p>Completeaza brief-ul sau lipeste un rand din Excel &mdash; verificam disponibilitatea domeniilor si generam alternative algoritmice pentru cele ocupate.</p>
</div>

<!-- Input Card -->
<div class="card" style="margin-bottom:20px">
    <div class="finder-mode-bar">
        <button class="finder-tab active" id="tabManualBtn" onclick="setMode('manual',this)">&#9998; Completare manuala</button>
        <button class="finder-tab" id="tabPasteBtn" onclick="setMode('paste',this)">&#128203; Lipeste din Excel</button>
    </div>

    <!-- PASTE MODE -->
    <div id="pasteMode" style="display:none;margin-bottom:16px">
        <div class="form-group">
            <label class="form-label">Lipeste un rand din Excel (tab-separated)</label>
            <textarea id="pasteInput" class="paste-area"
                placeholder="ID&#9;Language&#9;Niche&#9;Site Type&#9;Brand Name&#9;Positioning&#9;Article Types&#9;Domain1&#9;Domain2&#9;Domain3&#9;Domain4&#9;Domain5"
                rows="3"></textarea>
            <div class="form-hint" style="margin-top:6px">Copiaza un rand intreg din Excel si lipeste-l aici &mdash; campurile se vor completa automat</div>
        </div>
        <div class="paste-parsed-ok" id="pasteOk">&#10003; Rand parsat &mdash; verifica campurile mai jos si apasa <strong>Analizeaza</strong></div>
        <button class="btn btn-ghost btn-sm" style="margin-top:8px" onclick="doParse()">&#10003; Parseaza si completeaza</button>
    </div>

    <!-- MANUAL FORM (shown always; auto-filled when paste is parsed) -->
    <div id="manualForm">
        <div class="fields-row cols-3">
            <div class="form-group">
                <label class="form-label">Limba</label>
                <select id="fLanguage" class="form-select">
                    <option value="RO">RO</option>
                    <option value="EN">EN</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Nisa</label>
                <input id="fNiche" class="form-input" placeholder="ex: Beauty, Crypto, Fintech">
            </div>
            <div class="form-group">
                <label class="form-label">Tip Site</label>
                <input id="fSiteType" class="form-input" placeholder="ex: Magazine Editorial, News + Analysis">
            </div>
        </div>

        <div class="fields-row cols-2">
            <div class="form-group">
                <label class="form-label">Nume Brand</label>
                <input id="fBrandName" class="form-input" placeholder="ex: Glow Agenda">
            </div>
            <div class="form-group">
                <label class="form-label">Positioning / Value Proposition</label>
                <input id="fPositioning" class="form-input" placeholder="ex: Magazin beauty modern cu accent pe rutine inteligente">
            </div>
        </div>

        <div class="form-group" style="margin-bottom:16px">
            <label class="form-label">Tipuri de articole</label>
            <input id="fArticles" class="form-input" placeholder="ex: rutina skincare; top produse; trenduri beauty; comparatii produse">
        </div>

        <div class="form-group" style="margin-bottom:22px">
            <label class="form-label">Domenii candidate <span style="color:var(--text3);font-weight:400;text-transform:none">(optional)</span></label>
            <div class="domain-inputs">
                <input id="fDomain1" class="form-input" style="font-family:monospace;font-size:.85rem" placeholder="domeniu1.ro">
                <input id="fDomain2" class="form-input" style="font-family:monospace;font-size:.85rem" placeholder="domeniu2.com">
                <input id="fDomain3" class="form-input" style="font-family:monospace;font-size:.85rem" placeholder="domeniu3.ro">
                <input id="fDomain4" class="form-input" style="font-family:monospace;font-size:.85rem" placeholder="domeniu4.com">
                <input id="fDomain5" class="form-input" style="font-family:monospace;font-size:.85rem" placeholder="domeniu5.eu">
            </div>
        </div>

        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
            <button class="analyze-btn" id="analyzeBtn" onclick="analyzeBrief()">
                &#128270; Analizeaza Brief-ul
            </button>
            <button class="btn btn-ghost btn-sm" onclick="clearForm()">&#10005; Goleste formularul</button>
            <button class="btn btn-ghost btn-sm" style="font-size:.75rem;color:var(--text3)" onclick="debugGroq()">&#128295; Debug Groq</button>
        </div>
        <div id="groqDebugOut" style="display:none;margin-top:12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;font-family:monospace;font-size:.75rem;white-space:pre-wrap;word-break:break-all;color:var(--text2)"></div>
    </div>
</div>

<!-- Results -->
<div id="resultsSection" class="results-section" style="display:none"></div>

<!-- Monitor Modal -->
<div class="modal-overlay" id="addMonitorModal">
    <div class="modal" style="max-width:520px">
        <div class="modal-header">
            <div class="modal-title">+ Adauga in Monitorizare</div>
            <button class="modal-close" onclick="closeModal('addMonitorModal')">&#10005;</button>
        </div>
        <p style="color:var(--text2);margin-bottom:16px;font-size:.9rem">
            Domeniu: <strong id="monitorDomain" style="color:var(--text);font-family:monospace"></strong>
        </p>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="add_to_monitor">
            <input type="hidden" name="domain" id="monitorDomainInput">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
                <div class="form-group">
                    <label class="form-label">Eticheta</label>
                    <select name="label" class="form-select">
                        <option value="">Fara eticheta</option>
                        <?php foreach (LABELS as $key => $l): ?>
                        <option value="<?= $key ?>"><?= $l['label'] ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Tip</label>
                    <select name="domain_type" class="form-select">
                        <option value="monitor">Monitorizare</option>
                        <option value="owned">Il detin</option>
                    </select>
                </div>
            </div>
            <div class="form-group" style="margin-bottom:20px">
                <label class="form-label">Note (optional)</label>
                <input type="text" name="notes" class="form-input" maxlength="500">
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-ghost" onclick="closeModal('addMonitorModal')">Anuleaza</button>
                <button type="submit" class="btn btn-primary">Adauga</button>
            </div>
        </form>
    </div>
</div>

<script>
// ============================================================
// GROQ DEBUG
// ============================================================
async function debugGroq() {
    const out = document.getElementById('groqDebugOut');
    out.style.display = '';
    out.textContent = 'Se testeaza conexiunea Groq...';
    try {
        const fd = new FormData();
        fd.append('action', 'debug_groq');
        const r    = await fetch('/finder', {method:'POST', body:fd});
        const data = await r.json();
        out.textContent = JSON.stringify(data, null, 2);
    } catch(e) {
        out.textContent = 'Eroare fetch: ' + e.message;
    }
}

// ============================================================
// MODE SWITCHING
// ============================================================
function setMode(mode, btn) {
    document.querySelectorAll('.finder-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('pasteMode').style.display   = mode === 'paste'  ? '' : 'none';
}

// ============================================================
// EXCEL PASTE PARSING
// ============================================================
function doParse() {
    const text = document.getElementById('pasteInput').value.trim();
    if (!text) return;
    handlePaste(text);
}

// Auto-parse on paste event
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('pasteInput').addEventListener('paste', function() {
        setTimeout(() => handlePaste(this.value), 60);
    });
});

function handlePaste(text) {
    text = text.trim();
    if (!text) return;

    const cols = text.split('\t');
    if (cols.length < 5) {
        alert('Nu s-au detectat suficiente coloane separate prin tab. Copiaza direct din Excel.');
        return;
    }

    // Detecteaza daca prima coloana e ID numeric si sare peste ea
    let offset = 0;
    if (/^\d+$/.test(cols[0].trim())) offset = 1;

    const get = (i) => (cols[offset + i] || '').trim();

    const lang = get(0).toUpperCase();
    document.getElementById('fLanguage').value = ['RO','EN'].includes(lang) ? lang : 'RO';
    document.getElementById('fNiche').value        = get(1);
    document.getElementById('fSiteType').value     = get(2);
    document.getElementById('fBrandName').value    = get(3);
    document.getElementById('fPositioning').value  = get(4);
    document.getElementById('fArticles').value     = get(5);

    document.getElementById('fDomain1').value = cleanDomain(get(6));
    document.getElementById('fDomain2').value = cleanDomain(get(7));
    document.getElementById('fDomain3').value = cleanDomain(get(8));
    document.getElementById('fDomain4').value = cleanDomain(get(9));
    document.getElementById('fDomain5').value = cleanDomain(get(10));

    document.getElementById('pasteOk').style.display = '';
    // Scroll to form
    document.getElementById('manualForm').scrollIntoView({behavior:'smooth', block:'nearest'});
}

function cleanDomain(s) {
    return s.trim().toLowerCase()
        .replace(/^(https?:\/\/)?(www\.)?/, '')
        .replace(/\/$/, '');
}

// ============================================================
// FORM HELPERS
// ============================================================
function getBrief() {
    return {
        language:    document.getElementById('fLanguage').value,
        niche:       document.getElementById('fNiche').value.trim(),
        site_type:   document.getElementById('fSiteType').value.trim(),
        brand_name:  document.getElementById('fBrandName').value.trim(),
        positioning: document.getElementById('fPositioning').value.trim(),
        articles:    document.getElementById('fArticles').value.trim(),
        domains:     [1,2,3,4,5]
            .map(i => cleanDomain(document.getElementById('fDomain'+i).value))
            .filter(d => d.length > 0),
    };
}

function clearForm() {
    ['fNiche','fSiteType','fBrandName','fPositioning','fArticles',
     'fDomain1','fDomain2','fDomain3','fDomain4','fDomain5']
        .forEach(id => document.getElementById(id).value = '');
    document.getElementById('fLanguage').value = 'RO';
    document.getElementById('pasteInput').value = '';
    document.getElementById('pasteOk').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'none';
}

// ============================================================
// MAIN ANALYZE
// ============================================================
async function analyzeBrief() {
    const brief = getBrief();

    if (!brief.brand_name && !brief.niche) {
        alert('Completeaza minim Nisa si Numele Brandului.');
        return;
    }
    const btn = document.getElementById('analyzeBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-sm"></span> Se analizeaza...';

    const rs = document.getElementById('resultsSection');
    rs.style.display = '';
    rs.innerHTML = buildSkeleton(brief);
    rs.scrollIntoView({behavior:'smooth', block:'start'});

    // Salveaza brief-ul pentru "Sugereaza inca 20"
    _lastBrief = brief;

    // Lanseaza Groq AI in paralel (nu asteapta — ruleaza concurent cu WHOIS)
    generateBriefSuggestions(brief);

    // Verifica fiecare domeniu SECVENTIAL cu 1200ms intre cereri (rate-limit WHOIS)
    for (let i = 0; i < brief.domains.length; i++) {
        await checkCandidate(brief, brief.domains[i], i);
        if (i < brief.domains.length - 1) await sleep(1200);
    }

    btn.disabled = false;
    btn.innerHTML = '&#128270; Analizeaza Brief-ul';
}

function buildSkeleton(brief) {
    const briefSummary = [
        brief.language && `<span class="badge registered" style="font-size:.72rem">${escHtml(brief.language)}</span>`,
        brief.niche    && `<span style="color:var(--text2);font-size:.82rem">${escHtml(brief.niche)}</span>`,
        brief.site_type && `<span style="color:var(--text3);font-size:.78rem">${escHtml(brief.site_type)}</span>`,
        brief.brand_name && `<strong style="color:var(--text)">${escHtml(brief.brand_name)}</strong>`,
    ].filter(Boolean).join(' &nbsp;·&nbsp; ');

    let slots = '';
    brief.domains.forEach((d, i) => {
        slots += `<div class="candidate-slot" id="cslot_${i}">
            <div class="crow-main">
                <span class="cslot-domain">${escHtml(d)}</span>
                <div class="cslot-status" id="cstatus_${i}">
                    <span class="spinner-sm" style="width:10px;height:10px;border-width:1.5px"></span>
                    <span style="color:var(--text3);font-size:.78rem;margin-left:4px">Se verifica...</span>
                </div>
            </div>
            <div id="calt_${i}"></div>
        </div>`;
    });

    const candidateSection = slots
        ? `<div style="margin-bottom:20px">
               <div style="font-size:.75rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.4px;margin-bottom:8px">Domenii candidate</div>
               <div class="candidate-list">${slots}</div>
           </div>`
        : '';

    return `<div class="results-header">
        <div>
            <h3>&#128202; Rezultate</h3>
            <div style="margin-top:4px;display:flex;align-items:center;gap:6px;flex-wrap:wrap">${briefSummary}</div>
        </div>
    </div>
    ${candidateSection}
    <div id="bsSuggestSection">
        <div class="brief-suggest-section">
            <div class="brief-suggest-header">
                <div class="brief-suggest-title">&#10022; Groq AI &mdash; Sugestii domenii</div>
                <div class="brief-suggest-progress">
                    <span class="spinner-sm" style="width:9px;height:9px;border-width:1.5px"></span>
                    <span style="font-size:.75rem;color:var(--text3);margin-left:4px">Se genereaza cu Groq AI...</span>
                </div>
            </div>
        </div>
    </div>
`;
}

// ============================================================
// CHECK CANDIDATE DOMAIN
// ============================================================
async function checkCandidate(brief, domain, idx) {
    const slotEl   = document.getElementById(`cslot_${idx}`);
    const statusEl = document.getElementById(`cstatus_${idx}`);
    const altEl    = document.getElementById(`calt_${idx}`);
    if (!statusEl) return;

    try {
        const fd = new FormData();
        fd.append('action', 'check_candidate');
        fd.append('domain', domain);
        const data = await (await fetch('/finder', {method:'POST', body:fd})).json();

        if (data.error) {
            statusEl.innerHTML = `<span class="badge error" style="font-size:.72rem">${escHtml(data.error)}</span>`;
            return;
        }

        const st   = data.status || 'unknown';
        const dot  = `<span class="status-dot" style="background:${statusColor(st)}"></span>`;
        const lbl  = statusLabel(st);

        if (st === 'available') {
            slotEl.classList.add('slot-available');
            statusEl.innerHTML = `<span class="badge available" style="font-size:.72rem;padding:3px 8px">${dot}Disponibil</span>
                &nbsp;
                <a href="https://portal.chroot.ro/cart.php?a=add&domain=register&query=${encodeURIComponent(domain)}" target="_blank" class="btn btn-success btn-sm" style="font-size:.75rem">&#128722; Cumpara</a>
                <button class="btn btn-ghost btn-sm" style="font-size:.75rem" onclick="openAddMonitor('${escJs(domain)}')">+ Monitor</button>
                <button class="btn btn-ghost btn-sm" style="font-size:.75rem;color:var(--purple)" onclick="triggerAltFromAvailable('${escJs(domain)}',${idx})">&#10024; Alternative</button>`;

        } else if (st === 'registered' || st === 'pending_delete') {
            slotEl.classList.add('slot-taken');
            const regInfo = data.registrar
                ? `<div style="color:var(--text3);font-size:.72rem;margin-top:3px">${escHtml(data.registrar)}</div>` : '';
            statusEl.innerHTML = `<span class="badge ${st}" style="font-size:.72rem;padding:3px 8px">${dot}${lbl}</span>${regInfo}`;

            // Genereaza automat alternative
            altEl.innerHTML = `<div style="margin-top:12px;font-size:.75rem;color:var(--text3)">
                <span class="spinner-sm" style="width:9px;height:9px;border-width:1.5px"></span> Generez alternative relevante...
            </div>`;
            await generateAlternatives(brief, domain, altEl);

        } else if (st === 'pending_delete') {
            slotEl.classList.add('slot-pending');
            statusEl.innerHTML = `<span class="badge pending_delete" style="font-size:.72rem;padding:3px 8px">${dot}${lbl}</span>`;

        } else {
            statusEl.innerHTML = `<span class="badge ${st}" style="font-size:.72rem;padding:3px 8px">${dot}${lbl}</span>`;
            if (data.already_in) {
                statusEl.innerHTML += `<div style="font-size:.72rem;color:var(--success);margin-top:4px">&#10003; Deja monitorizat</div>`;
            }
        }

    } catch(e) {
        if (statusEl) statusEl.innerHTML = `<span style="color:var(--text3);font-size:.78rem">Eroare la verificare</span>`;
    }
}

// ============================================================
// GENERATE ALTERNATIVE SEEDS
// ============================================================
function buildAltSeeds(brief, failedDomain) {
    const lang = brief.language;
    const tld  = lang === 'RO' ? 'ro' : 'com';
    const tld2 = lang === 'RO' ? 'com' : 'io';
    const seeds = [];

    // Round 1: original failed domain
    seeds.push({ type: 'algo', seed: failedDomain, label: 'Runda 1 — variante algoritmice' });

    // Round 2: niche keyword as seed
    const nicheBase = (brief.niche || '').toLowerCase()
        .replace(/[^a-z0-9\s]/g, '').split(/\s+/)
        .find(w => w.length >= 4 && w !== failedDomain.split('.')[0]);

    if (nicheBase) {
        seeds.push({ type: 'algo', seed: nicheBase + '.' + tld, label: 'Runda 2 — seed din nisa' });
    }


    return seeds;
}

// ============================================================
// GLOBAL DEDUP — track all domains shown across all cards + AI
// ============================================================
const _seenAltDomains = new Set(); // all alt domains shown in any card (cross-card dedup)
let _lastBrief = null; // retine brief-ul curent pentru "Mai mult"

// ============================================================
// GENERATE ALTERNATIVES — algo-only per card; dedup via PHP excluded_domains
// ============================================================
async function generateAlternatives(brief, failedDomain, container) {
    const fd = new FormData();
    fd.append('action', 'find_alternatives');
    fd.append('failed_domain', failedDomain);
    ['language','niche','site_type','brand_name','positioning','articles']
        .forEach(k => fd.append(k, brief[k] || ''));

    // Pass all domains already shown in other cards → PHP skips them
    const excl = [..._seenAltDomains].join(',');
    if (excl) fd.append('excluded_domains', excl);

    let algoItems = [];
    try {
        const r = await fetch('/finder', {method:'POST', body:fd});
        algoItems = await r.json();
        if (!Array.isArray(algoItems)) algoItems = [];
    } catch(e) { algoItems = []; }

    // Track for next card's exclusion
    algoItems.forEach(x => { if (x.domain) _seenAltDomains.add(x.domain); });

    if (algoItems.length === 0) {
        container.innerHTML = `<div style="margin-top:12px;font-size:.8rem;color:var(--text3)">
            Nu s-au putut genera alternative. Completeaza mai multe campuri in brief.
        </div>`;
        return;
    }

    container.innerHTML = renderAltTable(algoItems, failedDomain);

    // Auto-check availability for all alternatives
    setTimeout(() => {
        const checkBtn = container.querySelector('button[onclick*="checkAllAlts"]');
        if (checkBtn) checkBtn.click();
    }, 300);
}

// ============================================================
// RENDER ALTERNATIVES TABLE
// ============================================================
function renderAltTable(items, failedDomain) {
    if (!items || items.length === 0) return '';

    const safeKey = (failedDomain || 'br').replace(/[^a-z0-9]/g,'') + '_' + Date.now();

    let rows = '';
    items.forEach((item, idx) => {
        const isAi = (item.reason || '').startsWith('✦ AI');
        const scoreColor = item.score >= 75 ? 'var(--success)' : item.score >= 55 ? '#f59e0b' : 'var(--danger)';
        rows += `<tr id="altrow_${safeKey}_${idx}">
            <td>
                <span class="mono" style="font-weight:600">${escHtml(item.domain)}</span>
                ${isAi ? '<span style="font-size:.62rem;color:var(--purple);font-weight:700;margin-left:4px;vertical-align:middle">AI</span>' : ''}
            </td>
            <td id="altav_${safeKey}_${idx}">
                <span style="color:var(--text3);font-size:.75rem">—</span>
            </td>
            <td>
                <div style="display:flex;align-items:center;gap:5px">
                    <div style="width:${Math.round(item.score*0.7)}px;max-width:70px;min-width:4px;height:4px;background:${scoreColor};border-radius:2px;flex-shrink:0"></div>
                    <span style="font-size:.72rem;color:var(--text3)">${item.score}</span>
                </div>
            </td>
            <td style="font-size:.72rem;color:var(--text3);max-width:200px">${escHtml((item.reason||'').replace(/^✦ AI: /,''))}</td>
            <td>
                <button class="btn btn-ghost btn-sm btn-icon"
                    onclick="checkAltOne(this,'${escJs(item.domain)}','${escJs(failedDomain||'')}',${idx},'${safeKey}')"
                    title="Verifica disponibilitate">&#128270;</button>
            </td>
        </tr>`;
    });

    return `<div class="alt-section" style="margin-top:14px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <div style="font-size:.78rem;font-weight:600;color:var(--text2)">${items.length} alternative</div>
            <button class="btn btn-ghost btn-sm" style="font-size:.75rem"
                onclick="checkAllAlts(this,'${escJs(failedDomain||'')}',${items.length},'${safeKey}')">
                &#128270; Verifica toate
            </button>
        </div>
        <div class="table-wrap">
            <table style="font-size:.82rem">
                <thead><tr>
                    <th>Domeniu</th><th>Disponibil</th><th>Scor</th><th>Motiv</th><th></th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    </div>`;
}

// ============================================================
// CHECK ALL ALTERNATIVES — secvential cu 1200ms intre cereri
// ============================================================
async function checkAllAlts(btn, failedDomain, count, safeKey) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-sm" style="width:10px;height:10px;border-width:1.5px"></span> Se verifica...';

    for (let i = 0; i < count; i++) {
        const row = document.getElementById(`altrow_${safeKey}_${i}`);
        if (!row) continue;
        const domEl = row.querySelector('td:first-child .mono');
        if (!domEl) continue;
        const domain = domEl.textContent.trim();
        await checkAltOneSilent(domain, failedDomain, i, safeKey);
        if (i < count - 1) await sleep(1200);
    }

    btn.disabled = false;
    btn.innerHTML = '&#128270; Verifica toate';
}

// ============================================================
// CHECK SINGLE ALTERNATIVE
// ============================================================
async function checkAltOne(btn, domain, failedDomain, idx, safeKey) {
    btn.disabled = true;
    const avEl = document.getElementById(`altav_${safeKey}_${idx}`);
    if (avEl) avEl.innerHTML = `<span class="spinner-sm" style="width:9px;height:9px;border-width:1.5px"></span>`;
    await checkAltOneSilent(domain, failedDomain, idx, safeKey);
    btn.disabled = false;
}

async function checkAltOneSilent(domain, failedDomain, idx, safeKey) {
    const avEl = document.getElementById(`altav_${safeKey}_${idx}`);
    if (!avEl) return;
    try {
        const fd = new FormData();
        fd.append('action', 'batch_check');
        fd.append('domain', domain);
        const data = await (await fetch('/finder', {method:'POST', body:fd})).json();
        const st   = data.status || 'unknown';
        if (st === 'available') {
            avEl.innerHTML = `<span class="badge available" style="font-size:.68rem;padding:2px 7px">&#10003; Disponibil</span>
                <a href="https://portal.chroot.ro/cart.php?a=add&domain=register&query=${encodeURIComponent(domain)}"
                   target="_blank" class="btn btn-success btn-sm"
                   style="margin-left:6px;padding:2px 8px;font-size:.7rem">&#128722;</a>`;
        } else {
            avEl.innerHTML = `<span class="badge ${st}" style="font-size:.68rem;padding:2px 7px">${statusLabel(st)}</span>`;
        }
    } catch(e) {
        if (avEl) avEl.innerHTML = `<span style="color:var(--text3);font-size:.72rem">Eroare</span>`;
    }
}

// ============================================================
// GROQ AI — BRIEF SUGGESTIONS
// ============================================================
function renderBsCards(items) {
    let cards = '';
    items.forEach(item => {
        const safeId = 'bscard_' + item.domain.replace(/[^a-z0-9]/g,'_');
        cards += `<div class="bs-card bs-pending" id="${safeId}">
            <div class="bs-card-domain">${escHtml(item.domain)}</div>
            <div style="font-size:.72rem;color:var(--text3);margin-bottom:6px">${escHtml((item.reason||'').replace(/^✦ AI: /,''))}</div>
            <div class="bs-card-actions">
                <button class="btn btn-ghost btn-sm" style="font-size:.72rem"
                    onclick="checkBsCard(this,'${escJs(item.domain)}')">&#128270; Verifica</button>
            </div>
        </div>`;
    });
    return cards;
}

async function generateBriefSuggestions(brief) {
    const sec = document.getElementById('bsSuggestSection');
    if (!sec) return;

    const fd = new FormData();
    fd.append('action', 'find_alternatives_ai');
    ['language','niche','site_type','brand_name','positioning','articles']
        .forEach(k => fd.append(k, brief[k] || ''));
    const excl = [..._seenAltDomains].join(',');
    if (excl) fd.append('excluded_domains', excl);

    let items = [];
    try {
        const r = await fetch('/finder', {method:'POST', body:fd});
        items = await r.json();
        if (!Array.isArray(items)) items = [];
    } catch(e) { items = []; }

    items.forEach(x => { if (x.domain) _seenAltDomains.add(x.domain); });

    if (items.length === 0) {
        sec.innerHTML = `<div class="brief-suggest-section">
            <div class="brief-suggest-header">
                <div class="brief-suggest-title">&#10022; Groq AI &mdash; Sugestii domenii</div>
            </div>
            <div style="padding:18px;color:var(--text3);font-size:.84rem">Groq nu a returnat sugestii. Completeaza mai multe campuri in brief.</div>
        </div>`;
        return;
    }

    const domainsJson = escHtml(JSON.stringify(items.map(i => i.domain)));
    sec.innerHTML = `<div class="brief-suggest-section">
        <div class="brief-suggest-header">
            <div class="brief-suggest-title">&#10022; Groq AI &mdash; <span id="bsCount">${items.length}</span> sugestii</div>
            <div style="display:flex;gap:8px;align-items:center">
                <button class="btn btn-ghost btn-sm" style="font-size:.75rem"
                    data-domains="${domainsJson}"
                    onclick="checkAllBsCards(this)">&#128270; Verifica toate</button>
                <button class="btn btn-ghost btn-sm" style="font-size:.75rem;color:var(--purple)"
                    id="moreGroqBtn" onclick="requestMoreGroq(this)">&#10022; Sugereaza inca 20</button>
            </div>
        </div>
        <div class="bs-found-grid" id="bsGrid">${renderBsCards(items)}</div>
    </div>`;
}

async function requestMoreGroq(btn) {
    if (!_lastBrief) return;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-sm" style="width:9px;height:9px;border-width:1.5px"></span> Se genereaza...';

    const fd = new FormData();
    fd.append('action', 'find_alternatives_ai');
    ['language','niche','site_type','brand_name','positioning','articles']
        .forEach(k => fd.append(k, _lastBrief[k] || ''));
    const excl = [..._seenAltDomains].join(',');
    if (excl) fd.append('excluded_domains', excl);

    let items = [];
    try {
        const r = await fetch('/finder', {method:'POST', body:fd});
        items = await r.json();
        if (!Array.isArray(items)) items = [];
    } catch(e) { items = []; }

    items.forEach(x => { if (x.domain) _seenAltDomains.add(x.domain); });

    const grid = document.getElementById('bsGrid');
    if (grid && items.length > 0) {
        grid.insertAdjacentHTML('beforeend', renderBsCards(items));
        // Actualizeaza counter
        const counter = document.getElementById('bsCount');
        if (counter) counter.textContent = grid.querySelectorAll('.bs-card').length;
        // Actualizeaza "Verifica toate" cu noile domenii
        const verBtn = document.querySelector('[data-domains]');
        if (verBtn) {
            const existing = JSON.parse(verBtn.dataset.domains || '[]');
            verBtn.dataset.domains = JSON.stringify([...existing, ...items.map(i => i.domain)]);
        }
    }

    btn.disabled = false;
    btn.innerHTML = '&#10022; Sugereaza inca 20';
}

async function checkBsCard(btn, domain) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-sm" style="width:9px;height:9px;border-width:1.5px"></span>';
    try {
        const fd = new FormData();
        fd.append('action', 'batch_check');
        fd.append('domain', domain);
        const data = await (await fetch('/finder', {method:'POST', body:fd})).json();
        const safeId = 'bscard_' + domain.replace(/[^a-z0-9]/g,'_');
        const card = document.getElementById(safeId);
        if (!card) return;
        const st = data.status || 'unknown';
        if (st === 'available') {
            card.classList.remove('bs-pending');
            card.querySelector('.bs-card-actions').innerHTML =
                `<span class="badge available" style="font-size:.7rem;padding:2px 8px">&#10003; Disponibil</span>
                <a href="https://portal.chroot.ro/cart.php?a=add&domain=register&query=${encodeURIComponent(domain)}"
                   target="_blank" class="btn btn-success btn-sm" style="font-size:.72rem">&#128722; Cumpara</a>
                <button class="btn btn-ghost btn-sm" style="font-size:.72rem" onclick="openAddMonitor('${escJs(domain)}')">+ Monitor</button>`;
        } else {
            card.querySelector('.bs-card-actions').innerHTML =
                `<span class="badge ${st}" style="font-size:.7rem;padding:2px 8px">${statusLabel(st)}</span>`;
        }
    } catch(e) {
        if (btn.parentNode) { btn.disabled = false; btn.innerHTML = '&#128270; Verifica'; }
    }
}

async function checkAllBsCards(btn) {
    const domains = JSON.parse(btn.dataset.domains || '[]');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-sm" style="width:10px;height:10px;border-width:1.5px"></span> Se verifica...';
    for (let i = 0; i < domains.length; i++) {
        const safeId = 'bscard_' + domains[i].replace(/[^a-z0-9]/g,'_');
        const card = document.getElementById(safeId);
        if (!card) continue;
        const checkBtn = card.querySelector('.bs-card-actions button');
        if (checkBtn && !checkBtn.disabled) await checkBsCard(checkBtn, domains[i]);
        if (i < domains.length - 1) await sleep(1200);
    }
    btn.disabled = false;
    btn.innerHTML = '&#128270; Verifica toate';
}

// ============================================================
// TRIGGER ALTERNATIVES FROM AN AVAILABLE DOMAIN (extra)
// ============================================================
async function triggerAltFromAvailable(domain, idx) {
    const brief = getBrief();
    const altEl = document.getElementById(`calt_${idx}`);
    if (!altEl) return;
    altEl.innerHTML = `<div style="margin-top:12px;font-size:.75rem;color:var(--text3);display:flex;gap:6px;align-items:center">
        <span class="spinner-sm" style="width:9px;height:9px;border-width:1.5px"></span> Generez alternative...
    </div>`;
    await generateAlternatives(brief, domain, altEl);
}

// ============================================================
// HELPERS
// ============================================================
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function statusColor(st) {
    const m = {available:'#10b981',registered:'#3b82f6',pending_delete:'#f59e0b',error:'#ef4444'};
    return m[st] || '#64748b';
}

function statusLabel(st) {
    const m = {available:'Disponibil',registered:'Inregistrat',pending_delete:'Pending Delete',error:'Eroare',unknown:'Necunoscut'};
    return m[st] || st;
}

function escHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function escJs(s) {
    if (!s) return '';
    return String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'");
}

function openAddMonitor(domain) {
    document.getElementById('monitorDomain').textContent = domain;
    document.getElementById('monitorDomainInput').value  = domain;
    document.getElementById('addMonitorModal').classList.add('open');
}

function closeModal(id) {
    document.getElementById(id).classList.remove('open');
}

document.querySelectorAll('.modal-overlay').forEach(el => {
    el.addEventListener('click', function(e) { if(e.target===this) this.classList.remove('open'); });
});
</script>

<?php include 'includes/footer.php'; ?>