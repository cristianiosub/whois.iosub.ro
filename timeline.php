<?php
require_once 'config.php';
require_once 'includes/auth.php';
require_once 'includes/db.php';
requireLogin();

$db        = getDB();
$pageTitle = 'Timeline';
$domainFilter = trim($_GET['domain'] ?? '');

// Suport backward-compat: ?domain_id= redirectioneaza catre ?domain=
if (empty($domainFilter) && isset($_GET['domain_id'])) {
    $tmpId = (int)$_GET['domain_id'];
    if ($tmpId > 0) {
        $r = $db->prepare("SELECT domain FROM domains WHERE id=?");
        $r->execute([$tmpId]);
        $found = $r->fetchColumn();
        if ($found) {
            header('Location: /timeline?domain=' . urlencode($found), true, 301);
            exit;
        }
    }
}

$domainId = 0;
if ($domainFilter !== '') {
    $r = $db->prepare("SELECT id FROM domains WHERE domain = ?");
    $r->execute([$domainFilter]);
    $found = $r->fetchColumn();
    if ($found) $domainId = (int)$found;
}

// Toate domeniile pentru selectorul din header
$allDomains = $db->query("SELECT id, domain, domain_type, current_status FROM domains ORDER BY domain")->fetchAll();

// Daca avem un domeniu selectat, incarcam toate evenimentele
$events   = [];
$domInfo  = null;

if ($domainId > 0) {
    $stmt = $db->prepare("SELECT * FROM domains WHERE id=?");
    $stmt->execute([$domainId]);
    $domInfo = $stmt->fetch() ?: null;

    if ($domInfo) {
        // 1. Adaugare in sistem
        $events[] = [
            'ts'    => strtotime($domInfo['added_at']),
            'date'  => $domInfo['added_at'],
            'type'  => 'added',
            'icon'  => '➕',
            'color' => '#3b82f6',
            'title' => 'Adaugat in DomainWatch',
            'desc'  => 'Domeniu adaugat in sistem pentru monitorizare.',
        ];

        // 2. Schimbari status din domain_history
        $hist = $db->prepare("SELECT * FROM domain_history WHERE domain_id=? ORDER BY checked_at ASC");
        $hist->execute([$domainId]);
        $prevStatus = null;
        foreach ($hist->fetchAll() as $h) {
            if ($h['status'] !== $prevStatus) {
                $typeMap = [
                    'available'     => ['icon' => '✅', 'color' => '#10b981', 'title' => 'Status: Disponibil'],
                    'registered'    => ['icon' => '🔵', 'color' => '#3b82f6', 'title' => 'Status: Inregistrat'],
                    'pending_delete'=> ['icon' => '⚠️', 'color' => '#f59e0b', 'title' => 'Status: Pending Delete'],
                    'error'         => ['icon' => '❌', 'color' => '#ef4444', 'title' => 'Eroare verificare'],
                ];
                $tm = $typeMap[$h['status']] ?? ['icon' => '❓', 'color' => '#64748b', 'title' => 'Status: ' . $h['status']];
                $desc = $prevStatus ? "Schimbare: {$prevStatus} → {$h['status']}" : "Status initial detectat: {$h['status']}";
                if ($h['registrar']) $desc .= " · Registrar: {$h['registrar']}";
                $events[] = [
                    'ts'    => strtotime($h['checked_at']),
                    'date'  => $h['checked_at'],
                    'type'  => 'status_' . $h['status'],
                    'icon'  => $tm['icon'],
                    'color' => $tm['color'],
                    'title' => $tm['title'],
                    'desc'  => $desc,
                ];
                $prevStatus = $h['status'];
            }
        }

        // 3. Schimbari IP/NS din settings
        $ipKey = "domain_ip_{$domainId}";
        $nsKey = "domain_ns_{$domainId}";
        $ipRow = $db->prepare("SELECT key_value, updated_at FROM settings WHERE key_name=?");
        $ipRow->execute([$ipKey]);
        if ($ipData = $ipRow->fetch()) {
            $events[] = [
                'ts'    => strtotime($ipData['updated_at']),
                'date'  => $ipData['updated_at'],
                'type'  => 'ip',
                'icon'  => '🌐',
                'color' => '#8b5cf6',
                'title' => 'IP curent detectat',
                'desc'  => "IP: {$ipData['key_value']}",
            ];
        }
        $nsRow = $db->prepare("SELECT key_value, updated_at FROM settings WHERE key_name=?");
        $nsRow->execute([$nsKey]);
        if ($nsData = $nsRow->fetch()) {
            $events[] = [
                'ts'    => strtotime($nsData['updated_at']),
                'date'  => $nsData['updated_at'],
                'type'  => 'ns',
                'icon'  => '📡',
                'color' => '#06b6d4',
                'title' => 'Nameservere curente',
                'desc'  => "NS: " . str_replace(',', ' · ', $nsData['key_value']),
            ];
        }

        // 4. Alerte SMS trimise
        $sms = $db->prepare("SELECT * FROM sms_alerts WHERE domain_id=? ORDER BY sent_at ASC");
        $sms->execute([$domainId]);
        foreach ($sms->fetchAll() as $s) {
            $events[] = [
                'ts'    => strtotime($s['sent_at']),
                'date'  => $s['sent_at'],
                'type'  => 'sms',
                'icon'  => '📱',
                'color' => '#f59e0b',
                'title' => 'Alertă SMS trimisă',
                'desc'  => htmlspecialchars(mb_substr($s['message'] ?? "{$s['old_status']} → {$s['new_status']}", 0, 120)),
                'phone' => $s['phone_number'],
            ];
        }

        // 5. Date WHOIS (inregistrare, expirare)
        if (!empty($domInfo['expires_on'])) {
            $daysLeft = (int)floor((strtotime($domInfo['expires_on']) - time()) / 86400);
            $color = $daysLeft < 7 ? '#ef4444' : ($daysLeft < 30 ? '#f59e0b' : '#10b981');
            $events[] = [
                'ts'    => strtotime($domInfo['expires_on']),
                'date'  => $domInfo['expires_on'],
                'type'  => 'expiry',
                'icon'  => $daysLeft < 0 ? '💀' : ($daysLeft < 30 ? '⚠️' : '📅'),
                'color' => $color,
                'title' => $daysLeft < 0 ? 'Domeniu EXPIRAT' : "Expira in {$daysLeft} zile",
                'desc'  => "Data expirare: {$domInfo['expires_on']}" . ($daysLeft < 0 ? ' — EXPIRAT' : ''),
                'future'=> $daysLeft >= 0,
            ];
        }

        // Sorteaza toate evenimentele dupa timestamp
        usort($events, fn($a, $b) => $a['ts'] <=> $b['ts']);
    }
}

include 'includes/header.php';
?>

<style>
.timeline-wrap{position:relative;padding-left:40px;margin-top:8px}
.timeline-wrap::before{content:'';position:absolute;left:16px;top:0;bottom:0;width:2px;background:var(--border);border-radius:999px}
.tl-event{position:relative;margin-bottom:24px;animation:fadeUp .2s ease both}
.tl-event:last-child{margin-bottom:0}
@keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.tl-dot{position:absolute;left:-31px;width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;border:2px solid var(--bg);flex-shrink:0;top:4px}
.tl-body{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 16px;transition:.15s}
.tl-body:hover{border-color:rgba(59,130,246,.3);background:var(--surface2)}
.tl-body.future{border-style:dashed;opacity:.75}
.tl-date{font-size:.72rem;color:var(--text3);margin-bottom:3px;font-family:monospace}
.tl-title{font-weight:600;font-size:.88rem;margin-bottom:3px}
.tl-desc{font-size:.8rem;color:var(--text2);line-height:1.5}
.tl-phone{font-size:.72rem;color:var(--text3);margin-top:3px;font-family:monospace}
.year-divider{position:relative;margin:28px 0 20px -40px;display:flex;align-items:center;gap:12px}
.year-divider::after{content:'';flex:1;height:1px;background:var(--border)}
.year-label{font-size:.8rem;font-weight:700;color:var(--text3);letter-spacing:.5px;white-space:nowrap}
.domain-select-wrap{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:20px}
.domain-select{background:var(--surface);border:1.5px solid var(--border);border-radius:10px;padding:10px 14px;color:var(--text);font-size:.9rem;font-family:inherit;min-width:280px;cursor:pointer}
.domain-select:focus{outline:none;border-color:var(--accent)}
.tl-empty{text-align:center;padding:48px 20px;color:var(--text3)}
.tl-empty .icon{font-size:3rem;margin-bottom:12px}
.stat-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:12px 16px;flex:1;min-width:120px}
.stat-card .val{font-size:1.4rem;font-weight:700;line-height:1}
.stat-card .lbl{font-size:.72rem;color:var(--text3);text-transform:uppercase;letter-spacing:.4px;margin-top:4px}
</style>

<div class="page-header">
    <h1>&#128336; Timeline</h1>
    <p>Linie de timp cu toate evenimentele pentru un domeniu</p>
</div>

<!-- Selector domeniu -->
<div class="domain-select-wrap">
    <select class="domain-select" onchange="window.location.href='/timeline?domain='+encodeURIComponent(this.options[this.selectedIndex].dataset.name||'')">
        <option value="">— Selecteaza un domeniu —</option>
        <?php foreach ($allDomains as $d): ?>
        <option value="<?= htmlspecialchars($d['domain']) ?>"
                data-name="<?= htmlspecialchars($d['domain']) ?>"
                <?= ($domainFilter !== '' && $d['domain'] === $domainFilter) ? 'selected' : '' ?>>
            <?= htmlspecialchars($d['domain']) ?>
            <?= $d['current_status'] === 'available' ? ' ✅' : ($d['current_status'] === 'pending_delete' ? ' ⚠️' : '') ?>
        </option>
        <?php endforeach; ?>
    </select>
    <?php if ($domInfo): ?>
    <a href="/history?domain=<?= urlencode($domInfo['domain']) ?>" class="btn btn-ghost btn-sm">&#128203; Istoric</a>
    <a href="/lookup?domain=<?= urlencode($domInfo['domain']) ?>" class="btn btn-ghost btn-sm">&#128202; Intelligence</a>
    <?php endif; ?>
</div>

<?php if (!$domInfo && !$domainId): ?>
<!-- Empty state initial -->
<div class="card">
    <div class="tl-empty">
        <div class="icon">&#128336;</div>
        <p style="font-size:.95rem;font-weight:500;margin-bottom:8px">Selecteaza un domeniu din lista de mai sus</p>
        <p>Vei vedea o linie de timp completa cu toate evenimentele: adaugare, schimbari de status, alerte SMS, IP/NS, expirare.</p>
    </div>
</div>

<?php elseif ($domInfo): ?>

<!-- Info domeniu -->
<div class="card" style="margin-bottom:20px">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
        <div>
            <div style="font-family:monospace;font-size:1.2rem;font-weight:700"><?= htmlspecialchars($domInfo['domain']) ?></div>
            <div style="font-size:.82rem;color:var(--text2);margin-top:3px">
                Tip: <?= $domInfo['domain_type'] === 'owned' ? '&#127968; Detin' : '&#128270; Monitorizare' ?>
                &nbsp;·&nbsp; Status: <span class="badge <?= $domInfo['current_status'] ?>" style="font-size:.72rem;padding:2px 8px"><?= $domInfo['current_status'] ?></span>
                <?php if (!empty($domInfo['expires_on'])): ?>
                &nbsp;·&nbsp; Expira: <?= date('d.m.Y', strtotime($domInfo['expires_on'])) ?>
                <?php endif; ?>
            </div>
        </div>
        <div style="display:flex;gap:8px">
            <a href="/lookup?domain=<?= urlencode($domInfo['domain']) ?>" class="btn btn-ghost btn-sm">&#128202; Intelligence</a>
            <a href="/history?domain=<?= urlencode($domInfo['domain']) ?>" class="btn btn-ghost btn-sm">&#128203; Istoric complet</a>
        </div>
    </div>
</div>

<!-- Stats -->
<?php
$statusChanges = count(array_filter($events, fn($e) => str_starts_with($e['type'], 'status_')));
$smsCount      = count(array_filter($events, fn($e) => $e['type'] === 'sms'));
$totalEvents   = count($events);
$firstTs       = $events[0]['ts'] ?? time();
$daysSince     = (int)floor((time() - $firstTs) / 86400);
?>
<div class="stat-row">
    <div class="stat-card"><div class="val"><?= $totalEvents ?></div><div class="lbl">Evenimente totale</div></div>
    <div class="stat-card"><div class="val"><?= $statusChanges ?></div><div class="lbl">Schimbari status</div></div>
    <div class="stat-card"><div class="val"><?= $smsCount ?></div><div class="lbl">Alerte SMS</div></div>
    <div class="stat-card"><div class="val"><?= $daysSince ?></div><div class="lbl">Zile in sistem</div></div>
</div>

<?php if (empty($events)): ?>
<div class="card">
    <div class="tl-empty">
        <div class="icon">&#128680;</div>
        <p>Niciun eveniment inregistrat inca pentru acest domeniu.</p>
    </div>
</div>
<?php else: ?>

<div class="card">
    <div class="card-header">
        <div class="card-title">&#128336; Linie de timp — <?= count($events) ?> evenimente</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
            <span style="font-size:.72rem;color:var(--text3)">
                <?= date('d.m.Y', $events[0]['ts']) ?> →
                <?= date('d.m.Y', $events[count($events)-1]['ts']) ?>
            </span>
        </div>
    </div>
    <div style="padding:20px 24px">
        <div class="timeline-wrap">
            <?php
            $currentYear = null;
            foreach ($events as $i => $ev):
                $year = date('Y', $ev['ts']);
                if ($year !== $currentYear):
                    $currentYear = $year;
            ?>
            <div class="year-divider">
                <span class="year-label">&#9201; <?= $year ?></span>
            </div>
            <?php endif; ?>

            <div class="tl-event" style="animation-delay:<?= $i * 0.04 ?>s">
                <div class="tl-dot" style="background:<?= $ev['color'] ?>22;border-color:<?= $ev['color'] ?>">
                    <?= $ev['icon'] ?>
                </div>
                <div class="tl-body <?= !empty($ev['future']) ? 'future' : '' ?>">
                    <div class="tl-date"><?= date('d.m.Y H:i', $ev['ts']) ?><?= !empty($ev['future']) ? ' <span style="color:#f59e0b">(viitor)</span>' : '' ?></div>
                    <div class="tl-title" style="color:<?= $ev['color'] ?>"><?= $ev['icon'] ?> <?= htmlspecialchars($ev['title']) ?></div>
                    <div class="tl-desc"><?= $ev['desc'] ?></div>
                    <?php if (!empty($ev['phone'])): ?>
                    <div class="tl-phone">&#128241; <?= htmlspecialchars($ev['phone']) ?></div>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
</div>

<?php endif; ?>
<?php endif; ?>

<?php include 'includes/footer.php'; ?>
