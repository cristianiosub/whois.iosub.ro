<?php
require_once 'config.php';
require_once 'includes/auth.php';
require_once 'includes/db.php';
requireLogin();

$db = getDB();

// Filtrare dupa numele domeniului (nu ID) - previne expunerea ID-urilor in URL
$domainSlug  = trim($_GET['domain'] ?? '');
// Suport backward-compat: ?domain_id= redirectioneaza catre ?domain=
if (empty($domainSlug) && isset($_GET['domain_id'])) {
    $tmpId = (int)$_GET['domain_id'];
    if ($tmpId > 0) {
        $r = $db->prepare("SELECT domain FROM domains WHERE id=?");
        $r->execute([$tmpId]);
        $found = $r->fetchColumn();
        if ($found) {
            header('Location: /history?domain=' . urlencode($found), true, 301);
            exit;
        }
    }
}

$search      = trim($_GET['q'] ?? '');
$dateFrom    = $_GET['date_from'] ?? '';
$dateTo      = $_GET['date_to']   ?? '';
$changesOnly = isset($_GET['changes_only']);

$domainInfo = null;
$domainId   = 0;
if ($domainSlug !== '') {
    $s = $db->prepare("SELECT * FROM domains WHERE domain=?");
    $s->execute([$domainSlug]);
    $domainInfo = $s->fetch() ?: null;
    if ($domainInfo) $domainId = (int)$domainInfo['id'];
}

$where  = '1=1';
$params = [];
if ($domainId > 0) { $where .= ' AND h.domain_id = ?';         $params[] = $domainId; }
if ($search)       { $where .= ' AND d.domain LIKE ?';          $params[] = "%$search%"; }
if ($dateFrom)     { $where .= ' AND DATE(h.checked_at) >= ?';  $params[] = $dateFrom; }
if ($dateTo)       { $where .= ' AND DATE(h.checked_at) <= ?';  $params[] = $dateTo; }

if ($changesOnly) {
    $where .= " AND h.id IN (
        SELECT id FROM (
            SELECT h2.id, h2.domain_id, h2.status,
                   LAG(h2.status) OVER (PARTITION BY h2.domain_id ORDER BY h2.checked_at) as prev_status
            FROM domain_history h2
        ) t WHERE t.prev_status IS NULL OR t.prev_status != t.status
    )";
}

$stmt = $db->prepare("
    SELECT h.*, d.domain
    FROM domain_history h
    JOIN domains d ON d.id = h.domain_id
    WHERE $where
    ORDER BY h.checked_at DESC
    LIMIT 500
");
$stmt->execute($params);
$history = $stmt->fetchAll();

$timeline = [];
if ($domainId > 0) {
    $ts = $db->prepare("SELECT status, checked_at FROM domain_history WHERE domain_id=? ORDER BY checked_at ASC");
    $ts->execute([$domainId]);
    $timeline = $ts->fetchAll();
}

$pageTitle = 'Istoric Stari';
include 'includes/header.php';
?>

<div class="page-header">
    <h1>Istoric Stari Domenii</h1>
    <p>
        <?php if ($domainInfo): ?>
            Istoricul complet pentru <strong><?= htmlspecialchars($domainInfo['domain']) ?></strong>
            &mdash; <a href="history.php" style="color:var(--accent)">Toate domeniile</a>
        <?php else: ?>
            Toate verificarile inregistrate
        <?php endif; ?>
    </p>
</div>

<div class="card mb-4">
    <form method="get" class="flex gap-2 items-center" style="flex-wrap:wrap">
        <?php if ($domainId): ?><input type="hidden" name="domain_id" value="<?= $domainId ?>"><?php endif; ?>
        <input type="text" name="q" class="form-input" placeholder="Cauta domeniu..." value="<?= htmlspecialchars($search) ?>" style="max-width:200px">
        <input type="date" name="date_from" class="form-input" value="<?= htmlspecialchars($dateFrom) ?>" style="max-width:155px">
        <span style="color:var(--text2)">-</span>
        <input type="date" name="date_to" class="form-input" value="<?= htmlspecialchars($dateTo) ?>" style="max-width:155px">
        <label class="flex items-center gap-2 text-sm" style="cursor:pointer;color:var(--text2)">
            <input type="checkbox" name="changes_only" <?= $changesOnly?'checked':'' ?> style="width:auto"> Doar schimbari de status
        </label>
        <button type="submit" class="btn btn-ghost btn-sm">Filtreaza</button>
        <a href="history.php" class="btn btn-ghost btn-sm">Reset</a>
    </form>
</div>

<?php if ($domainId && !empty($timeline) && count($timeline) > 1): ?>
<div class="card mb-4">
    <div class="card-header"><div class="card-title">Timeline Status</div></div>
    <div style="display:flex;gap:0;overflow-x:auto;padding:8px 0">
        <?php
        $prev   = null;
        $colors = ['available'=>'#10b981','registered'=>'#3b82f6','pending_delete'=>'#f59e0b','error'=>'#ef4444','unknown'=>'#64748b'];
        foreach ($timeline as $i => $t):
            $changed = ($prev && $prev['status'] !== $t['status']);
            $color   = $colors[$t['status']] ?? '#64748b';
        ?>
        <div style="flex:1;min-width:40px;position:relative" title="<?= date('d.m.Y H:i', strtotime($t['checked_at'])) ?> - <?= $t['status'] ?>">
            <div style="height:32px;background:<?= $color ?>;opacity:.8;border-right:1px solid var(--bg);<?= $changed?'border-left:2px solid white':'' ?>"></div>
            <?php if ($changed || $i === 0): ?>
            <div style="font-size:.6rem;color:var(--text2);margin-top:4px;writing-mode:vertical-rl;transform:rotate(180deg);max-height:60px;overflow:hidden">
                <?= date('d.m', strtotime($t['checked_at'])) ?>
            </div>
            <?php endif; ?>
        </div>
        <?php $prev = $t; endforeach; ?>
    </div>
    <div class="flex gap-3 mt-2" style="flex-wrap:wrap">
        <?php foreach (['available'=>'Disponibil','registered'=>'Inregistrat','pending_delete'=>'Pending Delete','error'=>'Eroare'] as $s=>$l): ?>
        <span style="font-size:.75rem;color:var(--text2)"><span style="display:inline-block;width:10px;height:10px;background:<?= $colors[$s] ?? '#888' ?>;border-radius:2px;margin-right:4px;vertical-align:middle"></span><?= $l ?></span>
        <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<div class="card">
    <div class="card-header">
        <div class="card-title"><?= count($history) ?> inregistrari</div>
    </div>
    <?php if (empty($history)): ?>
    <div class="empty-state">
        <div class="empty-icon">&#128203;</div>
        <p>Nicio inregistrare gasita.</p>
    </div>
    <?php else: ?>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Domeniu</th><th>Status</th><th>Registrar</th>
                    <th>Inregistrat la</th><th>Verificat la</th><th>WHOIS</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($history as $h): ?>
            <tr>
                <td>
                    <a href="/history?domain=<?= urlencode($h['domain']) ?>" style="color:var(--accent2)" class="domain-name">
                        <?= htmlspecialchars($h['domain']) ?>
                    </a>
                </td>
                <td><span class="badge <?= $h['status'] ?>"><?= ucfirst(str_replace('_',' ',$h['status'])) ?></span></td>
                <td class="text-sm text-muted"><?= htmlspecialchars($h['registrar'] ?? '-') ?></td>
                <td class="text-sm text-muted"><?= $h['registered_on'] ? date('d.m.Y', strtotime($h['registered_on'])) : '-' ?></td>
                <td class="text-sm text-muted"><?= date('d.m.Y H:i:s', strtotime($h['checked_at'])) ?></td>
                <td>
                    <?php if ($h['whois_snapshot']): ?>
                    <button class="btn btn-ghost btn-sm btn-icon" onclick="showWhois(this)" data-whois="<?= htmlspecialchars($h['whois_snapshot']) ?>">&#128269;</button>
                    <?php else: ?><span class="text-muted">-</span><?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<div class="modal-overlay" id="whoisModal">
    <div class="modal" style="max-width:700px">
        <div class="modal-header">
            <div class="modal-title">WHOIS Snapshot</div>
            <button class="modal-close" onclick="document.getElementById('whoisModal').classList.remove('open')">&#10005;</button>
        </div>
        <pre id="whoisContent" style="font-family:monospace;font-size:.8rem;color:var(--text2);background:var(--surface2);padding:16px;border-radius:8px;overflow:auto;max-height:400px;white-space:pre-wrap"></pre>
    </div>
</div>

<script>
function showWhois(btn) {
    document.getElementById('whoisContent').textContent = btn.getAttribute('data-whois');
    document.getElementById('whoisModal').classList.add('open');
}
document.querySelectorAll('.modal-overlay').forEach(el => {
    el.addEventListener('click', function(e) { if(e.target===this) this.classList.remove('open'); });
});
</script>

<?php include 'includes/footer.php'; ?>
