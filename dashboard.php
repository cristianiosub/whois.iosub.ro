<?php
require_once 'config.php';
require_once 'includes/auth.php';
require_once 'includes/db.php';
requireLogin();

$pageTitle = 'Dashboard';
$db = getDB();

$stats = $db->query("
    SELECT
        COUNT(*) as total,
        SUM(current_status='available') as available,
        SUM(current_status='registered') as registered,
        SUM(current_status='pending_delete') as pending_delete,
        SUM(current_status='error') as errors,
        SUM(monitoring_active=1) as active
    FROM domains
")->fetch();

$changes = $db->query("
    SELECT h.*, d.domain
    FROM domain_history h
    JOIN domains d ON d.id = h.domain_id
    WHERE h.id IN (SELECT MAX(h2.id) FROM domain_history h2 GROUP BY h2.domain_id)
    ORDER BY h.checked_at DESC LIMIT 10
")->fetchAll();

$available = $db->query("
    SELECT d.*, h.checked_at as last_seen_at
    FROM domains d
    LEFT JOIN domain_history h ON h.id = (SELECT MAX(id) FROM domain_history WHERE domain_id=d.id)
    WHERE d.current_status = 'available'
    ORDER BY h.checked_at DESC
")->fetchAll();

$pending = $db->query("
    SELECT * FROM domains WHERE current_status = 'pending_delete' ORDER BY last_checked_at DESC
")->fetchAll();

$lastSms = $db->query("
    SELECT s.*, d.domain FROM sms_alerts s
    JOIN domains d ON d.id = s.domain_id
    ORDER BY s.sent_at DESC LIMIT 5
")->fetchAll();

include 'includes/header.php';
?>

<div class="page-header">
    <h1>Dashboard</h1>
    <p>Monitorizare domenii in timp real - actualizat la fiecare 5 minute</p>
</div>

<div class="stats-grid">
    <div class="stat-card total">
        <div class="stat-label">Total Domenii</div>
        <div class="stat-value"><?= $stats['total'] ?></div>
        <div class="stat-sub"><?= $stats['active'] ?> active</div>
    </div>
    <div class="stat-card available">
        <div class="stat-label">Disponibile</div>
        <div class="stat-value text-success"><?= $stats['available'] ?></div>
        <div class="stat-sub">Pot fi cumparate acum</div>
    </div>
    <div class="stat-card pending">
        <div class="stat-label">Pending Delete</div>
        <div class="stat-value text-warning"><?= $stats['pending_delete'] ?></div>
        <div class="stat-sub">Se elibereaza in curand</div>
    </div>
    <div class="stat-card registered">
        <div class="stat-label">Inregistrate</div>
        <div class="stat-value"><?= $stats['registered'] ?></div>
        <div class="stat-sub">Ocupate de altcineva</div>
    </div>
</div>

<?php if (!empty($available)): ?>
<div class="card mb-4" style="border-color:rgba(16,185,129,.4)">
    <div class="card-header">
        <div class="card-title text-success">Domenii Disponibile - Cumpara Acum!</div>
        <a href="/domains?filter=available" class="btn btn-success btn-sm">Vezi toate</a>
    </div>
    <div class="table-wrap">
        <table>
            <tr><th>Domeniu</th><th>Detectat la</th><th>Actiune</th></tr>
            <?php foreach ($available as $d): ?>
            <tr>
                <td>
                    <div class="domain-name"><?= htmlspecialchars($d['domain']) ?></div>
                    <?php if ($d['notes']): ?><div class="text-xs text-muted"><?= htmlspecialchars($d['notes']) ?></div><?php endif; ?>
                </td>
                <td class="text-sm text-muted"><?= $d['last_seen_at'] ? date('d.m.Y H:i', strtotime($d['last_seen_at'])) : '-' ?></td>
                <td>
                    <a href="https://portal.chroot.ro/cart.php?a=add&domain=register&query=<?= urlencode($d['domain']) ?>" target="_blank" rel="noopener noreferrer" class="btn btn-success btn-sm">Cumpara</a>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>
</div>
<?php endif; ?>

<?php if (!empty($pending)): ?>
<div class="card mb-4" style="border-color:rgba(245,158,11,.3)">
    <div class="card-header">
        <div class="card-title" style="color:var(--warning)">Pending Delete - Se Elibereaza Curand</div>
    </div>
    <div class="table-wrap">
        <table>
            <tr><th>Domeniu</th><th>Ultima verificare</th><th>Note</th></tr>
            <?php foreach ($pending as $d): ?>
            <tr>
                <td class="domain-name"><?= htmlspecialchars($d['domain']) ?></td>
                <td class="text-sm text-muted"><?= $d['last_checked_at'] ? date('d.m.Y H:i', strtotime($d['last_checked_at'])) : '-' ?></td>
                <td class="text-sm text-muted"><?= htmlspecialchars($d['notes'] ?? '') ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>
</div>
<?php endif; ?>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
<div class="card">
    <div class="card-header">
        <div class="card-title">Verificari Recente</div>
        <a href="/history" class="btn btn-ghost btn-sm">Toate</a>
    </div>
    <?php if (empty($changes)): ?>
        <div class="empty-state" style="padding:24px">
            <div>Nicio verificare inca. Adauga domenii si porneste cron-ul.</div>
        </div>
    <?php else: ?>
    <div class="table-wrap">
        <table>
            <tr><th>Domeniu</th><th>Status</th><th>La</th></tr>
            <?php foreach ($changes as $h):
                $safeStatus = in_array($h['status'], ['unknown','available','registered','pending_delete','error']) ? $h['status'] : 'unknown';
            ?>
            <tr>
                <td class="domain-name" style="font-size:.8rem"><?= htmlspecialchars($h['domain']) ?></td>
                <td><span class="badge <?= $safeStatus ?>"><?= htmlspecialchars(ucfirst(str_replace('_',' ',$safeStatus))) ?></span></td>
                <td class="text-xs text-muted"><?= date('d.m H:i', strtotime($h['checked_at'])) ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>
    <?php endif; ?>
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title">Alerte SMS Recente</div>
        <a href="/alerts" class="btn btn-ghost btn-sm">Toate</a>
    </div>
    <?php if (empty($lastSms)): ?>
        <div class="empty-state" style="padding:24px"><div>Nicio alerta trimisa inca.</div></div>
    <?php else: ?>
    <div class="table-wrap">
        <table>
            <tr><th>Domeniu</th><th>Schimbare</th><th>La</th></tr>
            <?php foreach ($lastSms as $s):
                $oldSafe = in_array($s['old_status'], ['unknown','available','registered','pending_delete','error']) ? $s['old_status'] : 'unknown';
                $newSafe = in_array($s['new_status'], ['unknown','available','registered','pending_delete','error']) ? $s['new_status'] : 'unknown';
            ?>
            <tr>
                <td class="domain-name" style="font-size:.8rem"><?= htmlspecialchars($s['domain']) ?></td>
                <td>
                    <span class="badge <?= $oldSafe ?>" style="font-size:.65rem"><?= $oldSafe ?></span>
                    &rarr; <span class="badge <?= $newSafe ?>" style="font-size:.65rem"><?= $newSafe ?></span>
                </td>
                <td class="text-xs text-muted"><?= date('d.m H:i', strtotime($s['sent_at'])) ?></td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>
    <?php endif; ?>
</div>
</div>

<?php include 'includes/footer.php'; ?>
