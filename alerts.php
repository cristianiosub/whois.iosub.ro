<?php
require_once 'config.php';
require_once 'includes/auth.php';
require_once 'includes/db.php';
require_once 'includes/sms.php';
requireLogin();

$db = getDB();
$flashMsg  = '';
$flashType = 'success';

// Retry SMS
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'retry_sms' && isAdmin()) {
    validateCsrf();
    $alertId = (int)($_POST['alert_id'] ?? 0);
    if ($alertId > 0) {
        $stmt = $db->prepare("SELECT * FROM sms_alerts WHERE id = ?");
        $stmt->execute([$alertId]);
        $alertRow = $stmt->fetch();
        if ($alertRow) {
            // Incearca SendSMS.ro → SMSO.ro automat
            $newId = _sendSmsWithFallback($alertRow['phone_number'], $alertRow['message']);
            if ($newId !== null) {
                $db->prepare("UPDATE sms_alerts SET sendsms_message_id = ? WHERE id = ?")
                   ->execute([$newId, $alertId]);
                if (str_starts_with($newId, 'smso:')) {
                    $token = htmlspecialchars(substr($newId, 5, 24));
                    $flashMsg = '&#10003; SMS retrimis cu succes via <strong>SMSO.ro</strong>! Token: ' . $token;
                } else {
                    $flashMsg = '&#10003; SMS retrimis cu succes via <strong>SendSMS.ro</strong>! ID: ' . htmlspecialchars(substr((string)$newId, 0, 20));
                }
                $flashType = 'success';
            } else {
                $flashMsg  = '&#10007; Retry esuat pe ambii provideri (SendSMS.ro + SMSO.ro). Verifica <strong>logs/error.log</strong>.';
                $flashType = 'danger';
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'clear_all' && isAdmin()) {
    validateCsrf();
    $db->exec("DELETE FROM sms_alerts");
    header('Location: /alerts');
    exit;
}

$alerts  = $db->query("SELECT s.*, COALESCE(d.domain, s.phone_number) AS domain FROM sms_alerts s LEFT JOIN domains d ON d.id = s.domain_id ORDER BY s.sent_at DESC LIMIT 200")->fetchAll();
$total   = $db->query("SELECT COUNT(*) FROM sms_alerts")->fetchColumn();
$today   = $db->query("SELECT COUNT(*) FROM sms_alerts WHERE DATE(sent_at)=CURDATE()")->fetchColumn();

$pageTitle = 'Alerte SMS';
include 'includes/header.php';
?>

<div class="page-header">
    <h1>Alerte SMS Trimise</h1>
    <p>Jurnal complet al notificarilor SMS via SendSMS.ro / SMSO.ro</p>
</div>

<?php if ($flashMsg): ?>
<div class="alert alert-<?= htmlspecialchars($flashType) ?>" style="margin-bottom:16px"><?= $flashMsg ?></div>
<?php endif; ?>

<div class="stats-grid">
    <div class="stat-card total">
        <div class="stat-label">Total Alerte</div>
        <div class="stat-value"><?= $total ?></div>
    </div>
    <div class="stat-card available">
        <div class="stat-label">Astazi</div>
        <div class="stat-value text-success"><?= $today ?></div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title">Ultimele 200 alerte</div>
        <?php if (isAdmin() && $total > 0): ?>
        <form method="post" onsubmit="return confirm('Stergi toate cele <?= $total ?> alerte SMS? Actiunea e ireversibila.')">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">
            <input type="hidden" name="action" value="clear_all">
            <button type="submit" class="btn btn-ghost btn-sm" style="color:var(--danger);border-color:var(--danger)">&#128465; Sterge tot</button>
        </form>
        <?php endif; ?>
    </div>
    <?php if (empty($alerts)): ?>
    <div class="empty-state">
        <div class="empty-icon">&#128237;</div>
        <p>Nicio alerta trimisa inca. Alertele se trimit automat cand un domeniu isi schimba statusul.</p>
    </div>
    <?php else: ?>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Domeniu</th><th>Schimbare Status</th><th>Telefon</th>
                    <th>ID Mesaj / Provider</th><th>Trimis la</th><th>Mesaj</th><th></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($alerts as $a): ?>
            <tr>
                <td class="domain-name"><?= htmlspecialchars($a['domain']) ?></td>
                <td>
                    <span class="badge <?= $a['old_status'] ?>" style="font-size:.7rem"><?= $a['old_status'] ?></span>
                    <span style="color:var(--text3)"> &rarr; </span>
                    <span class="badge <?= $a['new_status'] ?>" style="font-size:.7rem"><?= $a['new_status'] ?></span>
                </td>
                <td class="text-sm" style="font-family:monospace"><?= htmlspecialchars($a['phone_number']) ?></td>
                <td class="text-xs text-muted" style="font-family:monospace">
                    <?php
                    $mid = $a['sendsms_message_id'] ?? '';
                    if (!$mid): ?>
                        <span style="color:var(--danger)">Esuat</span>
                    <?php elseif (str_starts_with($mid, 'smso:')): ?>
                        <span style="background:rgba(16,185,129,.15);color:#10b981;padding:1px 6px;border-radius:4px;font-size:.7rem;font-weight:600">SMSO</span>
                        <span style="color:var(--text3)"> <?= htmlspecialchars(substr($mid, 5, 12)) ?>&hellip;</span>
                    <?php else: ?>
                        <span style="background:rgba(59,130,246,.12);color:#60a5fa;padding:1px 6px;border-radius:4px;font-size:.7rem;font-weight:600">SendSMS</span>
                        <span style="color:var(--text3)"> <?= htmlspecialchars(substr($mid, 0, 12)) ?>&hellip;</span>
                    <?php endif; ?>
                </td>
                <td class="text-sm text-muted"><?= date('d.m.Y H:i:s', strtotime($a['sent_at'])) ?></td>
                <td>
                    <button class="btn btn-ghost btn-sm btn-icon" onclick="toggleMsg('msg_<?= $a['id'] ?>')" title="Previzualizeaza mesaj">&#128172;</button>
                    <pre id="msg_<?= $a['id'] ?>" style="display:none;font-size:.75rem;color:var(--text2);margin-top:8px;white-space:pre-wrap;background:var(--surface2);padding:8px;border-radius:6px"><?= htmlspecialchars($a['message']) ?></pre>
                </td>
                <td style="white-space:nowrap">
                <?php if (!$a['sendsms_message_id'] && isAdmin()): ?>
                <form method="post" style="display:inline" onsubmit="return confirm('Retrimiti acest SMS?')">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">
                    <input type="hidden" name="action" value="retry_sms">
                    <input type="hidden" name="alert_id" value="<?= (int)$a['id'] ?>">
                    <button type="submit" class="btn btn-ghost btn-sm" style="color:var(--warning,#f59e0b);border-color:var(--warning,#f59e0b)" title="Retrimite SMS">&#8635; Retry</button>
                </form>
                <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<script>
function toggleMsg(id) {
    var el = document.getElementById(id);
    el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
</script>

<?php include 'includes/footer.php'; ?>
