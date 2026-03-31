<?php
require_once 'config.php';
require_once 'includes/auth.php';
require_once 'includes/db.php';
require_once 'includes/sms.php';
require_once 'includes/uptime_check.php';
requireLogin();

$db = getDB();

// ── Creare tabele daca nu exista ────────────────────────────────────────────
$db->exec("
CREATE TABLE IF NOT EXISTS uptime_monitors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    type ENUM('http','ssl','port') NOT NULL DEFAULT 'http',
    target VARCHAR(500) NOT NULL,
    port SMALLINT UNSIGNED DEFAULT NULL,
    check_interval_minutes SMALLINT UNSIGNED NOT NULL DEFAULT 5,
    timeout_seconds TINYINT UNSIGNED NOT NULL DEFAULT 10,
    monitoring_active TINYINT(1) NOT NULL DEFAULT 1,
    added_by INT DEFAULT NULL,
    current_status ENUM('up','down','unknown') NOT NULL DEFAULT 'unknown',
    last_checked_at DATETIME DEFAULT NULL,
    last_status_change_at DATETIME DEFAULT NULL,
    ssl_expires_on DATE DEFAULT NULL,
    ssl_days_left INT DEFAULT NULL,
    ssl_issuer VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
");
$db->exec("
CREATE TABLE IF NOT EXISTS uptime_checks (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    monitor_id INT NOT NULL,
    status ENUM('up','down') NOT NULL,
    response_time_ms MEDIUMINT UNSIGNED DEFAULT NULL,
    http_code SMALLINT UNSIGNED DEFAULT NULL,
    ssl_days_left SMALLINT DEFAULT NULL,
    ssl_issuer VARCHAR(255) DEFAULT NULL,
    ssl_expires_on DATE DEFAULT NULL,
    error_message VARCHAR(500) DEFAULT NULL,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_monitor_time (monitor_id, checked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
");
$db->exec("
CREATE TABLE IF NOT EXISTS uptime_incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    monitor_id INT NOT NULL,
    started_at DATETIME NOT NULL,
    resolved_at DATETIME DEFAULT NULL,
    duration_seconds INT DEFAULT NULL,
    cause VARCHAR(255) DEFAULT NULL,
    INDEX idx_monitor (monitor_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
");

$user    = getCurrentUser();
$userId  = (int)($user['id'] ?? 0);
$isAdmin = function_exists('isAdmin') && isAdmin();
$csrfToken = getCsrfToken();

$msg = ''; $msgType = '';

// ── POST actions ─────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (empty($token) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        $msg = 'Cerere invalida.'; $msgType = 'danger';
    } else {
        $action = $_POST['action'] ?? '';

        if ($action === 'add' || $action === 'edit') {
            $name     = trim($_POST['name'] ?? '');
            $target   = trim($_POST['target'] ?? '');
            $port     = (int)($_POST['port'] ?? 0) ?: null;
            $interval = max(1, min(1440, (int)($_POST['interval'] ?? 5)));
            $timeout  = max(5, min(30, (int)($_POST['timeout'] ?? 10)));
            // Owner: admin poate alege orice user; user normal = el insusi
            $ownerInput = (int)($_POST['owner_id'] ?? 0);
            $ownerId = ($isAdmin && $ownerInput > 0) ? $ownerInput : $userId;

            if (!$name || !$target) {
                $msg = 'Completati toate campurile obligatorii.'; $msgType = 'danger';
            } else {
                if ($action === 'add') {
                    $types = array_filter((array)($_POST['types'] ?? []), fn($t) => in_array($t, ['http','ssl','port']));
                    if (empty($types)) $types = ['http'];
                    $added = 0;
                    foreach ($types as $type) {
                        $t2 = $target;
                        $p2 = $port;
                        if ($type === 'ssl') {
                            $t2 = preg_replace('#^https?://#', '', $target);
                            $t2 = rtrim(strtok($t2, '/'), '/');
                            $p2 = $p2 ?: 443;
                        }
                        $db->prepare("
                            INSERT INTO uptime_monitors (name, type, target, port, check_interval_minutes, timeout_seconds, added_by)
                            VALUES (?,?,?,?,?,?,?)
                        ")->execute([$name, $type, $t2, $p2, $interval, $timeout, $ownerId]);
                        $added++;
                    }
                    $msg = $added > 1
                        ? "<strong>" . htmlspecialchars($name) . "</strong> — $added monitoare adaugate."
                        : "Monitor <strong>" . htmlspecialchars($name) . "</strong> adaugat.";
                } else {
                    $type = in_array($_POST['type'] ?? '', ['http','ssl','port']) ? $_POST['type'] : 'http';
                    $id = (int)($_POST['id'] ?? 0);
                    $db->prepare("
                        UPDATE uptime_monitors SET name=?, type=?, target=?, port=?,
                            check_interval_minutes=?, timeout_seconds=?, added_by=? WHERE id=?
                    ")->execute([$name, $type, $target, $port, $interval, $timeout, $ownerId, $id]);
                    $msg = "Monitor actualizat.";
                }
                $msgType = 'success';
            }


        } elseif ($action === 'delete') {
            $id = (int)($_POST['id'] ?? 0);
            $db->prepare("DELETE FROM uptime_monitors WHERE id=?")->execute([$id]);
            $msg = 'Monitor sters.'; $msgType = 'success';

        } elseif ($action === 'toggle') {
            $id = (int)($_POST['id'] ?? 0);
            $db->prepare("UPDATE uptime_monitors SET monitoring_active = NOT monitoring_active WHERE id=?")->execute([$id]);
            $msg = 'Status monitorizare schimbat.'; $msgType = 'success';

        } elseif ($action === 'check') {
            $id = (int)($_POST['id'] ?? 0);
            $m  = $db->prepare("SELECT * FROM uptime_monitors WHERE id=?")->execute([$id]) ? null : null;
            $stmt = $db->prepare("SELECT * FROM uptime_monitors WHERE id=?");
            $stmt->execute([$id]);
            $m = $stmt->fetch();
            if ($m) {
                $prevStatus = $m['current_status'];
                $result     = runUptimeCheck($m);
                $newStatus  = $result['status'];
                try {
                    $db->prepare("
                        INSERT INTO uptime_checks (monitor_id, status, response_time_ms, http_code, ssl_days_left, ssl_issuer, ssl_expires_on, error_message)
                        VALUES (?,?,?,?,?,?,?,?)
                    ")->execute([$id, $newStatus, $result['response_time_ms'] ?? null, $result['http_code'] ?? null,
                        $result['ssl_days_left'] ?? null, $result['ssl_issuer'] ?? null, $result['ssl_expires_on'] ?? null, $result['error'] ?? null]);
                } catch (Exception $e) {}
                $db->prepare("UPDATE uptime_monitors SET current_status=?, last_checked_at=NOW() WHERE id=?")->execute([$newStatus, $id]);
                if (!empty($result['ssl_expires_on'])) {
                    $db->prepare("UPDATE uptime_monitors SET ssl_expires_on=?, ssl_days_left=?, ssl_issuer=? WHERE id=?")
                       ->execute([$result['ssl_expires_on'], $result['ssl_days_left'], $result['ssl_issuer'], $id]);
                }
                $badge = $newStatus === 'up' ? 'success' : 'danger';
                $ms    = isset($result['response_time_ms']) ? " &bull; {$result['response_time_ms']}ms" : '';
                $err   = !empty($result['error']) ? " &bull; " . htmlspecialchars($result['error']) : '';
                $msg   = "Verificat <strong>" . htmlspecialchars($m['name']) . "</strong> &rarr; <span class='text-$badge'>" . strtoupper($newStatus) . "</span>$ms$err";
                $msgType = 'info';
            }
        }
    }

    // Redirect POST → GET
    $redir = '?';
    if ($msg)     $_SESSION['flash_msg']  = $msg;
    if ($msgType) $_SESSION['flash_type'] = $msgType;
    if ($id ?? 0) header("Location: /uptime?id=" . ($id ?? 0));
    else          header("Location: /uptime");
    exit;
}

// Flash message din redirect
if (isset($_SESSION['flash_msg'])) {
    $msg = $_SESSION['flash_msg']; unset($_SESSION['flash_msg']);
    $msgType = $_SESSION['flash_type'] ?? 'info'; unset($_SESSION['flash_type']);
}

// ── View: detail sau list ─────────────────────────────────────────────────────
$detailName    = trim($_GET['name'] ?? '');
$detailId      = (int)($_GET['id'] ?? 0);
$detailMonitor = null; // single-monitor (port sau fallback ?id=X)
$detailHttp    = null;
$detailSsl     = null;

if ($detailName) {
    $stmt = $db->prepare("SELECT * FROM uptime_monitors WHERE name=? AND type='http' LIMIT 1");
    $stmt->execute([$detailName]); $detailHttp = $stmt->fetch() ?: null;
    $stmt = $db->prepare("SELECT * FROM uptime_monitors WHERE name=? AND type='ssl' LIMIT 1");
    $stmt->execute([$detailName]); $detailSsl  = $stmt->fetch() ?: null;
} elseif ($detailId > 0) {
    $stmt = $db->prepare("SELECT * FROM uptime_monitors WHERE id=?");
    $stmt->execute([$detailId]);
    $detailMonitor = $stmt->fetch() ?: null;
}
$isDetail = $detailName || $detailMonitor;

// ── Date pentru view ─────────────────────────────────────────────────────────
$monitorsRaw = $db->query("
    SELECT m.*, u.username AS owner_username
    FROM uptime_monitors m
    LEFT JOIN users u ON u.id = m.added_by
    ORDER BY m.name ASC, m.type ASC
")->fetchAll();

// Grupare: HTTP+SSL pe acelasi rand; Port = rand separat
$grouped = []; // ['name' => ['http'=>row, 'ssl'=>row, 'port'=>[rows]]]
foreach ($monitorsRaw as $m) {
    $key = $m['name'];
    if ($m['type'] === 'port') {
        $grouped[$key]['port'][] = $m;
    } else {
        $grouped[$key][$m['type']] = $m;
    }
    if (!isset($grouped[$key]['owner'])) $grouped[$key]['owner'] = $m['owner_username'];
}

// Reface $monitors pentru stats (total/up/down)
$monitors = $monitorsRaw;
$totalUp   = count(array_filter($monitors, fn($m) => $m['current_status'] === 'up'));
$totalDown = count(array_filter($monitors, fn($m) => $m['current_status'] === 'down'));
$totalAll  = count($monitors);

$allUsers  = $isAdmin ? $db->query("SELECT id, username FROM users ORDER BY username")->fetchAll() : [];
$pageTitle = 'Uptime Monitor';
include 'includes/header.php';
?>

<style>
/* ── Uptime-specific styles ── */
.uptime-status-dot{display:inline-block;width:10px;height:10px;border-radius:50%;flex-shrink:0}
.uptime-status-dot.up{background:var(--success);box-shadow:0 0 0 0 rgba(16,185,129,.4);animation:uptime-pulse 2s infinite}
.uptime-status-dot.down{background:var(--danger)}
.uptime-status-dot.unknown{background:var(--text3)}
@keyframes uptime-pulse{0%{box-shadow:0 0 0 0 rgba(16,185,129,.4)}70%{box-shadow:0 0 0 6px rgba(16,185,129,0)}100%{box-shadow:0 0 0 0 rgba(16,185,129,0)}}

.uptime-badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:.73rem;font-weight:700;letter-spacing:.03em}
.uptime-badge.up{background:rgba(16,185,129,.12);color:#34d399;border:1px solid rgba(16,185,129,.25)}
.uptime-badge.down{background:rgba(239,68,68,.12);color:#fca5a5;border:1px solid rgba(239,68,68,.25)}
.uptime-badge.unknown{background:rgba(100,116,139,.12);color:var(--text2);border:1px solid rgba(100,116,139,.2)}

.type-badge{display:inline-block;padding:2px 8px;border-radius:5px;font-size:.68rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase}
.type-badge.http{background:rgba(59,130,246,.12);color:var(--accent2);border:1px solid rgba(59,130,246,.2)}
.type-badge.ssl{background:rgba(16,185,129,.1);color:#34d399;border:1px solid rgba(16,185,129,.2)}
.type-badge.port{background:rgba(139,92,246,.1);color:#a78bfa;border:1px solid rgba(139,92,246,.2)}

.sparkline-wrap{min-width:100px;max-width:180px}
.ssl-days-ok{color:var(--success);font-weight:600}
.ssl-days-warn{color:var(--warning);font-weight:600}
.ssl-days-crit{color:var(--danger);font-weight:600}

.monitor-name-link{font-family:monospace;font-size:.9rem;font-weight:600;color:var(--text);transition:.15s}
.monitor-name-link:hover{color:var(--accent2)}

.response-chart{background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:20px}
.response-chart h3{font-size:.85rem;font-weight:600;color:var(--text2);margin-bottom:12px}

.incident-open{background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.2);border-radius:10px;padding:12px 16px;display:flex;align-items:center;gap:10px;margin-bottom:16px}
.incident-open .icon{font-size:1.2rem}

.uptime-bar{display:flex;gap:2px;height:20px;align-items:center}
.uptime-bar-seg{height:14px;border-radius:3px;flex:1;min-width:3px}
.uptime-bar-seg.up{background:var(--success)}
.uptime-bar-seg.down{background:var(--danger)}
.uptime-bar-seg.unknown{background:var(--surface2)}

.stat-card.up-card::before{background:var(--success)}
.stat-card.down-card::before{background:var(--danger)}
.stat-card.unknown-card::before{background:var(--text3)}
</style>

<div class="page-header" style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px">
  <div>
    <?php if ($detailName || $detailMonitor): ?>
      <?php $titleName = $detailName ?: $detailMonitor['name']; ?>
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <a href="/uptime" style="color:var(--text2);font-size:.85rem">&larr; Inapoi</a>
        <span style="color:var(--border)">|</span>
        <?php if ($detailHttp): ?><span class="uptime-status-dot <?= $detailHttp['current_status'] ?>"></span><?php endif; ?>
        <h1><?= htmlspecialchars($titleName) ?></h1>
      </div>
    <?php else: ?>
      <h1>Uptime Monitor</h1>
      <p>Monitorizare HTTP &bull; SSL &bull; Port</p>
    <?php endif; ?>
  </div>
  <?php if (!$isDetail): ?>
  <button class="btn btn-primary" onclick="document.getElementById('addModal').classList.add('open')">
    &#43; Adauga monitor
  </button>
  <?php elseif ($detailName): ?>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <?php if ($detailHttp): ?>
    <form method="post" style="display:inline">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
      <input type="hidden" name="action" value="check">
      <input type="hidden" name="id" value="<?= $detailHttp['id'] ?>">
      <button class="btn btn-ghost btn-sm" type="submit">&#8635; Verifica HTTP</button>
    </form>
    <?php endif; ?>
    <?php if ($detailSsl): ?>
    <form method="post" style="display:inline">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
      <input type="hidden" name="action" value="check">
      <input type="hidden" name="id" value="<?= $detailSsl['id'] ?>">
      <button class="btn btn-ghost btn-sm" type="submit">&#8635; Verifica SSL</button>
    </form>
    <?php endif; ?>
  </div>
  <?php else: ?>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <form method="post" style="display:inline">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
      <input type="hidden" name="action" value="check">
      <input type="hidden" name="id" value="<?= $detailMonitor['id'] ?>">
      <button class="btn btn-ghost btn-sm" type="submit">&#8635; Verifica acum</button>
    </form>
    <button class="btn btn-ghost btn-sm" onclick="openEdit(<?= htmlspecialchars(json_encode($detailMonitor)) ?>)">&#9998; Editeaza</button>
  </div>
  <?php endif; ?>
</div>

<?php if ($msg): ?>
<div class="alert alert-<?= htmlspecialchars($msgType) ?>" style="margin-bottom:20px">
  <?= $msg ?>
</div>
<?php endif; ?>

<?php if ($detailName):
  // ─── COMBINED DETAIL VIEW (HTTP + SSL) ──────────────────────────────────────

  // Helper: statistici pentru un monitor
  function monitorStats(PDO $db, ?array $mon): array {
      if (!$mon) return ['checks'=>[], 'checksAsc'=>[], 'incidents'=>[], 'upCount'=>0, 'downCount'=>0, 'uptimePct'=>0, 'avgMs'=>0, 'activeIncident'=>null];
      $stmt = $db->prepare("SELECT * FROM uptime_checks WHERE monitor_id=? ORDER BY checked_at DESC LIMIT 200");
      $stmt->execute([$mon['id']]); $checks = $stmt->fetchAll();
      $stmt = $db->prepare("SELECT * FROM uptime_incidents WHERE monitor_id=? ORDER BY started_at DESC LIMIT 20");
      $stmt->execute([$mon['id']]); $incidents = $stmt->fetchAll();
      $stmt = $db->prepare("SELECT * FROM uptime_incidents WHERE monitor_id=? AND resolved_at IS NULL ORDER BY started_at DESC LIMIT 1");
      $stmt->execute([$mon['id']]); $activeIncident = $stmt->fetch() ?: null;
      $upCount   = count(array_filter($checks, fn($c) => $c['status'] === 'up'));
      $downCount = count(array_filter($checks, fn($c) => $c['status'] === 'down'));
      $total     = count($checks);
      $times     = array_filter(array_column($checks, 'response_time_ms'));
      return [
          'checks'         => $checks,
          'checksAsc'      => array_reverse($checks),
          'incidents'      => $incidents,
          'activeIncident' => $activeIncident,
          'upCount'        => $upCount,
          'downCount'      => $downCount,
          'uptimePct'      => $total > 0 ? round($upCount / $total * 100, 2) : 0,
          'avgMs'          => count($times) > 0 ? round(array_sum($times) / count($times)) : 0,
      ];
  }

  $httpStats = monitorStats($db, $detailHttp);
  $sslStats  = monitorStats($db, $detailSsl);

  // Incident activ pe oricare
  $activeInc = $httpStats['activeIncident'] ?? $sslStats['activeIncident'] ?? null;
?>

<?php if ($activeInc): ?>
<div class="incident-open">
  <span class="icon">&#9888;</span>
  <div><strong style="color:var(--danger)">Incident activ</strong> din <?= date('d.m.Y H:i', strtotime($activeInc['started_at'])) ?>
  <?php if ($activeInc['cause']): ?> &bull; <?= htmlspecialchars($activeInc['cause']) ?><?php endif; ?></div>
</div>
<?php endif; ?>

<!-- Stats: HTTP + SSL side by side -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">

  <!-- HTTP block -->
  <div class="card" style="padding:20px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px">
      <span class="type-badge http">HTTP</span>
      <?php if ($detailHttp): ?>
        <span class="uptime-status-dot <?= $detailHttp['current_status'] ?>"></span>
        <span class="uptime-badge <?= $detailHttp['current_status'] ?>" style="font-size:.8rem"><?= strtoupper($detailHttp['current_status']) ?></span>
        <span style="font-size:.75rem;color:var(--text3);margin-left:auto"><?= $detailHttp['last_checked_at'] ? date('H:i', strtotime($detailHttp['last_checked_at'])) : '—' ?></span>
      <?php else: ?><span style="color:var(--text3);font-size:.85rem">Nemonitorat</span><?php endif; ?>
    </div>
    <?php if ($detailHttp): ?>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
      <div>
        <div style="font-size:.7rem;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">Uptime</div>
        <div style="font-size:1.4rem;font-weight:700;color:<?= $httpStats['uptimePct'] >= 99 ? 'var(--success)' : ($httpStats['uptimePct'] >= 95 ? 'var(--warning)' : 'var(--danger)') ?>"><?= $httpStats['uptimePct'] ?>%</div>
        <div style="font-size:.72rem;color:var(--text3)"><?= count($httpStats['checks']) ?> checks</div>
      </div>
      <div>
        <div style="font-size:.7rem;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">Raspuns mediu</div>
        <div style="font-size:1.4rem;font-weight:700"><?= $httpStats['avgMs'] ?>ms</div>
        <div style="font-size:.72rem;color:var(--text3)">la <?= $detailHttp['check_interval_minutes'] ?>min</div>
      </div>
      <div>
        <div style="font-size:.7rem;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">Incidente</div>
        <div style="font-size:1.4rem;font-weight:700"><?= count($httpStats['incidents']) ?></div>
        <div style="font-size:.72rem;color:var(--text3)"><?= $httpStats['downCount'] ?> down checks</div>
      </div>
    </div>
    <?php if (count($httpStats['checksAsc']) >= 2): ?>
    <div style="margin-top:14px">
      <div style="font-size:.72rem;color:var(--text3);margin-bottom:6px">Timp raspuns (ultimele <?= count($httpStats['checksAsc']) ?> verificari)</div>
      <?= generateSparklineSvg($httpStats['checksAsc'], 400, 50) ?>
    </div>
    <?php endif; ?>
    <?php if (count($httpStats['checks']) >= 2): ?>
    <div style="margin-top:10px">
      <div class="uptime-bar">
        <?php foreach (array_slice($httpStats['checks'], 0, 60) as $c): ?>
        <div class="uptime-bar-seg <?= $c['status'] ?>" title="<?= date('d.m H:i', strtotime($c['checked_at'])) ?> — <?= $c['status'] ?>"></div>
        <?php endforeach; ?>
      </div>
    </div>
    <?php endif; ?>
    <?php endif; ?>
  </div>

  <!-- SSL block -->
  <div class="card" style="padding:20px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:16px">
      <span class="type-badge ssl">SSL</span>
      <?php if ($detailSsl): ?>
        <span class="uptime-status-dot <?= $detailSsl['current_status'] ?>"></span>
        <span class="uptime-badge <?= $detailSsl['current_status'] ?>" style="font-size:.8rem"><?= strtoupper($detailSsl['current_status']) ?></span>
        <span style="font-size:.75rem;color:var(--text3);margin-left:auto"><?= $detailSsl['last_checked_at'] ? date('H:i', strtotime($detailSsl['last_checked_at'])) : '—' ?></span>
      <?php else: ?><span style="color:var(--text3);font-size:.85rem">Nemonitorat</span><?php endif; ?>
    </div>
    <?php if ($detailSsl): ?>
    <?php $sc = $detailSsl['ssl_days_left'] !== null ? ($detailSsl['ssl_days_left'] > 30 ? 'ssl-days-ok' : ($detailSsl['ssl_days_left'] > 7 ? 'ssl-days-warn' : 'ssl-days-crit')) : ''; ?>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px">
      <div>
        <div style="font-size:.7rem;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">Expira in</div>
        <div style="font-size:1.4rem;font-weight:700" class="<?= $sc ?>"><?= $detailSsl['ssl_days_left'] ?? '—' ?> <span style="font-size:.9rem">zile</span></div>
        <div style="font-size:.72rem;color:var(--text3)"><?= $detailSsl['ssl_expires_on'] ?? '' ?></div>
      </div>
      <div>
        <div style="font-size:.7rem;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">Uptime cert</div>
        <div style="font-size:1.4rem;font-weight:700;color:<?= $sslStats['uptimePct'] >= 99 ? 'var(--success)' : 'var(--warning)' ?>"><?= $sslStats['uptimePct'] ?>%</div>
        <div style="font-size:.72rem;color:var(--text3)"><?= count($sslStats['checks']) ?> checks</div>
      </div>
      <div>
        <div style="font-size:.7rem;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">Issuer</div>
        <div style="font-size:.82rem;font-weight:600;margin-top:4px"><?= htmlspecialchars(substr($detailSsl['ssl_issuer'] ?? 'Unknown', 0, 30)) ?></div>
        <div style="font-size:.72rem;color:var(--text3)">la <?= $detailSsl['check_interval_minutes'] ?>min</div>
      </div>
    </div>
    <?php if (count($sslStats['checks']) >= 2): ?>
    <div style="margin-top:14px">
      <div class="uptime-bar">
        <?php foreach (array_slice($sslStats['checks'], 0, 60) as $c): ?>
        <div class="uptime-bar-seg <?= $c['status'] ?>" title="<?= date('d.m H:i', strtotime($c['checked_at'])) ?> — <?= $c['status'] ?>"></div>
        <?php endforeach; ?>
      </div>
    </div>
    <?php endif; ?>
    <?php endif; ?>
  </div>
</div>

<!-- Tabele: Incidente + Checks recente -->
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
  <div class="card">
    <div class="card-header"><span class="card-title">Incidente HTTP</span></div>
    <?php if (empty($httpStats['incidents'])): ?>
    <div class="empty-state" style="padding:20px"><div class="empty-icon" style="font-size:1.5rem">&#10003;</div>Niciun incident</div>
    <?php else: ?>
    <div class="table-wrap"><table>
      <thead><tr><th>Status</th><th>Start</th><th>Durata</th></tr></thead>
      <tbody>
      <?php foreach ($httpStats['incidents'] as $inc): ?>
        <tr>
          <td><?php if (!$inc['resolved_at']): ?><span class="uptime-badge down">Activ</span><?php else: ?><span class="uptime-badge up">Rezolvat</span><?php endif; ?></td>
          <td style="font-size:.78rem"><?= date('d.m H:i', strtotime($inc['started_at'])) ?></td>
          <td style="font-size:.78rem"><?php if ($inc['resolved_at']) { $d=(int)$inc['duration_seconds']; echo $d>=3600?floor($d/3600).'h '.floor(($d%3600)/60).'m':($d>=60?floor($d/60).'m '.($d%60).'s':$d.'s'); } else echo '<span style="color:var(--warning)">In curs</span>'; ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table></div>
    <?php endif; ?>
  </div>

  <div class="card">
    <div class="card-header"><span class="card-title">Verificari recente</span></div>
    <div class="table-wrap"><table>
      <thead><tr><th>Data</th><th>HTTP</th><th>Ms</th><th>SSL</th></tr></thead>
      <tbody>
      <?php
        $httpChecks = array_slice($httpStats['checks'], 0, 3);
        $sslChecks  = array_slice($sslStats['checks'],  0, 3);
        $maxRows    = max(count($httpChecks), count($sslChecks));
        for ($i = 0; $i < $maxRows; $i++):
          $hc = $httpChecks[$i] ?? null;
          $sc = $sslChecks[$i]  ?? null;
          $ts = $hc ? strtotime($hc['checked_at']) : ($sc ? strtotime($sc['checked_at']) : 0);
      ?>
      <tr>
        <td style="font-size:.75rem;color:var(--text2)"><?= $ts ? date('d.m H:i', $ts) : '—' ?></td>
        <td><?php if ($hc): ?><span class="uptime-badge <?= $hc['status'] ?>" style="font-size:.68rem;padding:2px 7px"><?= strtoupper($hc['status']) ?></span><?php else: ?>—<?php endif; ?></td>
        <td style="font-size:.8rem"><?= $hc['response_time_ms'] ?? '—' ?></td>
        <td style="font-size:.8rem"><?php if ($sc): ?><span class="uptime-badge <?= $sc['status'] ?>" style="font-size:.68rem;padding:2px 7px"><?= strtoupper($sc['status']) ?></span><?php else: ?>—<?php endif; ?></td>
      </tr>
      <?php endfor; ?>
      </tbody>
    </table></div>
  </div>
</div>

<?php elseif ($detailMonitor):
  // ─── SINGLE MONITOR DETAIL (port / fallback) ─────────────────────────────────
  $m = $detailMonitor;
  $openIncident = $db->prepare("SELECT * FROM uptime_incidents WHERE monitor_id=? AND resolved_at IS NULL ORDER BY started_at DESC LIMIT 1");
  $openIncident->execute([$m['id']]);
  $activeIncident = $openIncident->fetch();

  $checksStmt = $db->prepare("SELECT * FROM uptime_checks WHERE monitor_id=? ORDER BY checked_at DESC LIMIT 100");
  $checksStmt->execute([$m['id']]);
  $checks = $checksStmt->fetchAll();
  $checksAsc = array_reverse($checks);

  $incidentsStmt = $db->prepare("SELECT * FROM uptime_incidents WHERE monitor_id=? ORDER BY started_at DESC LIMIT 20");
  $incidentsStmt->execute([$m['id']]);
  $incidents = $incidentsStmt->fetchAll();

  $upCount   = count(array_filter($checks, fn($c) => $c['status'] === 'up'));
  $downCount = count(array_filter($checks, fn($c) => $c['status'] === 'down'));
  $uptimePct = count($checks) > 0 ? round($upCount / count($checks) * 100, 2) : 0;
  $avgMs     = count($checks) > 0 ? round(array_sum(array_column($checks, 'response_time_ms')) / count($checks)) : 0;
?>

<?php if ($activeIncident): ?>
<div class="incident-open">
  <span class="icon">&#9888;</span>
  <div>
    <strong style="color:var(--danger)">Incident activ</strong> din <?= date('d.m.Y H:i', strtotime($activeIncident['started_at'])) ?>
    <?php if ($activeIncident['cause']): ?> &bull; <?= htmlspecialchars($activeIncident['cause']) ?><?php endif; ?>
  </div>
</div>
<?php endif; ?>

<div class="stats-grid" style="grid-template-columns:repeat(auto-fit,minmax(140px,1fr))">
  <div class="stat-card <?= $m['current_status'] === 'up' ? 'up-card' : 'down-card' ?>">
    <div class="stat-label">Status curent</div>
    <div class="stat-value" style="font-size:1.5rem"><?= strtoupper($m['current_status']) ?></div>
    <div class="stat-sub"><?= $m['last_checked_at'] ? 'La ' . date('H:i', strtotime($m['last_checked_at'])) : 'Neexaminat' ?></div>
  </div>
  <div class="stat-card total">
    <div class="stat-label">Uptime (<?= count($checks) ?> checks)</div>
    <div class="stat-value" style="font-size:1.5rem;color:<?= $uptimePct >= 99 ? 'var(--success)' : ($uptimePct >= 95 ? 'var(--warning)' : 'var(--danger)') ?>"><?= $uptimePct ?>%</div>
    <div class="stat-sub"><?= $upCount ?> up / <?= $downCount ?> down</div>
  </div>
  <div class="stat-card registered">
    <div class="stat-label">Raspuns mediu</div>
    <div class="stat-value" style="font-size:1.5rem"><?= $avgMs ?>ms</div>
    <div class="stat-sub">Interval: <?= $m['check_interval_minutes'] ?>min</div>
  </div>
  <?php if ($m['type'] === 'ssl' && $m['ssl_expires_on']): ?>
  <div class="stat-card <?= $m['ssl_days_left'] > 14 ? 'available' : ($m['ssl_days_left'] > 7 ? 'pending' : 'total') ?>">
    <div class="stat-label">SSL Expira</div>
    <div class="stat-value" style="font-size:1.2rem"><?= $m['ssl_days_left'] ?> zile</div>
    <div class="stat-sub"><?= $m['ssl_expires_on'] ?></div>
  </div>
  <?php endif; ?>
</div>

<?php if (count($checksAsc) >= 2): ?>
<div class="response-chart">
  <h3>Timp de raspuns — ultimele <?= count($checksAsc) ?> verificari</h3>
  <?= generateSparklineSvg($checksAsc, 800, 60) ?>
</div>
<?php endif; ?>

<!-- Uptime bar (90 checks vizualizate ca segmente) -->
<?php if (count($checks) >= 2): ?>
<div class="card" style="margin-bottom:20px;padding:16px 20px">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
    <span style="font-size:.8rem;font-weight:600;color:var(--text2)">Disponibilitate recenta (<?= count($checks) ?> verificari)</span>
    <span style="font-size:.8rem;color:var(--text2)"><?= $uptimePct ?>% uptime</span>
  </div>
  <div class="uptime-bar">
    <?php foreach (array_slice($checks, 0, 90) as $c): ?>
    <div class="uptime-bar-seg <?= $c['status'] ?>" title="<?= date('d.m H:i', strtotime($c['checked_at'])) ?> — <?= $c['status'] ?><?= $c['response_time_ms'] ? ' ('.$c['response_time_ms'].'ms)' : '' ?>"></div>
    <?php endforeach; ?>
  </div>
</div>
<?php endif; ?>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:0">
  <!-- Incidents -->
  <div class="card">
    <div class="card-header"><span class="card-title">Incidente</span></div>
    <?php if (empty($incidents)): ?>
    <div class="empty-state" style="padding:24px"><div class="empty-icon">&#10003;</div>Niciun incident inregistrat</div>
    <?php else: ?>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Status</th><th>Start</th><th>Durata</th><th>Cauza</th></tr></thead>
      <tbody>
      <?php foreach ($incidents as $inc): ?>
        <tr>
          <td><?php if (!$inc['resolved_at']): ?><span class="uptime-badge down">Activ</span><?php else: ?><span class="uptime-badge up">Rezolvat</span><?php endif; ?></td>
          <td style="font-size:.8rem"><?= date('d.m H:i', strtotime($inc['started_at'])) ?></td>
          <td style="font-size:.8rem"><?php
            if ($inc['resolved_at']) {
              $d = (int)$inc['duration_seconds'];
              echo $d >= 3600 ? floor($d/3600).'h '.floor(($d%3600)/60).'m' : ($d >= 60 ? floor($d/60).'m '.($d%60).'s' : $d.'s');
            } else { echo '<span style="color:var(--warning)">In curs</span>'; }
          ?></td>
          <td style="font-size:.8rem;color:var(--text2)"><?= htmlspecialchars(substr($inc['cause'] ?? '—', 0, 50)) ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
    <?php endif; ?>
  </div>

  <!-- Ultimele checks -->
  <div class="card">
    <div class="card-header"><span class="card-title">Ultimele verificari</span></div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Data</th><th>Status</th><th>Ms</th><?= $m['type'] === 'http' ? '<th>HTTP</th>' : '' ?></tr></thead>
      <tbody>
      <?php foreach (array_slice($checks, 0, 30) as $c): ?>
        <tr>
          <td style="font-size:.78rem;color:var(--text2)"><?= date('d.m H:i:s', strtotime($c['checked_at'])) ?></td>
          <td><span class="uptime-badge <?= $c['status'] ?>"><?= strtoupper($c['status']) ?></span></td>
          <td style="font-size:.8rem"><?= $c['response_time_ms'] ?? '—' ?></td>
          <?php if ($m['type'] === 'http'): ?><td style="font-size:.78rem;color:var(--text2)"><?= $c['http_code'] ?: '—' ?></td><?php endif; ?>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
    </div>
  </div>
</div>

<?php else:
  // ─── LIST VIEW ───────────────────────────────────────────────────────────────
?>

<div class="stats-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:24px">
  <div class="stat-card total">
    <div class="stat-label">Total</div>
    <div class="stat-value"><?= $totalAll ?></div>
    <div class="stat-sub">monitoare</div>
  </div>
  <div class="stat-card up-card">
    <div class="stat-label">Online</div>
    <div class="stat-value" style="color:var(--success)"><?= $totalUp ?></div>
    <div class="stat-sub"><?= $totalAll > 0 ? round($totalUp/$totalAll*100) : 0 ?>% uptime</div>
  </div>
  <div class="stat-card down-card">
    <div class="stat-label">Offline</div>
    <div class="stat-value" style="color:<?= $totalDown > 0 ? 'var(--danger)' : 'var(--text2)' ?>"><?= $totalDown ?></div>
    <div class="stat-sub">monitoare jos</div>
  </div>
  <div class="stat-card unknown-card">
    <div class="stat-label">Nechecked</div>
    <div class="stat-value"><?= $totalAll - $totalUp - $totalDown ?></div>
    <div class="stat-sub">unknown</div>
  </div>
</div>

<div class="card">
  <div class="table-wrap">
  <table id="uptimeTable">
    <thead>
      <tr>
        <th>Domeniu</th>
        <th>HTTP</th>
        <th>Raspuns</th>
        <th>SSL</th>
        <th>Owner</th>
        <th>Ultima verificare</th>
        <th>Actiuni</th>
      </tr>
    </thead>
    <tbody>
    <?php if (empty($grouped)): ?>
    <tr><td colspan="7"><div class="empty-state"><div class="empty-icon">&#128268;</div>Niciun monitor adaugat inca</div></td></tr>
    <?php endif; ?>
    <?php foreach ($grouped as $name => $group):
      $http = $group['http'] ?? null;
      $ssl  = $group['ssl']  ?? null;
      $ports = $group['port'] ?? [];
      $owner = $group['owner'] ?? null;

      // Ultima verificare = cel mai recent dintre HTTP si SSL
      $lastChecked = max(
          $http ? strtotime($http['last_checked_at'] ?? '0') : 0,
          $ssl  ? strtotime($ssl['last_checked_at']  ?? '0') : 0
      );

      // Last check data pentru HTTP
      $lastHttp = null;
      if ($http) {
          $q = $db->prepare("SELECT response_time_ms, http_code, error_message FROM uptime_checks WHERE monitor_id=? ORDER BY checked_at DESC LIMIT 1");
          $q->execute([$http['id']]);
          $lastHttp = $q->fetch();
      }

      // SSL class
      $sslClass = '';
      if ($ssl && $ssl['ssl_days_left'] !== null) {
          $sslClass = $ssl['ssl_days_left'] > 30 ? 'ssl-days-ok' : ($ssl['ssl_days_left'] > 7 ? 'ssl-days-warn' : 'ssl-days-crit');
      }

      $mainMon = $http ?? $ssl;
      $rowUrl  = '/uptime?name=' . urlencode($name);
    ?>
    <tr style="cursor:pointer" onclick="window.location='<?= htmlspecialchars($rowUrl) ?>'">
      <td onclick="event.stopPropagation()">
        <a href="<?= htmlspecialchars($rowUrl) ?>" class="monitor-name-link"><?= htmlspecialchars($name) ?></a>
        <?php if ($http && !$http['monitoring_active']): ?><span style="font-size:.7rem;color:var(--text3);margin-left:4px">PAUZAT</span><?php endif; ?>
      </td>
      <td>
        <?php if ($http): ?>
        <div style="display:flex;align-items:center;gap:6px">
          <span class="uptime-status-dot <?= $http['current_status'] ?>"></span>
          <span class="uptime-badge <?= $http['current_status'] ?>"><?= strtoupper($http['current_status']) ?></span>
        </div>
        <?php if ($lastHttp && $lastHttp['error_message'] && $http['current_status'] === 'down'): ?>
        <div style="font-size:.72rem;color:var(--danger);margin-top:2px"><?= htmlspecialchars(substr($lastHttp['error_message'],0,45)) ?></div>
        <?php endif; ?>
        <?php else: ?><span style="color:var(--text3)">—</span><?php endif; ?>
      </td>
      <td style="font-size:.85rem">
        <?php if ($lastHttp && $lastHttp['response_time_ms']): ?>
          <span style="color:<?= $lastHttp['response_time_ms'] <= 1500 ? 'var(--success)' : ($lastHttp['response_time_ms'] <= 2000 ? '#f97316' : 'var(--danger)') ?>"><?= $lastHttp['response_time_ms'] ?>ms</span>
          <?php if ($lastHttp['http_code']): ?><span style="font-size:.72rem;color:var(--text3)"> &bull; <?= $lastHttp['http_code'] ?></span><?php endif; ?>
        <?php else: ?>—<?php endif; ?>
      </td>
      <td style="font-size:.82rem">
        <?php if ($ssl): ?>
        <div style="display:flex;align-items:center;gap:6px">
          <span class="uptime-status-dot <?= $ssl['current_status'] ?>" style="width:8px;height:8px;flex-shrink:0"></span>
          <?php if ($ssl['ssl_days_left'] !== null): ?>
            <span class="<?= $sslClass ?>" style="font-weight:700"><?= $ssl['ssl_days_left'] ?>z</span>
            <span style="color:var(--text3);font-size:.72rem"><?= $ssl['ssl_expires_on'] ?></span>
          <?php else: ?>
            <span class="uptime-badge <?= $ssl['current_status'] ?>"><?= strtoupper($ssl['current_status']) ?></span>
          <?php endif; ?>
        </div>
        <?php else: ?><span style="color:var(--text3)">—</span><?php endif; ?>
      </td>
      <td style="font-size:.82rem;color:var(--text2)">
        <?php if ($owner): ?>
          <?= htmlspecialchars($owner) ?>
        <?php else: ?><span style="color:var(--text3)">—</span><?php endif; ?>
      </td>
      <td style="font-size:.8rem;color:var(--text2)"><?= $lastChecked ? date('d.m H:i', $lastChecked) : '—' ?></td>
      <td onclick="event.stopPropagation()">
        <div style="display:flex;gap:4px;flex-wrap:nowrap;align-items:center">
          <?php if ($http): ?>
          <form method="post" style="display:inline">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="check">
            <input type="hidden" name="id" value="<?= $http['id'] ?>">
            <button class="btn btn-ghost btn-sm btn-icon" title="Verifica HTTP acum">&#8635;</button>
          </form>
          <?php endif; ?>
          <?php if ($mainMon): ?>
          <button class="btn btn-ghost btn-sm btn-icon" onclick='openEdit(<?= htmlspecialchars(json_encode($mainMon)) ?>)' title="Editeaza">&#9998;</button>
          <?php endif; ?>
        </div>
      </td>
    </tr>
    <?php
      // Randuri separate pentru Port monitors
      foreach ($ports as $pm): ?>
    <tr style="background:rgba(139,92,246,.04)">
      <td style="padding-left:28px">
        <a href="/uptime?id=<?= $pm['id'] ?>" class="monitor-name-link" style="font-size:.82rem"><?= htmlspecialchars($pm['name']) ?></a>
        <span class="type-badge port" style="margin-left:6px">:<?= $pm['port'] ?></span>
      </td>
      <td colspan="2">
        <div style="display:flex;align-items:center;gap:6px">
          <span class="uptime-status-dot <?= $pm['current_status'] ?>"></span>
          <span class="uptime-badge <?= $pm['current_status'] ?>"><?= strtoupper($pm['current_status']) ?></span>
        </div>
      </td>
      <td colspan="2" style="font-size:.8rem;color:var(--text3)"><?= htmlspecialchars($pm['target']) ?>:<?= $pm['port'] ?></td>
      <td style="font-size:.8rem;color:var(--text2)"><?= $pm['last_checked_at'] ? date('d.m H:i', strtotime($pm['last_checked_at'])) : '—' ?></td>
      <td>
        <div style="display:flex;gap:4px">
          <a href="/uptime?id=<?= $pm['id'] ?>" class="btn btn-ghost btn-sm btn-icon">&#128269;</a>
          <form method="post" style="display:inline" onsubmit="return confirm('Stergi monitorul?')">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="id" value="<?= $pm['id'] ?>">
            <button class="btn btn-danger btn-sm btn-icon">&#128465;</button>
          </form>
        </div>
      </td>
    </tr>
    <?php endforeach; ?>
    <?php endforeach; ?>
    </tbody>
  </table>
  </div>
</div>

<!-- Add Monitor Modal -->
<div class="modal-overlay" id="addModal">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title">&#43; Adauga monitor</span>
      <button class="modal-close" onclick="document.getElementById('addModal').classList.remove('open')">&times;</button>
    </div>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
      <input type="hidden" name="action" value="add">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div class="form-group" style="grid-column:1/-1">
          <label class="form-label">Nume *</label>
          <input type="text" name="name" class="form-input" placeholder="Ex: iosub.ro" required maxlength="100">
        </div>
        <div class="form-group" style="grid-column:1/-1">
          <label class="form-label">Tip *</label>
          <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:4px">
            <label style="display:flex;align-items:center;gap:7px;cursor:pointer;font-size:.875rem">
              <input type="checkbox" name="types[]" value="http" id="addTypeHttp" checked onchange="updateAddHint()" style="width:15px;height:15px;accent-color:var(--accent)">
              <span class="type-badge http">HTTP</span> Uptime site
            </label>
            <label style="display:flex;align-items:center;gap:7px;cursor:pointer;font-size:.875rem">
              <input type="checkbox" name="types[]" value="ssl" id="addTypeSsl" onchange="updateAddHint()" style="width:15px;height:15px;accent-color:var(--success)">
              <span class="type-badge ssl">SSL</span> Certificat
            </label>
            <label style="display:flex;align-items:center;gap:7px;cursor:pointer;font-size:.875rem">
              <input type="checkbox" name="types[]" value="port" id="addTypePort" onchange="updateAddHint()" style="width:15px;height:15px;accent-color:#a78bfa">
              <span class="type-badge port">PORT</span> TCP connect
            </label>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Interval (min)</label>
          <select name="interval" class="form-select">
            <option value="1">1 minut</option>
            <option value="5" selected>5 minute</option>
            <option value="10">10 minute</option>
            <option value="30">30 minute</option>
            <option value="60">1 ora</option>
          </select>
        </div>
        <div class="form-group" style="grid-column:1/-1">
          <label class="form-label">Target *</label>
          <input type="text" name="target" class="form-input" id="addTarget" placeholder="https://www.iosub.ro" required maxlength="500">
          <span class="form-hint" id="addHint">URL complet — SSL se extrage automat din hostname</span>
        </div>
        <div class="form-group" id="addPortWrap" style="display:none">
          <label class="form-label">Port</label>
          <input type="number" name="port" class="form-input" placeholder="443" min="1" max="65535">
        </div>
        <div class="form-group">
          <label class="form-label">Timeout (sec)</label>
          <input type="number" name="timeout" class="form-input" value="10" min="5" max="30">
        </div>
        <?php if ($isAdmin && !empty($allUsers)): ?>
        <div class="form-group" style="grid-column:1/-1">
          <label class="form-label">Owner</label>
          <select name="owner_id" class="form-select">
            <?php foreach ($allUsers as $u): ?>
            <option value="<?= $u['id'] ?>" <?= $u['id'] == $userId ? 'selected' : '' ?>><?= htmlspecialchars($u['username']) ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <?php endif; ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-ghost" onclick="document.getElementById('addModal').classList.remove('open')">Anuleaza</button>
        <button type="submit" class="btn btn-primary">Adauga</button>
      </div>
    </form>
  </div>
</div>

<?php endif; ?>

<!-- Edit Monitor Modal (shared) -->
<div class="modal-overlay" id="editModal">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title">&#9998; Editeaza monitor</span>
      <button class="modal-close" onclick="document.getElementById('editModal').classList.remove('open')">&times;</button>
    </div>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
      <input type="hidden" name="action" value="edit">
      <input type="hidden" name="id" id="editId">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div class="form-group" style="grid-column:1/-1">
          <label class="form-label">Nume *</label>
          <input type="text" name="name" id="editName" class="form-input" required maxlength="100">
        </div>
        <div class="form-group">
          <label class="form-label">Tip *</label>
          <select name="type" class="form-select" id="editType" onchange="updateTargetPlaceholder(this,'edit')">
            <option value="http">HTTP — Uptime site</option>
            <option value="ssl">SSL — Certificat</option>
            <option value="port">Port — TCP connect</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Interval (min)</label>
          <select name="interval" class="form-select" id="editInterval">
            <option value="1">1 minut</option>
            <option value="5">5 minute</option>
            <option value="10">10 minute</option>
            <option value="30">30 minute</option>
            <option value="60">1 ora</option>
          </select>
        </div>
        <div class="form-group" style="grid-column:1/-1">
          <label class="form-label">Target *</label>
          <input type="text" name="target" id="editTarget" class="form-input" required maxlength="500">
        </div>
        <div class="form-group" id="editPortWrap">
          <label class="form-label">Port</label>
          <input type="number" name="port" id="editPort" class="form-input" min="1" max="65535">
        </div>
        <div class="form-group">
          <label class="form-label">Timeout (sec)</label>
          <input type="number" name="timeout" id="editTimeout" class="form-input" min="5" max="30">
        </div>
        <?php if ($isAdmin && !empty($allUsers)): ?>
        <div class="form-group" style="grid-column:1/-1">
          <label class="form-label">Owner</label>
          <select name="owner_id" id="editOwner" class="form-select">
            <?php foreach ($allUsers as $u): ?>
            <option value="<?= $u['id'] ?>"><?= htmlspecialchars($u['username']) ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <?php endif; ?>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-ghost" onclick="document.getElementById('editModal').classList.remove('open')">Anuleaza</button>
        <button type="submit" class="btn btn-primary">Salveaza</button>
      </div>
    </form>
  </div>
</div>

<script>
function openEdit(m) {
    document.getElementById('editId').value      = m.id;
    document.getElementById('editName').value    = m.name;
    document.getElementById('editTarget').value  = m.target;
    document.getElementById('editPort').value    = m.port || '';
    document.getElementById('editTimeout').value = m.timeout_seconds || 10;
    document.getElementById('editType').value    = m.type;

    const sel = document.getElementById('editInterval');
    sel.value = m.check_interval_minutes;
    if (!sel.value) sel.value = '5';

    const ownerSel = document.getElementById('editOwner');
    if (ownerSel && m.added_by) ownerSel.value = m.added_by;

    updateTargetPlaceholder(document.getElementById('editType'), 'edit');
    document.getElementById('editModal').classList.add('open');
}

function updateAddHint() {
    const hasPort = document.getElementById('addTypePort')?.checked;
    const portWrap = document.getElementById('addPortWrap');
    if (portWrap) portWrap.style.display = hasPort ? '' : 'none';
}

function updateTargetPlaceholder(sel, prefix) {
    // folosit doar pentru edit modal (tip unic)
    const t        = sel.value;
    const input    = document.getElementById(prefix + 'Target');
    const hint     = document.getElementById(prefix + 'Hint');
    const portWrap = document.getElementById(prefix + 'PortWrap');
    if (t === 'http') {
        input.placeholder = 'https://www.iosub.ro';
        if (hint) hint.textContent = 'URL complet pentru HTTP check';
        if (portWrap) portWrap.style.display = 'none';
    } else if (t === 'ssl') {
        input.placeholder = 'iosub.ro';
        if (hint) hint.textContent = 'Doar hostname-ul, fara https://';
        if (portWrap) portWrap.style.display = '';
    } else {
        input.placeholder = 'hostname sau IP';
        if (hint) hint.textContent = 'Hostname sau IP pentru port check';
        if (portWrap) portWrap.style.display = '';
    }
}

// Inchide modal la click pe overlay
document.querySelectorAll('.modal-overlay').forEach(el => {
    el.addEventListener('click', function(e) { if (e.target === this) this.classList.remove('open'); });
});

// Auto-refresh lista la fiecare 60s (doar pe list view)
<?php if (!$detailMonitor): ?>
setTimeout(() => location.reload(), 60000);
<?php endif; ?>
</script>

<?php include 'includes/footer.php'; ?>
