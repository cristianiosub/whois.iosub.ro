<?php
require_once 'config.php';
require_once 'includes/auth.php';
require_once 'includes/db.php';
require_once 'includes/whois.php';
requireLogin();

$db = getDB();
$msg = '';
$msgType = 'success';
$validStatuses = ['unknown', 'available', 'registered', 'pending_delete', 'error'];
$validLabels   = array_keys(LABELS);

// Helper: verifica daca utilizatorul curent detine domeniu-ul (sau e admin)
$ownsOrAdmin = function(int $domainId) use ($db): bool {
    if (isAdmin()) return true;
    $s = $db->prepare("SELECT id FROM domains WHERE id=? AND added_by=?");
    $s->execute([$domainId, (int)$_SESSION['user_id']]);
    return (bool)$s->fetch();
};

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
    $action = $_POST['action'] ?? '';

    if ($action === 'add') {
        $domain      = strtolower(trim($_POST['domain'] ?? ''));
        $notes       = trim($_POST['notes'] ?? '');
        $label       = in_array($_POST['label'] ?? '', $validLabels) ? $_POST['label'] : null;
        $dtype       = ($_POST['domain_type'] ?? 'monitor') === 'owned' ? 'owned' : 'monitor';
        $expires     = !empty($_POST['expires_on']) ? $_POST['expires_on'] : null;
        $interval    = ($dtype === 'owned') ? 1440 : ($label ? LABELS[$label]['interval'] : 5);
        $autoExt     = !empty($_POST['auto_extensions']); // checkbox: adauga si .com .ro .ai

        if (!isValidDomain($domain)) {
            $msg = 'Domeniu invalid.';
            $msgType = 'danger';
        } else {
            try {
                $tld = extractTld($domain);
                $db->prepare("INSERT INTO domains (domain, tld, notes, label, check_interval_minutes, domain_type, expires_on, added_by) VALUES (?,?,?,?,?,?,?,?)")
                   ->execute([$domain, $tld, $notes, $label, $interval, $dtype, $expires, $_SESSION['user_id']]);
                $msg = "Domeniu <strong>" . htmlspecialchars($domain) . "</strong> adaugat!";

                // Auto-adauga extensii .com .ro .ai daca e bifat si domeniu e de tip monitor
                if ($autoExt && $dtype === 'monitor') {
                    $baseName = preg_replace('/\.[^.]+$/', '', $domain); // scoate TLD-ul curent
                    $extensions = ['com', 'ro'];
                    $addedExt = [];
                    foreach ($extensions as $ext) {
                        $newDomain = $baseName . '.' . $ext;
                        if ($newDomain === $domain) continue; // nu duplica
                        if (!isValidDomain($newDomain)) continue;
                        try {
                            $db->prepare("INSERT IGNORE INTO domains (domain, tld, notes, label, check_interval_minutes, domain_type, added_by) VALUES (?,?,?,?,?,?,?)")
                               ->execute([$newDomain, $ext, $notes, $label, $interval, 'monitor', $_SESSION['user_id']]);
                            if ($db->lastInsertId()) $addedExt[] = '.' . $ext;
                        } catch(PDOException $e) {}
                    }
                    if (!empty($addedExt)) {
                        $msg .= " + extensii auto: <strong>" . implode(', ', $addedExt) . "</strong>";
                    }
                }
            } catch (PDOException $e) {
                $msg = ($e->getCode() === '23000') ? 'Domeniu deja existent.' : 'Eroare la salvare. Incearca din nou.';
                $msgType = 'danger';
            }
        }
    }
    elseif ($action === 'bulk_add') {
        $raw   = trim($_POST['bulk_domains'] ?? '');
        $label = in_array($_POST['label'] ?? '', $validLabels) ? $_POST['label'] : null;
        $dtype = ($_POST['domain_type'] ?? 'monitor') === 'owned' ? 'owned' : 'monitor';
        $interval = ($dtype === 'owned') ? 1440 : ($label ? LABELS[$label]['interval'] : 5);
        $lines = preg_split('/[\r\n,;]+/', $raw);
        $added = 0; $skipped = 0;
        foreach ($lines as $line) {
            $d = strtolower(trim($line));
            if (empty($d)) continue;
            if (!isValidDomain($d)) { $skipped++; continue; }
            try {
                $tld = extractTld($d);
                $stmt = $db->prepare("INSERT IGNORE INTO domains (domain, tld, label, check_interval_minutes, domain_type, added_by) VALUES (?,?,?,?,?,?)");
                $stmt->execute([$d, $tld, $label, $interval, $dtype, $_SESSION['user_id']]);
                if ($stmt->rowCount() > 0) $added++; else $skipped++;
            } catch (PDOException $e) { $skipped++; }
        }
        $msg = "Adaugate: <strong>$added</strong>. Ignorate: $skipped.";
        if ($added === 0) $msgType = 'warning';
    }
    elseif ($action === 'update') {
        $id       = (int)($_POST['id'] ?? 0);
        $notes    = trim($_POST['notes'] ?? '');
        $label    = in_array($_POST['label'] ?? '', $validLabels) ? $_POST['label'] : null;
        $dtype    = ($_POST['domain_type'] ?? 'monitor') === 'owned' ? 'owned' : 'monitor';
        $expires  = !empty($_POST['expires_on']) ? $_POST['expires_on'] : null;
        $active   = (int)($_POST['monitoring_active'] ?? 1);
        $interval = ($dtype === 'owned') ? 1440 : ($label ? LABELS[$label]['interval'] : (int)($_POST['check_interval_minutes'] ?? 5));
        $newOwner = !empty($_POST['added_by']) ? (int)$_POST['added_by'] : null;
        if ($id > 0) {
            if (!$ownsOrAdmin($id)) {
                $msg = 'Acces interzis.'; $msgType = 'danger';
            } elseif ($newOwner && isAdmin()) {
                $db->prepare("UPDATE domains SET notes=?, label=?, check_interval_minutes=?, domain_type=?, expires_on=?, monitoring_active=?, added_by=? WHERE id=?")
                   ->execute([$notes, $label, $interval, $dtype, $expires, $active, $newOwner, $id]);
                $msg = 'Domeniu actualizat.';
            } else {
                $db->prepare("UPDATE domains SET notes=?, label=?, check_interval_minutes=?, domain_type=?, expires_on=?, monitoring_active=? WHERE id=?")
                   ->execute([$notes, $label, $interval, $dtype, $expires, $active, $id]);
                $msg = 'Domeniu actualizat.';
            }
        }
    }
    elseif ($action === 'move_to_owned') {
        $id      = (int)($_POST['id'] ?? 0);
        $expires = !empty($_POST['expires_on']) ? $_POST['expires_on'] : null;
        if ($id > 0) {
            if (!$ownsOrAdmin($id)) {
                $msg = 'Acces interzis.'; $msgType = 'danger';
            } else {
                $db->prepare("UPDATE domains SET domain_type='owned', expires_on=?, monitoring_active=1, check_interval_minutes=1440 WHERE id=?")
                   ->execute([$expires, $id]);
                $msg = 'Domeniu mutat in Expiry Tracker. Monitorizare activa (1 data/zi).';
            }
        }
    }
    elseif ($action === 'delete') {
        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            if (!$ownsOrAdmin($id)) {
                $msg = 'Acces interzis.'; $msgType = 'danger';
            } else {
                $db->prepare("DELETE FROM domains WHERE id=?")->execute([$id]);
                $msg = 'Domeniu sters.';
            }
        }
    }
    elseif ($action === 'check_now') {
        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            if (!$ownsOrAdmin($id)) {
                $msg = 'Acces interzis.'; $msgType = 'danger';
            } else
            try {
                $row = $db->prepare("SELECT domain, current_status FROM domains WHERE id=?");
                $row->execute([$id]);
                $dr = $row->fetch();
                if ($dr) {
                    require_once 'includes/sms.php';
                    $result           = checkDomain($dr['domain']);
                    $newSt            = in_array($result['status'], $validStatuses) ? $result['status'] : 'error';
                    $snapshot         = substr($result['raw'] ?? '', 0, 2000);
                    $whoisStatusesStr = implode(',', $result['whois_statuses'] ?? []);
                    try {
                        $db->prepare("INSERT INTO domain_history (domain_id, status, whois_snapshot, whois_statuses, registrar, registered_on) VALUES (?,?,?,?,?,?)")
                           ->execute([$id, $newSt, $snapshot, $whoisStatusesStr ?: null, $result['registrar'] ?? null, $result['registered_on'] ?? null]);
                    } catch (PDOException $dbErr) {
                        $db->prepare("INSERT INTO domain_history (domain_id, status, whois_snapshot, registrar, registered_on) VALUES (?,?,?,?,?)")
                           ->execute([$id, $newSt, $snapshot, $result['registrar'] ?? null, $result['registered_on'] ?? null]);
                    }
                    $db->prepare("UPDATE domains SET current_status=?, last_checked_at=NOW() WHERE id=?")->execute([$newSt, $id]);
                    if (!empty($result['expires_on'])) {
                        $db->prepare("UPDATE domains SET expires_on=? WHERE id=? AND (expires_on IS NULL OR expires_on != ?)")
                           ->execute([$result['expires_on'], $id, $result['expires_on']]);
                    }
                    if ($dr['current_status'] !== $newSt) {
                        sendSmsToAllUsers($id, $dr['domain'], $dr['current_status'], $newSt);
                    }
                    $msg = "Verificat: <strong>" . htmlspecialchars($dr['domain']) . "</strong> &rarr; <span class='badge $newSt'>" . ucfirst(str_replace('_',' ',$newSt)) . "</span>";
                    if (!empty($result['whois_statuses'])) {
                        $msg .= " <span class='text-xs text-muted'>(" . htmlspecialchars(implode(', ', $result['whois_statuses'])) . ")</span>";
                    }
                }
            } catch (Throwable $e) {
                $msg = 'Eroare: ' . htmlspecialchars($e->getMessage());
                $msgType = 'danger';
                error_log('check_now error: ' . $e->getMessage());
            }
        }
    }
    elseif ($action === 'sync_extensions') {
        // Adauga .com si .ro pentru toate domeniile din lista de tip monitor
        // care nu le au inca
        $allMonitor = $db->query("
            SELECT DISTINCT domain FROM domains
            WHERE domain_type = 'monitor' AND monitoring_active = 1
        ")->fetchAll(PDO::FETCH_COLUMN);

        // Extrage numele de baza unice (fara TLD)
        $baseNames = [];
        foreach ($allMonitor as $d) {
            $base = preg_replace('/\.[^.]+$/', '', $d);
            if (!isset($baseNames[$base])) {
                // Ia label si interval de la primul domeniu gasit cu acest base
                $row = $db->prepare("SELECT label, check_interval_minutes, notes, added_by FROM domains WHERE domain LIKE ? AND domain_type='monitor' LIMIT 1");
                $row->execute([$base . '.%']);
                $baseNames[$base] = $row->fetch() ?: ['label' => null, 'check_interval_minutes' => 5, 'notes' => '', 'added_by' => $_SESSION['user_id']];
            }
        }

        $added = 0; $skipped = 0;
        foreach ($baseNames as $base => $meta) {
            foreach (['com', 'ro'] as $ext) {
                $newDomain = $base . '.' . $ext;
                if (!isValidDomain($newDomain)) { $skipped++; continue; }
                // Verifica daca exista deja
                $exists = $db->prepare("SELECT id FROM domains WHERE domain = ?");
                $exists->execute([$newDomain]);
                if ($exists->fetch()) { $skipped++; continue; }
                try {
                    $db->prepare("INSERT INTO domains (domain, tld, notes, label, check_interval_minutes, domain_type, added_by) VALUES (?,?,?,?,?,?,?)")
                       ->execute([$newDomain, $ext, $meta['notes'], $meta['label'], $meta['check_interval_minutes'], 'monitor', $meta['added_by']]);
                    $added++;
                } catch(PDOException $e) { $skipped++; }
            }
        }
        $msg = "Sincronizare finalizata: <strong>$added</strong> domenii noi adaugate, <strong>$skipped</strong> deja existente sau ignorate.";
        if ($added === 0) $msgType = 'warning';
    }
    elseif ($action === 'toggle_monitoring') {
        $id = (int)($_POST['id'] ?? 0);
        if ($id > 0) {
            if (!$ownsOrAdmin($id)) {
                $msg = 'Acces interzis.'; $msgType = 'danger';
            } else {
                $row = $db->prepare("SELECT domain_type, monitoring_active FROM domains WHERE id=?");
                $row->execute([$id]);
                $dr = $row->fetch();
                if ($dr && $dr['domain_type'] === 'owned' && (int)$dr['monitoring_active'] === 0) {
                    $db->prepare("UPDATE domains SET monitoring_active=1, check_interval_minutes=1440 WHERE id=?")->execute([$id]);
                } else {
                    $db->prepare("UPDATE domains SET monitoring_active = 1 - monitoring_active WHERE id=?")->execute([$id]);
                }
                $msg = 'Status monitorizare actualizat.';
            }
        }
    }
}

$filter      = $_GET['filter'] ?? 'all';
$labelFilter = $_GET['label']  ?? '';
$search      = trim($_GET['q'] ?? '');
$tldFilter   = trim($_GET['tld'] ?? '');
$typeFilter  = $_GET['type']   ?? 'monitor';

if (!in_array($filter, array_merge(['all'], $validStatuses))) $filter = 'all';
if (!in_array($typeFilter, ['monitor', 'owned', 'all'])) $typeFilter = 'monitor';
if ($labelFilter && !in_array($labelFilter, $validLabels)) $labelFilter = '';

$where  = "d.domain_type = '$typeFilter'";
if ($typeFilter === 'all') $where = '1=1';
$params = [];
if ($filter !== 'all') { $where .= ' AND d.current_status = ?'; $params[] = $filter; }
if ($search)           { $where .= ' AND d.domain LIKE ?';      $params[] = "%$search%"; }
if ($tldFilter)        { $where .= ' AND d.tld = ?';            $params[] = $tldFilter; }
if ($labelFilter)      { $where .= ' AND d.label = ?';          $params[] = $labelFilter; }

$stmt = $db->prepare("SELECT d.*,
    (SELECT COUNT(*) FROM domain_history WHERE domain_id=d.id) as history_count,
    (SELECT whois_statuses FROM domain_history WHERE domain_id=d.id ORDER BY checked_at DESC LIMIT 1) as last_whois_statuses,
                    u.username as owner_username
    FROM domains d
    LEFT JOIN users u ON u.id = d.added_by
    WHERE $where
    ORDER BY
      FIELD(d.current_status,'available','pending_delete','error','unknown','registered') ASC,
      d.domain ASC");
$stmt->execute($params);
$domains = $stmt->fetchAll();

$tlds = $db->query("SELECT DISTINCT tld FROM domains ORDER BY tld")->fetchAll(PDO::FETCH_COLUMN);

try {
    $monitorCount = $db->query("SELECT COUNT(*) FROM domains WHERE domain_type='monitor' AND monitoring_active=1")->fetchColumn();
    $ownedCount   = $db->query("SELECT COUNT(*) FROM domains WHERE domain_type='owned'")->fetchColumn();
} catch(Exception $e) { $monitorCount = 0; $ownedCount = 0; }

$csrfToken = getCsrfToken();
$pageTitle = 'Domenii';
// Useri disponibili pentru alocare (doar admin vede selectul)
$allUsers = isAdmin() ? $db->query("SELECT id, username FROM users ORDER BY username")->fetchAll() : [];
include 'includes/header.php';
?>

<div class="page-header">
    <div class="flex justify-between items-center">
        <div>
            <h1>Domenii</h1>
            <p>Monitorizare si Expiry Tracker</p>
        </div>
        <div class="flex gap-2">
            <button class="btn btn-ghost" onclick="openModal('bulkModal')">Bulk Add</button>
            <button class="btn btn-primary" onclick="openModal('addModal')">+ Adauga</button>
        </div>
    </div>
</div>

<?php if ($msg): ?>
<div class="alert alert-<?= htmlspecialchars($msgType) ?>"><?= $msg ?></div>
<?php endif; ?>

<div class="flex gap-2 mb-4">
    <a href="?type=monitor<?= $filter!='all'?"&filter=$filter":'' ?><?= $labelFilter?"&label=$labelFilter":'' ?>"
       class="btn btn-sm <?= $typeFilter==='monitor'?'btn-primary':'btn-ghost' ?>">
        &#128270; Monitorizare <span style="opacity:.7">(<?= $monitorCount ?>)</span>
    </a>
    <a href="?type=owned<?= $filter!='all'?"&filter=$filter":'' ?><?= $labelFilter?"&label=$labelFilter":'' ?>"
       class="btn btn-sm <?= $typeFilter==='owned'?'btn-primary':'btn-ghost' ?>">
        &#127968; Detin <span style="opacity:.7">(<?= $ownedCount ?>)</span>
    </a>
</div>

<div class="card mb-4">
    <form method="get" class="flex gap-2 items-center" style="flex-wrap:wrap">
        <input type="hidden" name="type" value="<?= htmlspecialchars($typeFilter) ?>">
        <input type="text" name="q" class="form-input" placeholder="Cauta domeniu..." value="<?= htmlspecialchars($search) ?>" style="max-width:200px" maxlength="100">
        <select name="tld" class="form-select" style="max-width:110px">
            <option value="">Toate TLD</option>
            <?php foreach ($tlds as $t): ?>
            <option value="<?= htmlspecialchars($t) ?>" <?= $tldFilter===$t?'selected':'' ?>>.<?= htmlspecialchars($t) ?></option>
            <?php endforeach; ?>
        </select>
        <select name="label" class="form-select" style="max-width:130px">
            <option value="">Toate etichetele</option>
            <?php foreach (LABELS as $key => $l): ?>
            <option value="<?= $key ?>" <?= $labelFilter===$key?'selected':'' ?>><?= $l['label'] ?></option>
            <?php endforeach; ?>
        </select>
        <?php if ($typeFilter === 'monitor'): ?>
        <div class="flex gap-2">
            <?php foreach (['all'=>'Toate','available'=>'Disponibile','pending_delete'=>'Pending','registered'=>'Inregistrate','error'=>'Eroare'] as $k=>$v): ?>
            <a href="?type=monitor&filter=<?= $k ?><?= $search?"&q=".urlencode($search):'' ?><?= $tldFilter?"&tld=".urlencode($tldFilter):'' ?><?= $labelFilter?"&label=$labelFilter":'' ?>"
               class="btn btn-sm <?= $filter===$k?'btn-primary':'btn-ghost' ?>"><?= $v ?></a>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
        <button type="submit" class="btn btn-ghost btn-sm">Filtreaza</button>
    </form>
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title"><?= count($domains) ?> domenii</div>
    </div>
    <?php if (empty($domains)): ?>
    <div class="empty-state">
        <div class="empty-icon">&#128301;</div>
        <p>Nicio domeniu. <a href="#" onclick="openModal('addModal')" style="color:var(--accent)">Adauga primul domeniu</a>.</p>
    </div>
    <?php else: ?>
    <div class="table-wrap">
        <table id="domainsTable">
            <thead>
                <tr>
                    <th class="sortable" data-col="0" data-type="str">Domeniu <span class="sort-icon">↕</span></th>
                    <th class="sortable" data-col="1" data-type="str">Eticheta <span class="sort-icon">↕</span></th>
                    <?php if ($typeFilter === 'monitor'): ?>
                    <th class="sortable" data-col="2" data-type="status">Status <span class="sort-icon">↕</span></th>
                    <th class="sortable" data-col="3" data-type="num">Interval <span class="sort-icon">↕</span></th>
                    <?php else: ?>
                    <th class="sortable" data-col="2" data-type="date">Expira <span class="sort-icon">↕</span></th>
                    <th class="sortable" data-col="3" data-type="num">Zile ramase <span class="sort-icon">↕</span></th>
                    <?php endif; ?>
                    <th class="sortable" data-col="4" data-type="str">Owner <span class="sort-icon">↕</span></th>
                    <th>Monitorizare</th>
                    <th class="sortable" data-col="6" data-type="date">Ultima verificare <span class="sort-icon">↕</span></th>
                    <th>Actiuni</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($domains as $d):
                $safeStatus    = in_array($d['current_status'] ?? 'unknown', $validStatuses) ? $d['current_status'] : 'unknown';
                $whoisStatuses = ($d['last_whois_statuses'] ?? '') ? array_filter(array_map('trim', explode(',', $d['last_whois_statuses']))) : [];
                $dangerStatuses  = ['DeleteProhibited','Hold','Locked','RegistrantTransferProhibited','ServerDeleteProhibited','ServerTransferProhibited','ClientDeleteProhibited','ClientTransferProhibited','ClientHold'];
                $warningStatuses = ['PendingDelete','PendingTransfer','Inactive','Expired'];

                $daysLeft = null;
                $expClass = '';
                if (!empty($d['expires_on'])) {
                    $daysLeft = (int)floor((strtotime($d['expires_on']) - time()) / 86400);
                    if ($daysLeft <= 7)  $expClass = 'text-danger';
                    elseif ($daysLeft <= 30) $expClass = 'text-warning';
                    else $expClass = 'text-success';
                }
            ?>
            <tr>
                <td data-val="<?= htmlspecialchars($d['domain']) ?>">
                    <div class="domain-name"><?= htmlspecialchars($d['domain']) ?></div>
                    <?php if (!empty($d['notes'])): ?>
                    <div class="text-xs text-muted" title="<?= htmlspecialchars($d['notes']) ?>"><?= htmlspecialchars(mb_substr($d['notes'], 0, 40)) ?><?= mb_strlen($d['notes'])>40?'…':'' ?></div>
                    <?php endif; ?>
                    <div class="text-xs text-muted"><?= (int)$d['history_count'] ?> verificari</div>
                </td>
                <td data-val="<?= htmlspecialchars($d['label'] ?? '') ?>"><?= labelBadge($d['label'] ?? null) ?></td>
                <?php if ($typeFilter === 'monitor'): ?>
                <td data-val="<?= $safeStatus ?>">
                    <?php if (!empty($whoisStatuses)): ?>
                    <div class="whois-tooltip-wrap">
                        <span class="badge <?= $safeStatus ?>"><?= htmlspecialchars(ucfirst(str_replace('_',' ',$safeStatus))) ?></span>
                        <span class="whois-info-dot">i</span>
                        <div class="whois-tooltip">
                            <div class="whois-tooltip-title">Statusuri WHOIS</div>
                            <?php foreach ($whoisStatuses as $ws):
                                $wsClean = trim($ws);
                                $cls = in_array($wsClean, $dangerStatuses) ? 'danger' : (in_array($wsClean, $warningStatuses) ? 'warning' : (strtolower($wsClean)==='ok'?'ok':''));
                            ?>
                            <span class="whois-tooltip-tag <?= $cls ?>"><?= htmlspecialchars($wsClean) ?></span>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php else: ?>
                    <span class="badge <?= $safeStatus ?>"><?= htmlspecialchars(ucfirst(str_replace('_',' ',$safeStatus))) ?></span>
                    <?php endif; ?>
                </td>
                <td class="text-xs text-muted" data-val="<?= (int)($d['check_interval_minutes'] ?? 5) ?>">
                    <?php
                        $iv = (int)($d['check_interval_minutes'] ?? 5);
                        if ($iv >= 1440) echo round($iv/1440) . 'z';
                        elseif ($iv >= 60) echo round($iv/60) . 'h';
                        else echo $iv . 'min';
                    ?>
                </td>
                <?php else: ?>
                <td class="text-sm <?= $expClass ?>" data-val="<?= $d['expires_on'] ?? '' ?>">
                    <?= !empty($d['expires_on']) ? date('d.m.Y', strtotime($d['expires_on'])) : '<span class="text-muted">—</span>' ?>
                </td>
                <td class="text-sm <?= $expClass ?>" data-val="<?= $daysLeft ?? 99999 ?>">
                    <?php if ($daysLeft !== null): ?>
                        <strong><?= $daysLeft > 0 ? $daysLeft . ' zile' : 'EXPIRAT' ?></strong>
                    <?php else: ?>
                        <span class="text-muted">—</span>
                    <?php endif; ?>
                </td>
                <?php endif; ?>
                <td data-val="<?= htmlspecialchars($d['owner_username'] ?? '') ?>" class="text-sm">
                    <?php if (!empty($d['owner_username'])): ?>
                    <span style="color:var(--text2)"><?= htmlspecialchars($d['owner_username']) ?></span>
                    <?php else: ?>
                    <span class="text-muted">—</span>
                    <?php endif; ?>
                </td>
                <td>
                    <form method="post" style="display:inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                        <input type="hidden" name="action" value="toggle_monitoring">
                        <input type="hidden" name="id" value="<?= (int)$d['id'] ?>">
                        <button type="submit" class="btn btn-sm <?= $d['monitoring_active'] ? 'btn-success' : 'btn-ghost' ?>"
                                title="<?= $d['monitoring_active'] ? 'Opreste monitorizarea' : 'Activeaza monitorizarea' ?>">
                            <?= $d['monitoring_active'] ? 'Activ' : 'Oprit' ?>
                        </button>
                    </form>
                </td>
                <td class="text-sm text-muted" data-val="<?= $d['last_checked_at'] ?? '' ?>" style="white-space:nowrap"><?= !empty($d['last_checked_at']) ? date('d.m.Y H:i', strtotime($d['last_checked_at'])) : 'Niciodata' ?></td>
                <td>
                    <div class="flex gap-2">
                        <form method="post" style="display:inline">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
                            <input type="hidden" name="action" value="check_now">
                            <input type="hidden" name="id" value="<?= (int)$d['id'] ?>">
                            <button type="submit" class="btn btn-ghost btn-sm btn-icon" title="Verifica acum">&#8635;</button>
                        </form>
                        <button class="btn btn-ghost btn-sm btn-icon" title="Editeaza"
                            onclick="openEdit(<?= (int)$d['id'] ?>, <?= htmlspecialchars(json_encode([
                                'notes'    => $d['notes'] ?? '',
                                'label'    => $d['label'] ?? '',
                                'dtype'    => $d['domain_type'] ?? 'monitor',
                                'expires'  => $d['expires_on'] ?? '',
                                'active'   => $d['monitoring_active'],
                                'interval' => $d['check_interval_minutes'] ?? 5,
                                'owner'    => $d['added_by'] ?? '',
                            ])) ?>)">&#9998;</button>
                        <?php if ($typeFilter === 'monitor' && $safeStatus === 'available'): ?>
                        <a href="https://portal.chroot.ro/cart.php?a=add&domain=register&query=<?= urlencode($d['domain']) ?>" target="_blank" rel="noopener noreferrer" class="btn btn-success btn-sm">Cumpara</a>
                        <?php endif; ?>
                        <?php if ($typeFilter === 'monitor'): ?>
                        <button class="btn btn-ghost btn-sm btn-icon" title="Muta in Expiry Tracker"
                            onclick="openMoveToOwned(<?= (int)$d['id'] ?>, '<?= htmlspecialchars($d['domain']) ?>')">&#127968;</button>
                        <?php else: ?>
                        <button class="btn btn-ghost btn-sm btn-icon" title="Muta in Monitorizare"
                            onclick="moveToMonitor(<?= (int)$d['id'] ?>)">&#128270;</button>
                        <?php endif; ?>
                        <a href="/history?domain=<?= urlencode($d['domain']) ?>" class="btn btn-ghost btn-sm btn-icon" title="Istoric">&#128203;</a>
                        <button class="btn btn-danger btn-sm btn-icon" title="Sterge"
                            onclick="confirmDelete(<?= (int)$d['id'] ?>, <?= htmlspecialchars(json_encode($d['domain'])) ?>)">&#128465;</button>
                    </div>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>
</div>

<!-- Modal Adauga -->
<div class="modal-overlay" id="addModal">
    <div class="modal" style="max-width:580px">
        <div class="modal-header">
            <div class="modal-title">Adauga Domeniu</div>
            <button class="modal-close" onclick="closeModal('addModal')">&#10005;</button>
        </div>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="add">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
                <div class="form-group">
                    <label class="form-label">Domeniu</label>
                    <input type="text" name="domain" class="form-input" placeholder="exemplu.ro" required autofocus maxlength="255">
                </div>
                <div class="form-group">
                    <label class="form-label">Tip</label>
                    <select name="domain_type" class="form-select" onchange="toggleExpiry(this.value)">
                        <option value="monitor">Monitorizare (vreau sa-l cumpar)</option>
                        <option value="owned">Il detin (expiry tracker)</option>
                    </select>
                </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
                <div class="form-group">
                    <label class="form-label">Eticheta</label>
                    <select name="label" class="form-select">
                        <option value="">Fara eticheta</option>
                        <?php foreach (LABELS as $key => $l): ?>
                        <option value="<?= $key ?>"><?= $l['label'] ?> (check: <?= $l['interval']>=1440?'1zi':$l['interval'].'min' ?>)</option>
                        <?php endforeach; ?>
                    </select>
                    <div class="form-hint">Intervalul se seteaza automat. Owned = mereu 1zi.</div>
                </div>
                <div class="form-group" id="expiryField" style="display:none">
                    <label class="form-label">Data expirare</label>
                    <input type="date" name="expires_on" class="form-input">
                </div>
            </div>
            <div class="form-group" style="margin-bottom:16px">
                <label class="form-label">Note (optional)</label>
                <input type="text" name="notes" class="form-input" placeholder="Nota scurta..." maxlength="500">
            </div>
            <div id="autoExtRow" style="margin-bottom:16px;padding:10px 14px;background:rgba(59,130,246,.06);border:1px solid rgba(59,130,246,.15);border-radius:8px">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" name="auto_extensions" value="1" checked
                           style="width:16px;height:16px;accent-color:var(--accent);cursor:pointer">
                    <span style="font-size:.85rem">
                        Adauga automat si extensiile <strong>.com</strong> si <strong>.ro</strong>
                        <span style="color:var(--text3);font-size:.78rem;display:block">Domeniile cu alte extensii vor fi monitorizate simultan</span>
                    </span>
                </label>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-ghost" onclick="closeModal('addModal')">Anuleaza</button>
                <button type="submit" class="btn btn-primary">Adauga</button>
            </div>
        </form>
    </div>
</div>

<!-- Modal Bulk Add -->
<div class="modal-overlay" id="bulkModal">
    <div class="modal" style="max-width:580px">
        <div class="modal-header">
            <div class="modal-title">Adauga Bulk</div>
            <button class="modal-close" onclick="closeModal('bulkModal')">&#10005;</button>
        </div>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="bulk_add">
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
                        <option value="owned">Detin (expiry tracker)</option>
                    </select>
                </div>
            </div>
            <div class="form-group" style="margin-bottom:16px">
                <label class="form-label">Domenii (unul per linie)</label>
                <textarea name="bulk_domains" class="form-textarea" rows="8" placeholder="domeniu1.ro&#10;domeniu2.com&#10;domeniu3.net" required></textarea>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-ghost" onclick="closeModal('bulkModal')">Anuleaza</button>
                <button type="submit" class="btn btn-primary">Importa</button>
            </div>
        </form>
    </div>
</div>

<!-- Modal Edit -->
<div class="modal-overlay" id="editModal">
    <div class="modal" style="max-width:580px">
        <div class="modal-header">
            <div class="modal-title">Editeaza Domeniu</div>
            <button class="modal-close" onclick="closeModal('editModal')">&#10005;</button>
        </div>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="update">
            <input type="hidden" name="id" id="editId">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
                <div class="form-group">
                    <label class="form-label">Eticheta</label>
                    <select name="label" id="editLabel" class="form-select">
                        <option value="">Fara eticheta</option>
                        <?php foreach (LABELS as $key => $l): ?>
                        <option value="<?= $key ?>"><?= $l['label'] ?> (<?= $l['interval']>=1440?'1zi':$l['interval'].'min' ?>)</option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Tip domeniu</label>
                    <select name="domain_type" id="editDtype" class="form-select">
                        <option value="monitor">Monitorizare</option>
                        <option value="owned">Il detin</option>
                    </select>
                </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
                <div class="form-group">
                    <label class="form-label">Monitorizare</label>
                    <select name="monitoring_active" id="editActive" class="form-select">
                        <option value="1">Activa</option>
                        <option value="0">Oprita</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Data expirare</label>
                    <input type="date" name="expires_on" id="editExpires" class="form-input">
                </div>
            </div>
            <div class="form-group" style="margin-bottom:16px">
                <label class="form-label">Note</label>
                <input type="text" name="notes" id="editNotes" class="form-input" maxlength="500">
            </div>
            <?php if (!empty($allUsers)): ?>
            <div class="form-group" style="margin-bottom:16px">
                <label class="form-label">Proprietar (SMS alerts)</label>
                <select name="added_by" id="editOwner" class="form-select">
                    <?php foreach ($allUsers as $u): ?>
                    <option value="<?= (int)$u['id'] ?>"><?= htmlspecialchars($u['username']) ?></option>
                    <?php endforeach; ?>
                </select>
                <div class="form-hint">Userul care primeste SMS-urile pentru acest domeniu</div>
            </div>
            <?php endif; ?>
            <div class="modal-footer">
                <button type="button" class="btn btn-ghost" onclick="closeModal('editModal')">Anuleaza</button>
                <button type="submit" class="btn btn-primary">Salveaza</button>
            </div>
        </form>
    </div>
</div>

<!-- Modal Move to Owned -->
<div class="modal-overlay" id="moveOwnedModal">
    <div class="modal" style="max-width:420px">
        <div class="modal-header">
            <div class="modal-title">&#127968; Muta in Expiry Tracker</div>
            <button class="modal-close" onclick="closeModal('moveOwnedModal')">&#10005;</button>
        </div>
        <p style="color:var(--text2);margin-bottom:12px;font-size:.9rem">
            Domeniu <strong id="moveOwnedDomain" style="color:var(--text);font-family:monospace"></strong> va fi mutat in lista domeniilor detinute.
        </p>
        <p style="color:var(--success);font-size:.82rem;margin-bottom:20px">&#10003; Monitorizarea va ramane activa — verificat o data pe zi.</p>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="move_to_owned">
            <input type="hidden" name="id" id="moveOwnedId">
            <div class="form-group" style="margin-bottom:20px">
                <label class="form-label">Data expirare (optional)</label>
                <input type="date" name="expires_on" class="form-input">
                <div class="form-hint">Introdu data pentru a primi alerte SMS inainte de expirare</div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-ghost" onclick="closeModal('moveOwnedModal')">Anuleaza</button>
                <button type="submit" class="btn btn-primary">Muta</button>
            </div>
        </form>
    </div>
</div>

<!-- Modal Delete -->
<div class="modal-overlay" id="deleteModal">
    <div class="modal" style="max-width:400px">
        <div class="modal-header">
            <div class="modal-title" style="color:var(--danger)">Confirmare Stergere</div>
            <button class="modal-close" onclick="closeModal('deleteModal')">&#10005;</button>
        </div>
        <p style="color:var(--text2);margin-bottom:20px">Stergi <strong id="deleteDomain" style="color:var(--text)"></strong> si tot istoricul?</p>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="id" id="deleteId">
            <div class="modal-footer">
                <button type="button" class="btn btn-ghost" onclick="closeModal('deleteModal')">Anuleaza</button>
                <button type="submit" class="btn btn-danger">Sterge</button>
            </div>
        </form>
    </div>
</div>

<!-- Form ascuns move to monitor -->
<form method="post" id="moveMonitorForm" style="display:none">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
    <input type="hidden" name="action" value="update">
    <input type="hidden" name="id" id="moveMonitorId">
    <input type="hidden" name="domain_type" value="monitor">
    <input type="hidden" name="monitoring_active" value="1">
    <input type="hidden" name="label" value="">
    <input type="hidden" name="notes" value="">
    <input type="hidden" name="expires_on" value="">
</form>

<script>
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

function openEdit(id, data) {
    document.getElementById('editId').value      = id;
    document.getElementById('editNotes').value   = data.notes || '';
    document.getElementById('editLabel').value   = data.label || '';
    document.getElementById('editDtype').value   = data.dtype || 'monitor';
    document.getElementById('editExpires').value = data.expires || '';
    document.getElementById('editActive').value  = data.active;
    const ownerSel = document.getElementById('editOwner');
    if (ownerSel && data.owner) ownerSel.value = data.owner;
    openModal('editModal');
}

function openMoveToOwned(id, domain) {
    document.getElementById('moveOwnedId').value = id;
    document.getElementById('moveOwnedDomain').textContent = domain;
    openModal('moveOwnedModal');
}

function moveToMonitor(id) {
    if (!confirm('Muta domeniu inapoi in monitorizare?')) return;
    document.getElementById('moveMonitorId').value = id;
    document.getElementById('moveMonitorForm').submit();
}

function confirmDelete(id, domain) {
    document.getElementById('deleteId').value = id;
    document.getElementById('deleteDomain').textContent = domain;
    openModal('deleteModal');
}

function toggleExpiry(val) {
    document.getElementById('expiryField').style.display = val === 'owned' ? 'flex' : 'none';
    const extRow = document.getElementById('autoExtRow');
    if (extRow) extRow.style.display = val === 'owned' ? 'none' : '';
}

document.querySelectorAll('.modal-overlay').forEach(el => {
    el.addEventListener('click', function(e) { if(e.target===this) this.classList.remove('open'); });
});

// ---- Sortare tabel ----
(function() {
    // Ordine prioritati pentru status (available = cel mai important, registered = normal)
    const STATUS_ORDER = {available:0, pending_delete:1, error:2, unknown:3, registered:4};

    let sortCol = -1;
    let sortAsc = true;

    const table = document.getElementById('domainsTable');
    if (!table) return;

    // Aplica stiluri capete sortabile
    const style = document.createElement('style');
    style.textContent = `
        th.sortable { cursor:pointer; user-select:none; white-space:nowrap }
        th.sortable:hover { color:var(--accent2) }
        th.sortable.sort-asc .sort-icon::after  { content:' ▲'; color:var(--accent2) }
        th.sortable.sort-desc .sort-icon::after { content:' ▼'; color:var(--accent2) }
        th.sortable .sort-icon { font-size:.7rem; opacity:.4; transition:.15s }
        th.sortable:hover .sort-icon, th.sortable.sort-asc .sort-icon, th.sortable.sort-desc .sort-icon { opacity:1 }
    `;
    document.head.appendChild(style);

    function getVal(row, col, type) {
        const cells = row.querySelectorAll('td');
        const cell  = cells[col];
        if (!cell) return '';
        const raw = (cell.dataset.val ?? cell.textContent).trim();
        if (type === 'num')    return parseFloat(raw) || 0;
        if (type === 'date')   return raw ? raw.replace(/[^0-9]/g,'') : '99999999999999';
        if (type === 'status') return STATUS_ORDER[raw] ?? 99;
        return raw.toLowerCase(); // str
    }

    function sortTable(col, type) {
        const tbody = table.querySelector('tbody');
        if (!tbody) return;

        // Toggle directie daca acelasi col
        if (sortCol === col) sortAsc = !sortAsc;
        else { sortCol = col; sortAsc = true; }

        const rows = Array.from(tbody.querySelectorAll('tr'));
        rows.sort((a, b) => {
            const va = getVal(a, col, type);
            const vb = getVal(b, col, type);
            let cmp = 0;
            if (typeof va === 'number') cmp = va - vb;
            else cmp = String(va).localeCompare(String(vb), 'ro', {numeric:true});
            return sortAsc ? cmp : -cmp;
        });

        rows.forEach(r => tbody.appendChild(r));

        // Actualizeaza iconite
        table.querySelectorAll('th.sortable').forEach(th => {
            th.classList.remove('sort-asc','sort-desc');
        });
        const activeTh = table.querySelector(`th.sortable[data-col="${col}"]`);
        if (activeTh) activeTh.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
    }

    // Ataseaza click pe fiecare th sortabil
    table.querySelectorAll('th.sortable').forEach(th => {
        th.addEventListener('click', () => {
            sortTable(parseInt(th.dataset.col), th.dataset.type || 'str');
        });
    });

    // Aplica sortare initiala: Status ASC (available primul, registered ultimul)
    sortTable(2, 'status');
})();
</script>

<?php include 'includes/footer.php'; ?>
