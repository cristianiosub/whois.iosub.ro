#!/usr/bin/env php
<?php
if (isset($_SERVER['HTTP_HOST'])) { http_response_code(403); die('Forbidden'); }
define('CRON_RUN', true);
chdir(__DIR__ . '/..');
require_once 'config.php';
require_once 'includes/db.php';
require_once 'includes/whois.php';
require_once 'includes/sms.php';

$lockFile = __DIR__ . '/../logs/cron.lock';
if (file_exists($lockFile)) {
    $pid = (int)file_get_contents($lockFile);
    if ($pid > 0 && file_exists("/proc/$pid")) { echo "[" . date('H:i:s') . "] Already running.\n"; exit(0); }
}
file_put_contents($lockFile, getmypid());

$validStatuses = ['unknown','available','registered','pending_delete','error'];
$db = getDB();

// Actualizeaza intervalul pentru domeniile personal existente (1440 -> 10080)
// si forteaza 5 min pentru pending_delete
try {
    $db->exec("UPDATE domains SET check_interval_minutes = 10080 WHERE label = 'personal' AND check_interval_minutes = 1440 AND domain_type = 'monitor'");
    $db->exec("UPDATE domains SET check_interval_minutes = 5 WHERE current_status = 'pending_delete' AND domain_type = 'monitor' AND check_interval_minutes > 5");
} catch(Exception $e) {}

// Selecteaza domeniile de tip "monitor" care au intervalul depasit.
// Domeniile cu status pending_delete folosesc mereu 5 minute, indiferent de label.
$stmt = $db->query("
    SELECT id, domain, tld, current_status,
           CASE WHEN current_status = 'pending_delete' THEN 5
                ELSE check_interval_minutes
           END AS effective_interval
    FROM domains
    WHERE monitoring_active = 1
      AND domain_type = 'monitor'
      AND (
          last_checked_at IS NULL
          OR (
              current_status = 'pending_delete'
              AND last_checked_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE)
          )
          OR (
              current_status != 'pending_delete'
              AND last_checked_at < DATE_SUB(NOW(), INTERVAL check_interval_minutes MINUTE)
          )
      )
    ORDER BY
      current_status = 'pending_delete' DESC,
      last_checked_at ASC
");
$domains = $stmt->fetchAll();

echo "[" . date('Y-m-d H:i:s') . "] Verificare " . count($domains) . " domenii...\n";

foreach ($domains as $row) {
    $id         = (int)$row['id'];
    $domain     = $row['domain'];
    $prevStatus = $row['current_status'];

    echo "  $domain ... ";

    try {
        $result    = checkDomain($domain);
        $newStatus = in_array($result['status'], $validStatuses) ? $result['status'] : 'error';
    } catch (Exception $e) {
        $newStatus = 'error';
        $result    = ['raw' => $e->getMessage(), 'registrar' => null, 'registered_on' => null, 'expires_on' => null, 'whois_statuses' => []];
    }

    // Daca WHOIS returneaza 'unknown'/'error' pentru un domeniu cu status cunoscut,
    // poate fi o eroare tranzitorie (timeout, rate limiting, server WHOIS down).
    // Reincercam de pana la 4 ori (total 5 incercari) inainte sa acceptam rezultatul.
    $knownStatusesList = ['registered', 'available', 'pending_delete'];
    if (in_array($newStatus, ['unknown', 'error']) && in_array($prevStatus, $knownStatusesList)) {
        $maxRetries = 4;
        for ($attempt = 1; $attempt <= $maxRetries; $attempt++) {
            usleep(2000000); // 2 secunde intre incercari
            echo " [retry $attempt/$maxRetries]";
            try {
                $retryResult = checkDomain($domain);
                $retryStatus = in_array($retryResult['status'], $validStatuses) ? $retryResult['status'] : 'error';
            } catch (Exception $e) {
                $retryStatus = 'error';
                $retryResult = ['raw' => $e->getMessage(), 'registrar' => null, 'registered_on' => null, 'expires_on' => null, 'whois_statuses' => []];
            }
            if (!in_array($retryStatus, ['unknown', 'error'])) {
                $newStatus = $retryStatus;
                $result    = $retryResult;
                echo " => $newStatus (recuperat dupa $attempt reincercare(i))";
                break;
            }
        }
    }

    // Daca dupa toate reincercarile statusul e tot unknown/error iar inainte stiam statusul,
    // e o eroare tranzitorie: nu actualizam statusul si nu poluam istoricul.
    $isTransientFailure = (
        in_array($newStatus, ['unknown', 'error']) &&
        in_array($prevStatus, $knownStatusesList)
    );

    $whoisStatusesStr = implode(',', $result['whois_statuses'] ?? []);
    $snapshot         = substr($result['raw'] ?? '', 0, 2000);
    echo "$newStatus" . ($whoisStatusesStr ? " [$whoisStatusesStr]" : "");
    if ($isTransientFailure) echo " [eroare tranzitorie - se pastreaza $prevStatus]";
    echo "\n";

    // Nu inseram in istoric daca e eroare tranzitorie — evita poluarea timeline-ului
    // cu intrari "unknown" care dispar la urmatoarea verificare
    if (!$isTransientFailure) {
        try {
            $db->prepare("INSERT INTO domain_history (domain_id, status, whois_snapshot, whois_statuses, registrar, registered_on) VALUES (?,?,?,?,?,?)")
               ->execute([$id, $newStatus, $snapshot, $whoisStatusesStr ?: null, $result['registrar'], $result['registered_on']]);
        } catch (PDOException $e) {
            $db->prepare("INSERT INTO domain_history (domain_id, status, whois_snapshot, registrar, registered_on) VALUES (?,?,?,?,?)")
               ->execute([$id, $newStatus, $snapshot, $result['registrar'], $result['registered_on']]);
        }
    } else {
        echo " [ignorat - nu se salveaza in istoric]";
    }

    if ($isTransientFailure) {
        // Actualizeaza doar last_checked_at, nu schimba statusul
        $db->prepare("UPDATE domains SET last_checked_at=NOW() WHERE id=?")->execute([$id]);
    } else {
        $db->prepare("UPDATE domains SET current_status=?, last_checked_at=NOW() WHERE id=?")->execute([$newStatus, $id]);
    }

    // Actualizeaza expires_on daca WHOIS a returnat data
    if (!empty($result['expires_on'])) {
        $db->prepare("UPDATE domains SET expires_on=? WHERE id=? AND (expires_on IS NULL OR expires_on != ?)")
           ->execute([$result['expires_on'], $id, $result['expires_on']]);
    }

    // Trimite SMS doar la schimbari intre statusuri cunoscute (available/registered/pending_delete)
    // Nu trimite niciodata din/spre unknown, null, error sau erori tranzitorii
    $knownStatuses = ['available', 'registered', 'pending_delete'];
    if (!$isTransientFailure
        && $prevStatus !== $newStatus
        && in_array($prevStatus, $knownStatuses, true)
        && in_array($newStatus,  $knownStatuses, true)
    ) {
        echo "  !! STATUS CHANGE: $prevStatus -> $newStatus - Trimitere SMS\n";
        sendSmsToAllUsers($id, $domain, $prevStatus, $newStatus);
    }

    // Ajusteaza intervalul automat pe baza noului status
    if ($prevStatus !== $newStatus) {
        if ($newStatus === 'pending_delete') {
            // Tocmai a intrat in pending_delete -> forteaza 5 min
            $db->prepare("UPDATE domains SET check_interval_minutes = 5 WHERE id = ?")->execute([$id]);
            echo "  => Interval setat la 5 min (pending_delete)\n";
        } elseif ($prevStatus === 'pending_delete') {
            // A iesit din pending_delete -> restaureaza intervalul label-ului
            $labelRow = $db->prepare("SELECT label FROM domains WHERE id = ?");
            $labelRow->execute([$id]);
            $labelVal = $labelRow->fetchColumn();
            $labels = defined('LABELS') ? LABELS : [];
            $defaultInterval = ($labelVal && isset($labels[$labelVal])) ? $labels[$labelVal]['interval'] : 1440;
            $db->prepare("UPDATE domains SET check_interval_minutes = ? WHERE id = ?")->execute([$defaultInterval, $id]);
            echo "  => Interval restaurat la {$defaultInterval} min (iesit din pending_delete)\n";
        }
    }

    // Salveaza IP curent (fara SMS alert)
    $currentIp = @gethostbyname($domain);
    if ($currentIp && $currentIp !== $domain) {
        try {
            $db->prepare("INSERT INTO settings (key_name, key_value) VALUES (?,?) ON DUPLICATE KEY UPDATE key_value=?, updated_at=NOW()")
               ->execute(["domain_ip_{$id}", $currentIp, $currentIp]);
        } catch(Exception $e) {}
    }

    // Salveaza NS curent (fara SMS alert)
    $nsRecs = @dns_get_record($domain, DNS_NS);
    if ($nsRecs) {
        $currentNs = implode(',', array_map(fn($r) => strtolower($r['target']), $nsRecs));
        try {
            $db->prepare("INSERT INTO settings (key_name, key_value) VALUES (?,?) ON DUPLICATE KEY UPDATE key_value=?, updated_at=NOW()")
               ->execute(["domain_ns_{$id}", $currentNs, $currentNs]);
        } catch(Exception $e) {}
    }

    usleep(600000); // 0.6s intre cereri ca sa nu fie blocat de WHOIS
}

// Alerte expirare pentru domeniile "owned"
$expiring = $db->query("
    SELECT id, domain, expires_on, DATEDIFF(expires_on, CURDATE()) as days_left
    FROM domains
    WHERE domain_type = 'owned'
      AND expires_on IS NOT NULL
      AND expires_on >= CURDATE()
      AND DATEDIFF(expires_on, CURDATE()) IN (30, 14, 7, 3, 1)
")->fetchAll();

foreach ($expiring as $e) {
    $key = "expiry_alert_{$e['id']}_{$e['days_left']}";
    $alreadySent = $db->prepare("SELECT key_value FROM settings WHERE key_name=? AND updated_at >= DATE_SUB(NOW(), INTERVAL 23 HOUR)");
    $alreadySent->execute([$key]);
    if ($alreadySent->fetch()) continue;

    $msg = "DomainWatch: {$e['domain']} expira in {$e['days_left']} zile ({$e['expires_on']}). Reinnoieste acum!";
    sendSmsToAllUsers($e['id'], $e['domain'], 'expiry_alert', "expires_in_{$e['days_left']}_days", $msg);
    setSetting($key, date('Y-m-d H:i:s'));
    echo "  EXPIRY ALERT: {$e['domain']} in {$e['days_left']} zile\n";
}

// Cleanup
try { $db->exec("DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 2 HOUR)"); } catch(Exception $e) {}

echo "[" . date('Y-m-d H:i:s') . "] Done.\n";
@unlink($lockFile);
