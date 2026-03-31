#!/usr/bin/env php
<?php
if (isset($_SERVER['HTTP_HOST'])) { http_response_code(403); die('Forbidden'); }
define('CRON_RUN', true);
chdir(__DIR__ . '/..');
require_once 'config.php';
require_once 'includes/db.php';
require_once 'includes/sms.php';
require_once 'includes/uptime_check.php';

$lockFile = __DIR__ . '/../logs/cron_uptime.lock';
if (file_exists($lockFile)) {
    $pid = (int)file_get_contents($lockFile);
    if ($pid > 0 && file_exists("/proc/$pid")) { echo "[" . date('H:i:s') . "] Already running.\n"; exit(0); }
}
file_put_contents($lockFile, getmypid());

$db = getDB();

$monitors = $db->query("
    SELECT *
    FROM uptime_monitors
    WHERE monitoring_active = 1
      AND (last_checked_at IS NULL OR last_checked_at < DATE_SUB(NOW(), INTERVAL check_interval_minutes MINUTE))
    ORDER BY last_checked_at ASC
")->fetchAll();

echo "[" . date('Y-m-d H:i:s') . "] Verificare " . count($monitors) . " monitoare uptime...\n";

foreach ($monitors as $m) {
    $id         = (int)$m['id'];
    $prevStatus = $m['current_status'];

    echo "  [{$m['type']}] {$m['name']} ... ";

    $result    = runUptimeCheck($m);
    $newStatus = $result['status'];

    // Salveaza check in istoric
    try {
        $db->prepare("
            INSERT INTO uptime_checks
                (monitor_id, status, response_time_ms, http_code, ssl_days_left, ssl_issuer, ssl_expires_on, error_message)
            VALUES (?,?,?,?,?,?,?,?)
        ")->execute([
            $id,
            $newStatus,
            $result['response_time_ms'] ?? null,
            $result['http_code']        ?? null,
            $result['ssl_days_left']    ?? null,
            $result['ssl_issuer']       ?? null,
            $result['ssl_expires_on']   ?? null,
            $result['error']            ?? null,
        ]);
    } catch (Exception $e) {}

    // Actualizeaza statusul curent
    $db->prepare("UPDATE uptime_monitors SET current_status=?, last_checked_at=NOW() WHERE id=?")
       ->execute([$newStatus, $id]);

    // Cache SSL info pe monitor
    if (!empty($result['ssl_expires_on'])) {
        $db->prepare("UPDATE uptime_monitors SET ssl_expires_on=?, ssl_days_left=?, ssl_issuer=? WHERE id=?")
           ->execute([$result['ssl_expires_on'], $result['ssl_days_left'], $result['ssl_issuer'], $id]);
    }

    $icon = $newStatus === 'up' ? '✓' : '✗';
    echo "$icon $newStatus";
    if (isset($result['response_time_ms'])) echo " ({$result['response_time_ms']}ms)";
    if (!empty($result['error'])) echo " [{$result['error']}]";
    echo "\n";

    // Detectare schimbare status — nu notifica din/spre 'unknown' (starea initiala)
    if ($prevStatus !== $newStatus && $prevStatus !== 'unknown') {
        $db->prepare("UPDATE uptime_monitors SET last_status_change_at=NOW() WHERE id=?")->execute([$id]);

        if ($newStatus === 'down') {
            // Deschide incident nou
            $db->prepare("INSERT INTO uptime_incidents (monitor_id, started_at, cause) VALUES (?, NOW(), ?)")
               ->execute([$id, $result['error'] ?? 'Serviciu indisponibil']);
            echo "  !! DOWN - incident deschis, trimitere SMS\n";

            $msg  = "DomainWatch: {$m['name']} este DOWN!\n";
            $msg .= $result['error'] ? "Cauza: {$result['error']}\n" : '';
            $msg .= date('d.m.Y H:i');
            sendUptimeSmsToAllUsers($id, $m['name'], $prevStatus, $newStatus, $msg);

        } elseif ($newStatus === 'up' && $prevStatus === 'down') {
            // Inchide incident deschis
            $db->prepare("
                UPDATE uptime_incidents
                SET resolved_at=NOW(), duration_seconds=TIMESTAMPDIFF(SECOND, started_at, NOW())
                WHERE monitor_id=? AND resolved_at IS NULL
            ")->execute([$id]);
            echo "  !! BACK UP - incident rezolvat, trimitere SMS\n";

            $msg  = "DomainWatch: {$m['name']} este din nou UP!\n";
            if (isset($result['response_time_ms'])) $msg .= "Raspuns: {$result['response_time_ms']}ms\n";
            $msg .= date('d.m.Y H:i');
            sendUptimeSmsToAllUsers($id, $m['name'], $prevStatus, $newStatus, $msg);
        }
    }

    // SMS-urile SSL (expirare anticipata) sunt dezactivate — se trimite SMS doar la DOWN/UP

    usleep(300000); // 0.3s intre verificari
}

echo "[" . date('Y-m-d H:i:s') . "] Done.\n";
@unlink($lockFile);
