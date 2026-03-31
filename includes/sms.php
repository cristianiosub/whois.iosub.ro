<?php
// includes/sms.php

require_once __DIR__ . '/db.php';

/**
 * Helper intern: executa un request GET catre API-ul SendSMS.ro (ca din browser).
 * Incearca in ordine: IPv4+SSL → IPv4+noSSL
 * Returneaza raspunsul JSON brut sau null la esec total / raspuns HTML.
 */
function _smsSendRequest(string $username, string $apiKey, string $to, string $text, string $from): ?string {
    $params = [
        'action'      => 'message_send',
        'username'    => $username,
        'password'    => $apiKey,
        'to'          => $to,
        'from'        => $from,
        'text'        => $text,
        'ctype'       => 1,
        'report_mask' => 19,
    ];

    $url = 'https://api.sendsms.ro/json?' . http_build_query($params);

    if (function_exists('curl_init')) {
        // Try IPv4+SSL first, then IPv4+noSSL
        $combos = [
            [CURL_IPRESOLVE_V4, true,  'IPv4+SSL'],
            [CURL_IPRESOLVE_V4, false, 'IPv4+noSSL'],
        ];

        foreach ($combos as [$ipResolve, $sslVerify, $label]) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING       => '',
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_SSL_VERIFYPEER => $sslVerify,
                CURLOPT_SSL_VERIFYHOST => $sslVerify ? 2 : 0,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_IPRESOLVE      => $ipResolve,
            ]);
            $r   = curl_exec($ch);
            $err = ($r === false) ? curl_error($ch) : '';
            curl_close($ch);

            if ($r !== false && stripos(ltrim($r), '<!DOCTYPE') !== 0) {
                error_log("[SendSMS] Conectat cu succes via $label, sender: $from");
                return $r;
            }
            if ($r === false) {
                error_log("[SendSMS] $label esuat cURL: $err");
            } else {
                $preview = preg_replace('/\s+/', ' ', strip_tags(substr($r, 0, 600)));
                error_log("[SendSMS] $label returnat HTML. Preview: " . substr($preview, 0, 200));
                @file_put_contents(__DIR__ . '/../logs/sms_block_response.html', $r);
            }
        }
        error_log("[SendSMS] Toate combinatiile IP/SSL au esuat pentru sender: $from");
        return null;
    }

    // Fallback: stream_context (GET)
    $ctx = stream_context_create([
        'http'  => ['timeout' => 15],
        'ssl'   => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);
    $r = @file_get_contents($url, false, $ctx);
    if ($r !== false && stripos(ltrim($r), '<!DOCTYPE') !== 0) {
        error_log("[SendSMS] stream_context a reusit pentru sender: $from");
        return $r;
    }

    return null;
}

/**
 * Fallback: apeleaza curl-ul de sistem via exec()/shell_exec().
 */
function _smsSendRequestExec(string $payload): ?string {
    $disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
    $canExec  = function_exists('exec')       && !in_array('exec',       $disabled, true);
    $canShell = function_exists('shell_exec') && !in_array('shell_exec', $disabled, true);

    if (!$canExec && !$canShell) {
        error_log("[SendSMS] exec() si shell_exec() sunt dezactivate");
        return null;
    }

    $curlBin = null;
    foreach (['/usr/bin/curl', '/usr/local/bin/curl', '/bin/curl'] as $bin) {
        if (@is_executable($bin)) { $curlBin = $bin; break; }
    }
    if (!$curlBin) {
        if ($canExec) { $out=[]; exec('which curl 2>/dev/null', $out); $curlBin = trim($out[0] ?? ''); }
        if (!$curlBin) { error_log("[SendSMS] exec fallback: curl binary negasit"); return null; }
    }

    error_log("[SendSMS] Incerc system curl: $curlBin");
    foreach (['-6', '-4', ''] as $ipFlag) {
        $cmd = $curlBin
             . ' -s -m 15 -X POST -k'
             . ' -H ' . escapeshellarg('Content-Type: application/x-www-form-urlencoded')
             . ' -H ' . escapeshellarg('Accept: application/json, text/plain, */*')
             . ' -H ' . escapeshellarg('Accept-Language: ro-RO,ro;q=0.9,en-US;q=0.8,en;q=0.7')
             . ' -H ' . escapeshellarg('User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36')
             . ' -H ' . escapeshellarg('Origin: https://hub.sendsms.ro')
             . ' -H ' . escapeshellarg('Referer: https://hub.sendsms.ro/')
             . ($ipFlag ? " $ipFlag" : '')
             . ' --data ' . escapeshellarg($payload)
             . ' https://api.sendsms.ro/json 2>/dev/null';
        $r = null;
        if ($canExec) {
            $out = []; $ret = -1; exec($cmd, $out, $ret);
            $r = implode('', $out);
        } elseif ($canShell) {
            $r = (string)shell_exec($cmd);
        }
        if ($r && stripos(ltrim($r), '<!DOCTYPE') !== 0 && trim($r) !== '') {
            error_log("[SendSMS] System curl $ipFlag a reusit!");
            return $r;
        }
    }
    error_log("[SendSMS] System curl a esuat pe toate variantele");
    return null;
}

/**
 * Fallback: stream_socket_client pentru HTTPS raw.
 */
function _smsSendRequestSocket(string $payload): ?string {
    $host    = 'api.sendsms.ro';
    $port    = 443;
    $timeout = 15;

    $ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
    $fp  = @stream_socket_client("tls://$host:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) {
        error_log("[SendSMS] stream_socket_client esuat: [$errno] $errstr");
        return null;
    }
    $request = "POST /json HTTP/1.1\r\n"
             . "Host: $host\r\n"
             . "Content-Type: application/x-www-form-urlencoded\r\n"
             . "Accept: application/json, text/plain, */*\r\n"
             . "Accept-Language: ro-RO,ro;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
             . "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\n"
             . "Origin: https://hub.sendsms.ro\r\n"
             . "Referer: https://hub.sendsms.ro/\r\n"
             . "Content-Length: " . strlen($payload) . "\r\n"
             . "Connection: close\r\n\r\n"
             . $payload;
    fwrite($fp, $request);
    stream_set_timeout($fp, $timeout);
    $response = '';
    while (!feof($fp)) $response .= fread($fp, 4096);
    fclose($fp);

    $parts = explode("\r\n\r\n", $response, 2);
    $body  = isset($parts[1]) ? $parts[1] : $response;
    if (stripos($parts[0] ?? '', 'Transfer-Encoding: chunked') !== false) {
        $decoded = '';
        $pos = 0;
        while ($pos < strlen($body)) {
            $nl = strpos($body, "\r\n", $pos);
            if ($nl === false) break;
            $size = hexdec(substr($body, $pos, $nl - $pos));
            if ($size === 0) break;
            $decoded .= substr($body, $nl + 2, $size);
            $pos = $nl + 2 + $size + 2;
        }
        $body = $decoded ?: $body;
    }

    if ($body && stripos(ltrim($body), '<!DOCTYPE') !== 0 && trim($body) !== '') {
        error_log("[SendSMS] stream_socket_client a reusit!");
        return $body;
    }
    error_log("[SendSMS] stream_socket_client: raspuns invalid sau HTML");
    return null;
}

/**
 * Helper: executa POST catre SMSO.ro (provider de fallback).
 * Autentificare via header X-Authorization, body JSON.
 * Returneaza raspunsul JSON brut sau null la esec.
 */
function _smsoSendRequest(string $to, string $text): ?string {
    $apiKey = getSetting('smso_apikey') ?? '';
    if (!$apiKey) {
        error_log("[SMSO] API Key neconfigurat in setari");
        return null;
    }

    // Foloseste sender ID specific pentru SMSO (nu SendSMS.from!)
    $smsoFrom = getSetting('smso_from') ?? 'DomainWatch';

    $body = json_encode([
        'sender' => $smsoFrom,
        'to'     => $to,
        'body'   => $text,
    ]);

    $headers = [
        'Content-Type: application/json',
        'Accept: application/json',
        'X-Authorization: ' . $apiKey,
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    ];

    if (function_exists('curl_init')) {
        $combos = [
            [CURL_IPRESOLVE_V6, true,  'IPv6+SSL'],
            [CURL_IPRESOLVE_V6, false, 'IPv6+noSSL'],
            [CURL_IPRESOLVE_V4, true,  'IPv4+SSL'],
            [CURL_IPRESOLVE_V4, false, 'IPv4+noSSL'],
        ];
        foreach ($combos as [$ipResolve, $sslVerify, $label]) {
            $ch = curl_init('https://app.smso.ro/api/v1/send');
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $body,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING       => '',   // decomprima automat gzip/deflate/br
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_SSL_VERIFYPEER => $sslVerify,
                CURLOPT_SSL_VERIFYHOST => $sslVerify ? 2 : 0,
                CURLOPT_HTTPHEADER     => $headers,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_IPRESOLVE      => $ipResolve,
            ]);
            $r        = curl_exec($ch);
            $err      = ($r === false) ? curl_error($ch) : '';
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($r !== false && stripos(ltrim($r), '<!DOCTYPE') !== 0) {
                error_log("[SMSO] Conectat via $label, HTTP $httpCode");
                return $r;
            }
            if ($r === false) {
                error_log("[SMSO] $label esuat cURL: $err");
            } else {
                $preview = preg_replace('/\s+/', ' ', strip_tags(substr($r, 0, 300)));
                error_log("[SMSO] $label returnat HTML: " . substr($preview, 0, 150));
            }
        }
        error_log("[SMSO] Toate combinatiile IP/SSL au esuat");
        return null;
    }

    // Fallback: stream_context
    $headerStr = implode("\r\n", $headers);
    foreach ([true, false] as $sslVerify) {
        $ctx = stream_context_create([
            'http' => ['method' => 'POST', 'content' => $body, 'timeout' => 15, 'header' => $headerStr],
            'ssl'  => ['verify_peer' => $sslVerify, 'verify_peer_name' => $sslVerify],
        ]);
        $r = @file_get_contents('https://app.smso.ro/api/v1/send', false, $ctx);
        if ($r !== false && stripos(ltrim($r), '<!DOCTYPE') !== 0) {
            error_log("[SMSO] stream_context a reusit");
            return $r;
        }
    }

    error_log("[SMSO] Toate variantele au esuat");
    return null;
}

/**
 * Trimite SMS prin cel mai bun provider disponibil.
 *   1. SendSMS.ro (primar) - incearca cu mai multi senders ca fallback
 *   2. SMSO.ro    (fallback automat)
 *
 * Returneaza messageId string la succes sau null la esec total.
 * NU face INSERT in sms_alerts — apelantul e responsabil pentru persistenta.
 */
function _sendSmsWithFallback(string $phoneNumber, string $text): ?string {
    $username = getSetting('sendsms_username') ?? '';
    $apiKey   = getSetting('sendsms_apikey')   ?? '';
    $primarySender = getSetting('sendsms_from') ?? 'DomainWatch';

    // 1. SendSMS.ro cu CyberShield
    if ($apiKey) {
        $result = _smsSendRequest($username, $apiKey, $phoneNumber, $text, 'CyberShield');
        $data = $result ? json_decode($result, true) : null;

        if (($data['status'] ?? -99) === 1) {
            error_log("[SMS] SendSMS.ro OK (sender: CyberShield) -> $phoneNumber");
            return $data['details'] ?? 'sendsms:ok';
        }

        error_log("[SMS] SendSMS.ro esuat (status=" . ($data['status'] ?? 'null') . "), incerc SMSO.ro...");
    } else {
        error_log("[SMS] SendSMS.ro API Key neconfigurat, incerc direct SMSO.ro...");
    }

    // 2. SMSO.ro fallback (foloseste smso_from din setari, nu sendsms_from!)
    $smsoResult = _smsoSendRequest($phoneNumber, $text);
    $smsoData   = $smsoResult ? json_decode($smsoResult, true) : null;
    if (!empty($smsoData['responseToken'])) {
        error_log("[SMS] SMSO.ro OK -> $phoneNumber (token=" . $smsoData['responseToken'] . ")");
        return 'smso:' . $smsoData['responseToken'];
    }

    error_log("[SMS] Esec TOTAL (SendSMS.ro + SMSO.ro) -> $phoneNumber");
    return null;
}

/**
 * Trimite SMS si inregistreaza in tabelul sms_alerts.
 */
function sendSmsAlert(int $domainId, string $domain, string $oldStatus, string $newStatus, string $phoneNumber, string $customText = ''): bool {
    if ($customText) {
        $text = $customText;
    } else {
        $statusLabels = [
            'available'      => 'DISPONIBIL',
            'registered'     => 'Inregistrat',
            'pending_delete' => 'PendingDelete',
            'error'          => 'Eroare',
            'unknown'        => 'Necunoscut',
        ];
        $oldLabel = $statusLabels[$oldStatus] ?? $oldStatus;
        $newLabel = $statusLabels[$newStatus] ?? $newStatus;
        $text = "DomainWatch: $domain\nStatus: $oldLabel -> $newLabel";
        if ($newStatus === 'available')          $text .= "\nDOMENIU DISPONIBIL! Inregistreaza-l acum!";
        elseif ($newStatus === 'pending_delete') $text .= "\nIn curand disponibil!";
    }

    $messageId = _sendSmsWithFallback($phoneNumber, $text);
    $success   = ($messageId !== null);

    if ($domainId > 0) {
        try {
            $db = getDB();
            $db->prepare("INSERT INTO sms_alerts (domain_id, phone_number, message, old_status, new_status, sendsms_message_id) VALUES (?,?,?,?,?,?)")
               ->execute([$domainId, $phoneNumber, $text, $oldStatus, $newStatus, $messageId]);
        } catch(Exception $e) {}
    }

    return $success;
}

/**
 * Trimite SMS proprietarului domeniului (si CC admin).
 */
function sendSmsToAllUsers(int $domainId, string $domain, string $oldStatus, string $newStatus, string $customText = ''): void {
    $db = getDB();

    $owner = null;
    if ($domainId > 0) {
        $stmt = $db->prepare(
            "SELECT u.phone_number FROM domains d
             JOIN users u ON u.id = d.added_by
             WHERE d.id = ? AND u.sms_alerts = 1
               AND u.phone_number != '' AND u.phone_number != '40700000000'"
        );
        $stmt->execute([$domainId]);
        $owner = $stmt->fetchColumn();
    }

    $admin = $db->query(
        "SELECT phone_number FROM users
         WHERE role = 'admin' AND sms_alerts = 1
           AND phone_number != '' AND phone_number != '40700000000'
         LIMIT 1"
    )->fetchColumn();

    if ($owner) {
        sendSmsAlert($domainId, $domain, $oldStatus, $newStatus, $owner, $customText);
        if ($admin && $admin !== $owner) {
            sendSmsAlert($domainId, $domain, $oldStatus, $newStatus, $admin, $customText);
        }
        return;
    }

    if ($admin) {
        sendSmsAlert($domainId, $domain, $oldStatus, $newStatus, $admin, $customText);
    }
}

/**
 * Trimite SMS pentru alerte uptime (HTTP/SSL/Port monitors).
 */
function sendUptimeSmsToAllUsers(int $monitorId, string $monitorName, string $oldStatus, string $newStatus, string $customText = ''): void {
    $db = getDB();

    $owner = null;
    if ($monitorId > 0) {
        $stmt = $db->prepare(
            "SELECT u.phone_number FROM uptime_monitors m
             JOIN users u ON u.id = m.added_by
             WHERE m.id = ? AND u.sms_alerts = 1
               AND u.phone_number != '' AND u.phone_number != '40700000000'"
        );
        $stmt->execute([$monitorId]);
        $owner = $stmt->fetchColumn();
    }

    $admin = $db->query(
        "SELECT phone_number FROM users
         WHERE role = 'admin' AND sms_alerts = 1
           AND phone_number != '' AND phone_number != '40700000000'
         LIMIT 1"
    )->fetchColumn();

    if ($owner) {
        sendSmsAlert(0, $monitorName, $oldStatus, $newStatus, $owner, $customText);
        if ($admin && $admin !== $owner) {
            sendSmsAlert(0, $monitorName, $oldStatus, $newStatus, $admin, $customText);
        }
        return;
    }

    if ($admin) {
        sendSmsAlert(0, $monitorName, $oldStatus, $newStatus, $admin, $customText);
    }
}
