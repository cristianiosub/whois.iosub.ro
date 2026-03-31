<?php
// includes/uptime_check.php

function checkHttp(string $url, int $timeout = 10): array {
    if (!function_exists('curl_init')) {
        return ['status' => 'down', 'error' => 'cURL unavailable', 'http_code' => 0, 'response_time_ms' => 0];
    }
    $start = microtime(true);
    $ch    = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 5,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_USERAGENT      => 'DomainWatch/1.0 Uptime Monitor',
        CURLOPT_NOBODY         => true,
    ]);
    curl_exec($ch);
    $code    = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $elapsed = (int)round((microtime(true) - $start) * 1000);
    $curlErr = curl_error($ch) ?: null;
    curl_close($ch);

    // 2xx, 3xx, 401, 403 = server responds = up
    $up = ($code >= 200 && $code < 500 && $code !== 0);
    return [
        'status'           => $up ? 'up' : 'down',
        'http_code'        => $code,
        'response_time_ms' => $elapsed,
        'error'            => $up ? null : ($curlErr ?? "HTTP $code"),
    ];
}

function checkSsl(string $host, int $port = 443, int $timeout = 10): array {
    $ctx    = stream_context_create(['ssl' => [
        'capture_peer_cert' => true,
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
    ]]);
    $start  = microtime(true);
    $socket = @stream_socket_client("ssl://$host:$port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
    $elapsed = (int)round((microtime(true) - $start) * 1000);

    if (!$socket) {
        return ['status' => 'down', 'error' => $errstr ?: 'Conexiune esuata', 'response_time_ms' => $elapsed];
    }
    $params = stream_context_get_params($socket);
    $cert   = $params['options']['ssl']['peer_certificate'] ?? null;
    fclose($socket);

    if (!$cert) {
        return ['status' => 'down', 'error' => 'Certificat negasit', 'response_time_ms' => $elapsed];
    }
    $info      = openssl_x509_parse($cert);
    $expiresTs = $info['validTo_time_t'] ?? 0;
    $issuer    = $info['issuer']['O'] ?? ($info['issuer']['CN'] ?? 'Unknown');
    $expiresOn = $expiresTs ? date('Y-m-d', $expiresTs) : null;
    $daysLeft  = $expiresTs ? (int)(($expiresTs - time()) / 86400) : -1;

    return [
        'status'           => $daysLeft > 0 ? 'up' : 'down',
        'ssl_days_left'    => $daysLeft,
        'ssl_issuer'       => substr($issuer, 0, 100),
        'ssl_expires_on'   => $expiresOn,
        'response_time_ms' => $elapsed,
        'error'            => $daysLeft <= 0 ? 'Certificat expirat' : null,
    ];
}

function checkPort(string $host, int $port, int $timeout = 10): array {
    $start  = microtime(true);
    $socket = @fsockopen($host, $port, $errno, $errstr, $timeout);
    $elapsed = (int)round((microtime(true) - $start) * 1000);
    if (!$socket) {
        return ['status' => 'down', 'error' => $errstr ?: "Port $port inchis", 'response_time_ms' => $elapsed];
    }
    fclose($socket);
    return ['status' => 'up', 'response_time_ms' => $elapsed, 'error' => null];
}

function runUptimeCheck(array $monitor): array {
    $type    = $monitor['type'];
    $target  = $monitor['target'];
    $port    = (int)($monitor['port'] ?? 0);
    $timeout = max(5, min(30, (int)($monitor['timeout_seconds'] ?? 10)));

    switch ($type) {
        case 'http':
            return checkHttp($target, $timeout);
        case 'ssl':
            $host = preg_replace('#^https?://#', '', $target);
            $host = strtok($host, '/') ?: $host;
            return checkSsl($host, $port ?: 443, $timeout);
        case 'port':
            return checkPort($target, $port, $timeout);
        default:
            return ['status' => 'down', 'error' => 'Tip monitor necunoscut', 'response_time_ms' => 0];
    }
}

function generateSparklineSvg(array $checks, int $w = 300, int $h = 36): string {
    $checks = array_filter($checks, fn($c) => isset($c['response_time_ms']) && $c['response_time_ms'] > 0);
    $checks = array_values($checks);
    if (count($checks) < 2) return '';

    $times = array_column($checks, 'response_time_ms');
    $max   = max($times) ?: 1;
    $n     = count($times);
    $pts   = [];
    foreach ($times as $i => $t) {
        $x    = round($i / ($n - 1) * $w, 1);
        $y    = round($h - ($t / $max * ($h - 6)) - 3, 1);
        $pts[] = "$x,$y";
    }
    $poly = implode(' ', $pts);
    // Fill area under line
    $first = $pts[0];
    $last  = $pts[$n - 1];
    [$fx] = explode(',', $first);
    [$lx] = explode(',', $last);
    $fillPts = $poly . " $lx,$h $fx,$h";

    return "<svg viewBox='0 0 $w $h' style='width:100%;height:{$h}px;display:block'>"
        . "<polygon points='$fillPts' fill='rgba(59,130,246,0.08)'/>"
        . "<polyline points='$poly' fill='none' stroke='#3b82f6' stroke-width='1.5' stroke-linejoin='round' stroke-linecap='round'/>"
        . "</svg>";
}
