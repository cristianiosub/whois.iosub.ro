<?php
// includes/db.php

require_once __DIR__ . '/../config.php';

// Etichete disponibile cu culori si intervale implicite
define('LABELS', [
    'personal'   => ['color' => '#8b5cf6', 'bg' => 'rgba(139,92,246,.15)',  'border' => 'rgba(139,92,246,.3)',  'interval' => 10080, 'label' => 'Personal'],
    'client'     => ['color' => '#3b82f6', 'bg' => 'rgba(59,130,246,.15)',  'border' => 'rgba(59,130,246,.3)',  'interval' => 1440, 'label' => 'Client'],
    'proiect'    => ['color' => '#10b981', 'bg' => 'rgba(16,185,129,.15)',  'border' => 'rgba(16,185,129,.3)',  'interval' => 5,    'label' => 'Proiect'],
    'friends'    => ['color' => '#f59e0b', 'bg' => 'rgba(245,158,11,.15)',  'border' => 'rgba(245,158,11,.3)',  'interval' => 1440, 'label' => 'Friends'],
    'investitie' => ['color' => '#ef4444', 'bg' => 'rgba(239,68,68,.15)',   'border' => 'rgba(239,68,68,.3)',   'interval' => 5,    'label' => 'Investitie'],
]);

function getDB(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=" . DB_CHARSET;
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];
        $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    }
    return $pdo;
}

function getSetting(string $key): ?string {
    $db = getDB();
    $stmt = $db->prepare("SELECT key_value FROM settings WHERE key_name = ?");
    $stmt->execute([$key]);
    $row = $stmt->fetch();
    return $row ? $row['key_value'] : null;
}

function setSetting(string $key, string $value): void {
    $db = getDB();
    $stmt = $db->prepare("INSERT INTO settings (key_name, key_value) VALUES (?,?) ON DUPLICATE KEY UPDATE key_value=?, updated_at=NOW()");
    $stmt->execute([$key, $value, $value]);
}

function isAdmin(): bool {
    if (!isset($_SESSION['user_id'])) return false;
    $db = getDB();
    try {
        $stmt = $db->prepare("SELECT role FROM users WHERE id=?");
        $stmt->execute([$_SESSION['user_id']]);
        $row = $stmt->fetch();
        return ($row['role'] ?? 'user') === 'admin';
    } catch (Exception $e) {
        return false;
    }
}

function requireAdmin(): void {
    if (!isAdmin()) {
        http_response_code(403);
        die('Acces interzis. Doar administratorii pot accesa aceasta pagina.');
    }
}

// Helper: returneaza HTML badge pentru label
function labelBadge(?string $label): string {
    if (!$label || !isset(LABELS[$label])) return '';
    $l = LABELS[$label];
    return "<span style=\"display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:600;background:{$l['bg']};color:{$l['color']};border:1px solid {$l['border']}\">{$l['label']}</span>";
}
