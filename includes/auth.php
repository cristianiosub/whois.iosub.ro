<?php
// includes/auth.php

require_once __DIR__ . '/db.php';

/* ============================================================
   SESIUNE SECURIZATA
   ============================================================ */

function startSecureSession(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_set_cookie_params([
            'lifetime' => 0,            // cookie de sesiune (nu persistent)
            'path'     => '/',
            'secure'   => isset($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_name('DW_SID');
        session_start();
    }
    if (!isset($_SESSION['_initiated'])) {
        session_regenerate_id(true);
        $_SESSION['_initiated'] = true;
        $_SESSION['_start_time'] = time();
    }
    // Timeout absolut: 8 ore
    if (isset($_SESSION['_start_time']) && (time() - $_SESSION['_start_time']) > SESSION_LIFETIME) {
        session_destroy();
        session_start();
        session_regenerate_id(true);
        $_SESSION['_initiated']  = true;
        $_SESSION['_start_time'] = time();
    }
}

/* ============================================================
   AUTENTIFICARE
   ============================================================ */

function isLoggedIn(): bool {
    startSecureSession();
    if (!isset($_SESSION['user_id'], $_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        return false;
    }
    $fingerprint = hash('sha256', ($_SERVER['REMOTE_ADDR'] ?? '') . ($_SERVER['HTTP_USER_AGENT'] ?? ''));
    if (!isset($_SESSION['_fingerprint'])) {
        $_SESSION['_fingerprint'] = $fingerprint;
    } elseif ($_SESSION['_fingerprint'] !== $fingerprint) {
        session_destroy();
        return false;
    }
    return true;
}

function requireLogin(): void {
    if (!isLoggedIn()) {
        header('Location: /');
        exit;
    }
}

/* ============================================================
   CSRF
   ============================================================ */

function getCsrfToken(): string {
    startSecureSession();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Valideaza token-ul CSRF si il roteste dupa validare.
 */
function validateCsrf(): void {
    $token = $_POST['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    if (empty($token) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(403);
        die('Cerere invalida (CSRF). <a href="javascript:history.back()">Inapoi</a>');
    }
    // Roteaza token-ul dupa utilizare
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* ============================================================
   GEO-RESTRICȚIE
   ============================================================ */

/**
 * Verifica daca IP-ul apartine uneia din tarile permise (GEO_ALLOWED_COUNTRIES).
 * Rezultatul e cacheuit in baza de date timp de 7 zile.
 */
function isAllowedCountry(string $ip): bool {
    // Permite intotdeauna IP-uri locale / private
    if (in_array($ip, ['127.0.0.1', '::1'], true) ||
        (bool)preg_match('/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/', $ip)) {
        return true;
    }

    $allowed = GEO_ALLOWED_COUNTRIES;
    $db      = getDB();

    // Creeaza tabela cache daca nu exista
    try {
        $db->exec("CREATE TABLE IF NOT EXISTS ip_geo_cache (
            ip          VARCHAR(45) NOT NULL PRIMARY KEY,
            country     VARCHAR(5)  NOT NULL DEFAULT '',
            checked_at  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_checked (checked_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    } catch (PDOException $e) {}

    // Cauta in cache (valid 7 zile)
    try {
        $stmt = $db->prepare("SELECT country FROM ip_geo_cache WHERE ip=? AND checked_at > DATE_SUB(NOW(), INTERVAL 7 DAY)");
        $stmt->execute([$ip]);
        $row = $stmt->fetch();
        if ($row !== false) {
            return in_array($row['country'], $allowed, true);
        }
    } catch (PDOException $e) {}

    // Interogeaza ip-api.com (gratuit, 45 req/min)
    $country = '';
    $ctx = stream_context_create(['http' => [
        'timeout'       => 3,
        'ignore_errors' => true,
        'method'        => 'GET',
    ]]);
    $raw = @file_get_contents("http://ip-api.com/json/{$ip}?fields=status,countryCode", false, $ctx);
    if ($raw !== false) {
        $data = json_decode($raw, true);
        if (is_array($data) && ($data['status'] ?? '') === 'success') {
            $country = $data['countryCode'] ?? '';
        }
    }

    // Stocheaza in cache (chiar daca e gol — fail-closed)
    try {
        $db->prepare(
            "INSERT INTO ip_geo_cache (ip, country) VALUES (?,?)
             ON DUPLICATE KEY UPDATE country=?, checked_at=NOW()"
        )->execute([$ip, $country, $country]);
    } catch (PDOException $e) {}

    return $country !== '' && in_array($country, $allowed, true);
}

/* ============================================================
   COOKIE RATE-LIMIT
   ============================================================ */

/**
 * Returneaza (sau creeaza) un cookie de tracking pentru rate-limit la login.
 * Cookie-ul e HttpOnly, Secure, SameSite=Strict si dureaza 30 de zile.
 */
function getOrSetLoginCookie(): string {
    $name = 'dw_la';
    if (!empty($_COOKIE[$name]) && preg_match('/^[a-f0-9]{64}$/', $_COOKIE[$name])) {
        return $_COOKIE[$name];
    }
    $id = bin2hex(random_bytes(32));
    setcookie($name, $id, [
        'expires'  => time() + 86400 * 30,
        'path'     => '/',
        'secure'   => isset($_SERVER['HTTPS']),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    return $id;
}

/* ============================================================
   LOGIN
   ============================================================ */

/**
 * Incearca autentificarea.
 *
 * Returneaza:
 *  true           — succes
 *  'geo_blocked'  — IP nu este din Romania (sau tara permisa)
 *  'cooldown'     — mai putin de LOGIN_COOLDOWN_SECONDS secunde de la ultima incercare
 *  'blocked'      — prea multe incercari (IP sau cookie)
 *  false          — credentiale incorecte
 */
function login(string $username, string $password) {
    $db = getDB();
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // ── 1. Creeaza / migreaza tabela login_attempts ─────────────────────
    // Creeaza tabela daca nu exista
    try {
        $db->exec("CREATE TABLE IF NOT EXISTS login_attempts (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            ip           VARCHAR(45)  NOT NULL,
            cookie_id    VARCHAR(64)  DEFAULT NULL,
            username     VARCHAR(50)  DEFAULT NULL,
            attempted_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ip_time     (ip,        attempted_at),
            INDEX idx_cookie_time (cookie_id, attempted_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    } catch (PDOException $e) {}

    // Migrare: adauga coloana cookie_id daca lipseste (tabela exista deja fara ea)
    try {
        $chk = $db->query("SHOW COLUMNS FROM login_attempts LIKE 'cookie_id'");
        if ($chk && $chk->rowCount() === 0) {
            $db->exec("ALTER TABLE login_attempts ADD COLUMN cookie_id VARCHAR(64) DEFAULT NULL AFTER ip");
            try { $db->exec("ALTER TABLE login_attempts ADD INDEX idx_cookie_time (cookie_id, attempted_at)"); } catch (PDOException $e2) {}
        }
    } catch (PDOException $e) {}

    // ── 2. Geo-restricție ────────────────────────────────────────────────
    if (defined('GEO_RESTRICT_LOGIN') && GEO_RESTRICT_LOGIN) {
        startSecureSession(); // necesar pentru cache-ul de geo in sesiune
        if (!isAllowedCountry($ip)) {
            return 'geo_blocked';
        }
    }

    // ── 3. Cookie de rate-limit ──────────────────────────────────────────
    $cookieId = getOrSetLoginCookie();

    $window  = defined('LOGIN_WINDOW_SECONDS')  ? (int)LOGIN_WINDOW_SECONDS  : 900;
    $maxAtt  = defined('LOGIN_MAX_ATTEMPTS')     ? (int)LOGIN_MAX_ATTEMPTS    : 5;
    $cooldown = defined('LOGIN_COOLDOWN_SECONDS') ? (int)LOGIN_COOLDOWN_SECONDS : 5;

    // ── 4. Rate-limit per IP ─────────────────────────────────────────────
    $stmt = $db->prepare(
        "SELECT COUNT(*) FROM login_attempts
         WHERE ip=? AND attempted_at > DATE_SUB(NOW(), INTERVAL ? SECOND)"
    );
    $stmt->execute([$ip, $window]);
    if ((int)$stmt->fetchColumn() >= $maxAtt) {
        return 'blocked';
    }

    // ── 5. Rate-limit per cookie ─────────────────────────────────────────
    try {
        $stmt = $db->prepare(
            "SELECT COUNT(*) FROM login_attempts
             WHERE cookie_id=? AND attempted_at > DATE_SUB(NOW(), INTERVAL ? SECOND)"
        );
        $stmt->execute([$cookieId, $window]);
        if ((int)$stmt->fetchColumn() >= $maxAtt) {
            return 'blocked';
        }
    } catch (PDOException $e) {
        // Coloana cookie_id inca nu exista (migrare in curs) — ignoram
    }

    // ── 6. Cooldown de 5 secunde intre incercari ─────────────────────────
    $stmt = $db->prepare(
        "SELECT MAX(attempted_at) FROM login_attempts WHERE ip=?"
    );
    $stmt->execute([$ip]);
    $lastAttempt = $stmt->fetchColumn();
    if ($lastAttempt) {
        $elapsed = time() - strtotime($lastAttempt);
        if ($elapsed < $cooldown) {
            return 'cooldown';
        }
    }

    // ── 7. Verifica credentialele ────────────────────────────────────────
    $stmt = $db->prepare("SELECT id, password_hash FROM users WHERE username=? LIMIT 1");
    $stmt->execute([trim($username)]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        // Succes: sterge incercarile esuale
        $db->prepare("DELETE FROM login_attempts WHERE ip=?")->execute([$ip]);
        try { $db->prepare("DELETE FROM login_attempts WHERE cookie_id=?")->execute([$cookieId]); } catch (PDOException $e) {}

        startSecureSession();
        session_regenerate_id(true);
        $_SESSION['user_id']      = $user['id'];
        $_SESSION['username']     = trim($username);
        $_SESSION['logged_in']    = true;
        $_SESSION['_fingerprint'] = hash('sha256', $ip . ($_SERVER['HTTP_USER_AGENT'] ?? ''));
        $_SESSION['_start_time']  = time();
        return true;
    }

    // Esec: inregistreaza incercarea (cu fallback daca cookie_id nu exista inca)
    try {
        $db->prepare(
            "INSERT INTO login_attempts (ip, cookie_id, username, attempted_at) VALUES (?,?,?,NOW())"
        )->execute([$ip, $cookieId, substr(trim($username), 0, 50)]);
    } catch (PDOException $e) {
        // Fallback fara cookie_id (coloana inca nu a fost migrata)
        try {
            $db->prepare("INSERT INTO login_attempts (ip, username, attempted_at) VALUES (?,?,NOW())")
               ->execute([$ip, substr(trim($username), 0, 50)]);
        } catch (PDOException $e2) {}
    }

    return false;
}

/* ============================================================
   LOGOUT
   ============================================================ */

function logout(): void {
    startSecureSession();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $p['path'], $p['domain'], $p['secure'], $p['httponly']
        );
    }
    session_destroy();
    header('Location: /');
    exit;
}

/* ============================================================
   UTILIZATOR CURENT
   ============================================================ */

function getCurrentUser(): ?array {
    if (!isLoggedIn()) return null;
    $db   = getDB();
    $stmt = $db->prepare("SELECT id, username, phone_number, sms_alerts FROM users WHERE id=?");
    $stmt->execute([$_SESSION['user_id']]);
    return $stmt->fetch() ?: null;
}
