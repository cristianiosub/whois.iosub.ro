<?php
require_once 'config.php';
require_once 'includes/auth.php';

// Permite logout doar prin POST cu token CSRF valid
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /');
    exit;
}
startSecureSession();
$token = $_POST['csrf_token'] ?? '';
if (empty($token) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
    header('Location: /dashboard');
    exit;
}
logout();
