<?php
require_once 'config.php';
require_once 'includes/auth.php';

if (isLoggedIn()) {
    header('Location: /dashboard');
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (empty($token) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        $error = 'Cerere invalida. Reincearca.';
    } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if (empty($username) || empty($password)) {
            $error = 'Completati toate campurile.';
        } else {
            $result = login($username, $password);
            if ($result === true) {
                header('Location: /dashboard');
                exit;
            } elseif ($result === 'geo_blocked') {
                $error = 'Autentificarea este permisa doar din Romania. IP-ul dvs. nu este autorizat.';
            } elseif ($result === 'cooldown') {
                $error = 'Asteptati cel putin 5 secunde intre incercari.';
            } elseif ($result === 'blocked') {
                $error = 'Prea multe incercari esuate. Asteptati 15 minute.';
            } else {
                $error = 'Credentiale incorecte.';
            }
        }
    }
}

$csrfToken = getCsrfToken();
?>
<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DomainWatch — Autentificare</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e1a;--surface:#111827;--surface2:#1a2234;--border:#1e2d45;
  --accent:#3b82f6;--text:#e2e8f0;--text2:#94a3b8;--danger:#ef4444;
}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.login-wrap{width:100%;max-width:420px;position:relative;z-index:1}
.logo{text-align:center;margin-bottom:40px}
.logo-icon{width:56px;height:56px;background:linear-gradient(135deg,var(--accent),#8b5cf6);border-radius:16px;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;font-size:24px}
.logo h1{font-size:1.75rem;font-weight:700;letter-spacing:-.5px}
.logo p{color:var(--text2);font-size:.9rem;margin-top:6px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:36px}
.form-group{margin-bottom:20px}
label{display:block;font-size:.85rem;font-weight:500;color:var(--text2);margin-bottom:8px;letter-spacing:.3px;text-transform:uppercase}
input[type=text],input[type=password]{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:13px 16px;color:var(--text);font-size:.95rem;font-family:inherit;transition:.2s}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.btn{width:100%;padding:14px;background:linear-gradient(135deg,var(--accent),#6366f1);border:none;border-radius:10px;color:#fff;font-size:1rem;font-weight:600;cursor:pointer;transition:.2s;font-family:inherit;margin-top:4px}
.btn:hover{opacity:.9;transform:translateY(-1px)}
.error{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;padding:12px 16px;border-radius:10px;font-size:.875rem;margin-bottom:20px}
.particles{position:fixed;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:0;overflow:hidden}
.particle{position:absolute;background:var(--accent);border-radius:50%;animation:float linear infinite;opacity:.2}
@keyframes float{from{transform:translateY(100vh);opacity:.2}to{transform:translateY(-100px);opacity:0}}
</style>
</head>
<body>
<div class="particles" id="particles"></div>
<div class="login-wrap">
  <div class="logo">
    <div class="logo-icon">&#128301;</div>
    <h1>DomainWatch</h1>
    <p>Monitorizare disponibilitate domenii</p>
  </div>
  <div class="card">
    <?php if ($error): ?>
      <div class="error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <form method="post" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
      <div class="form-group">
        <label>Utilizator</label>
        <input type="text" name="username" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" placeholder="username" autofocus required maxlength="50">
      </div>
      <div class="form-group">
        <label>Parola</label>
        <input type="password" name="password" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
      </div>
      <button type="submit" class="btn">Autentificare &rarr;</button>
    </form>
  </div>
</div>
<script>
const p = document.getElementById('particles');
for(let i=0;i<20;i++){
  const el=document.createElement('div');
  el.className='particle';
  const s=1+Math.random()*2;
  el.style.cssText=`left:${Math.random()*100}%;width:${s}px;height:${s}px;animation-duration:${10+Math.random()*15}s;animation-delay:${Math.random()*10}s`;
  p.appendChild(el);
}
</script>
</body>
</html>
