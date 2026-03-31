<?php
// includes/header.php
if (!isset($pageTitle)) $pageTitle = 'Domain Monitor';
$user = getCurrentUser();
$currentPage = basename($_SERVER['PHP_SELF'], '.php');

function userAvatarColor(string $username): string {
    $colors = ['#3b82f6','#8b5cf6','#10b981','#f59e0b','#ef4444','#06b6d4','#ec4899','#84cc16','#f97316','#6366f1'];
    return $colors[abs(crc32($username)) % count($colors)];
}
function userAvatarHtml(string $username, int $size = 32, int $radius = 8, float $fontSize = .875): string {
    $color = userAvatarColor($username);
    $letter = strtoupper(substr($username, 0, 1));
    return "<span style=\"width:{$size}px;height:{$size}px;border-radius:{$radius}px;background:{$color};display:inline-flex;align-items:center;justify-content:center;font-weight:700;font-size:{$fontSize}rem;color:#fff;flex-shrink:0\">{$letter}</span>";
}
?>
<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= htmlspecialchars($pageTitle) ?> — Domain Monitor</title>
<meta property="og:title" content="Domain Monitor">
<meta property="og:description" content="Project by White Hat Technology">
<meta property="og:type" content="website">
<meta property="og:url" content="https://whois.iosub.ro">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e1a;--surface:#111827;--surface2:#1a2234;--border:#1e2d45;
  --accent:#3b82f6;--accent2:#60a5fa;--text:#e2e8f0;--text2:#94a3b8;--text3:#64748b;
  --success:#10b981;--danger:#ef4444;--warning:#f59e0b;--purple:#8b5cf6;--sidebar:240px;
}

/* ===================== LAYOUT ===================== */
html,body{height:100%;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);display:flex;min-height:100vh}
a{color:inherit;text-decoration:none}

/* Sidebar - desktop fix */
.sidebar{
  width:var(--sidebar);min-height:100vh;
  background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  position:fixed;top:0;left:0;z-index:200;
  transition:transform .3s ease;
}
.sidebar-logo{padding:20px 20px 18px;border-bottom:1px solid var(--border);flex-shrink:0}
.sidebar-logo a:hover .sidebar-logo-inner{opacity:.85}
.sidebar-logo-inner{display:flex;align-items:center;gap:10px;transition:.15s}
.sidebar-logo-icon{width:34px;height:34px;flex-shrink:0;display:flex;align-items:center;justify-content:center}
.sidebar-logo-icon svg{width:34px;height:34px}
.sidebar-logo h2{font-size:1rem;font-weight:700;line-height:1.2;white-space:nowrap}
.sidebar-logo h2 span.accent{color:var(--accent2)}
nav{flex:1;padding:16px 12px;overflow-y:auto;overflow-x:hidden}
.nav-section{font-size:.7rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.8px;padding:8px 8px 6px}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:10px;font-size:.875rem;font-weight:500;color:var(--text2);transition:.15s;margin-bottom:2px}
.nav-item:hover{background:var(--surface2);color:var(--text)}
.nav-item.active{background:rgba(59,130,246,.15);color:var(--accent2);border:1px solid rgba(59,130,246,.2)}
.nav-item .icon{width:18px;text-align:center;font-size:16px;flex-shrink:0}
.nav-badge{margin-left:auto;background:var(--accent);color:#fff;font-size:.65rem;font-weight:700;padding:2px 7px;border-radius:999px;flex-shrink:0}
.nav-badge.success{background:var(--success)}
.nav-badge.warning{background:var(--warning)}
.sidebar-footer{padding:10px 14px;border-top:1px solid var(--border);flex-shrink:0}
.sf-row{display:flex;align-items:center;gap:6px}
.user-pill{display:flex;align-items:center;gap:8px;padding:7px 9px;background:var(--surface2);border-radius:9px;flex:1;text-decoration:none;color:inherit;transition:.15s;min-width:0}
.user-pill:hover{background:var(--border)}
.user-avatar{width:28px;height:28px;border-radius:7px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.8rem;flex-shrink:0;color:#fff}
.user-name{font-size:.82rem;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.logout-btn-row{flex-shrink:0;display:flex;align-items:center;gap:5px;padding:7px 10px;border-radius:9px;background:var(--surface2);border:1px solid var(--border);color:var(--text2);cursor:pointer;font-family:inherit;font-size:.78rem;font-weight:500;transition:.15s;white-space:nowrap}
.logout-btn-row:hover{background:rgba(239,68,68,.12);border-color:var(--danger);color:var(--danger)}
.sf-version{font-size:.65rem;color:var(--text3);text-align:center;margin-top:6px;letter-spacing:.3px}

/* Main content */
.main{margin-left:var(--sidebar);flex:1;padding:32px;min-height:100vh}

/* ===================== MOBILE TOPBAR ===================== */
.topbar{
  display:none;
  position:fixed;top:0;left:0;right:0;z-index:150;
  height:56px;
  background:var(--surface);
  border-bottom:1px solid var(--border);
  align-items:center;
  padding:0 16px;
  gap:12px;
}
.topbar-logo{display:flex;align-items:center;gap:8px;flex:1}
.topbar-logo svg{width:26px;height:26px}
.topbar-logo span{font-size:.95rem;font-weight:700}
.topbar-logo span em{color:var(--accent2);font-style:normal}
.hamburger{background:none;border:none;color:var(--text2);cursor:pointer;padding:8px;border-radius:8px;display:flex;flex-direction:column;gap:5px;flex-shrink:0}
.hamburger span{display:block;width:20px;height:2px;background:currentColor;border-radius:2px;transition:.3s}
.hamburger.open span:nth-child(1){transform:translateY(7px) rotate(45deg)}
.hamburger.open span:nth-child(2){opacity:0}
.hamburger.open span:nth-child(3){transform:translateY(-7px) rotate(-45deg)}

/* Overlay pentru mobile menu */
.sidebar-overlay{
  display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);
  z-index:190;opacity:0;transition:opacity .3s;
  pointer-events:none;
}
.sidebar-overlay.visible{opacity:1;pointer-events:all}

/* ===================== COMPONENTS ===================== */
.page-header{margin-bottom:28px}
.page-header h1{font-size:1.5rem;font-weight:700}
.page-header p{color:var(--text2);font-size:.9rem;margin-top:4px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:24px}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:10px}
.card-title{font-size:1rem;font-weight:600}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:28px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:20px;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px}
.stat-card.available::before{background:var(--success)}
.stat-card.registered::before{background:var(--accent)}
.stat-card.pending::before{background:var(--warning)}
.stat-card.total::before{background:var(--purple)}
.stat-label{font-size:.75rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.5px}
.stat-value{font-size:2rem;font-weight:700;margin:8px 0 4px}
.stat-sub{font-size:.8rem;color:var(--text2)}
.badge{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:999px;font-size:.75rem;font-weight:600}
.badge::before{content:'';width:6px;height:6px;border-radius:50%;flex-shrink:0}
.badge.available{background:rgba(16,185,129,.15);color:#34d399;border:1px solid rgba(16,185,129,.25)}.badge.available::before{background:#10b981}
.badge.registered{background:rgba(59,130,246,.15);color:var(--accent2);border:1px solid rgba(59,130,246,.25)}.badge.registered::before{background:var(--accent)}
.badge.pending_delete{background:rgba(245,158,11,.15);color:#fbbf24;border:1px solid rgba(245,158,11,.25)}.badge.pending_delete::before{background:var(--warning);animation:blink 1s ease-in-out infinite}
.badge.error{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.25)}.badge.error::before{background:var(--danger)}
.badge.unknown{background:rgba(100,116,139,.15);color:var(--text2);border:1px solid rgba(100,116,139,.2)}.badge.unknown::before{background:var(--text3)}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}

/* ===================== TABLE ===================== */
/* Scrollbar orizontal stilizat dark - se potriveste cu tema */
.table-wrap{
  overflow-x:auto;
  -webkit-overflow-scrolling:touch;
  /* Scrollbar dark pentru Chrome/Edge/Safari */
  scrollbar-width:thin;
  scrollbar-color:var(--border) transparent;
}
.table-wrap::-webkit-scrollbar{height:6px}
.table-wrap::-webkit-scrollbar-track{background:transparent}
.table-wrap::-webkit-scrollbar-thumb{background:var(--border);border-radius:999px}
.table-wrap::-webkit-scrollbar-thumb:hover{background:var(--text3)}

table{width:100%;border-collapse:collapse;min-width:600px}
th{text-align:left;font-size:.75rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;padding:10px 16px;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:12px 16px;border-bottom:1px solid rgba(30,45,69,.6);font-size:.875rem}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}

/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:9px;font-size:.875rem;font-weight:500;cursor:pointer;transition:.15s;border:none;font-family:inherit;white-space:nowrap}
.btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:#2563eb}
.btn-success{background:var(--success);color:#fff}.btn-success:hover{background:#059669}
.btn-danger{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.2)}.btn-danger:hover{background:var(--danger);color:#fff}
.btn-ghost{background:transparent;color:var(--text2);border:1px solid var(--border)}.btn-ghost:hover{background:var(--surface2);color:var(--text)}
.btn-sm{padding:6px 12px;font-size:.8rem}
.btn-icon{padding:7px 10px}

/* Forms */
.form-group{display:flex;flex-direction:column;gap:6px}
.form-label{font-size:.8rem;font-weight:500;color:var(--text2);text-transform:uppercase;letter-spacing:.3px}
.form-input,.form-select,.form-textarea{background:var(--surface2);border:1px solid var(--border);border-radius:9px;padding:11px 14px;color:var(--text);font-size:.9rem;font-family:inherit;transition:.15s;width:100%}
.form-input:focus,.form-select:focus,.form-textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.1)}
.form-textarea{resize:vertical;min-height:80px}
.form-hint{font-size:.78rem;color:var(--text3)}

/* Alerts */
.alert{padding:12px 16px;border-radius:10px;font-size:.875rem;margin-bottom:20px;display:flex;align-items:flex-start;gap:10px}
.alert-success{background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);color:#6ee7b7}
.alert-danger{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5}
.alert-warning{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);color:#fcd34d}
.alert-info{background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.3);color:#93c5fd}

/* Modals */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:500;display:flex;align-items:center;justify-content:center;padding:16px;opacity:0;pointer-events:none;transition:.2s}
.modal-overlay.open{opacity:1;pointer-events:all}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;width:100%;max-width:540px;padding:24px;transform:scale(.95);transition:.2s;max-height:90vh;overflow-y:auto}
.modal-overlay.open .modal{transform:scale(1)}
.modal-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.modal-title{font-size:1.1rem;font-weight:600}
.modal-close{background:none;border:none;color:var(--text2);font-size:1.2rem;cursor:pointer;padding:4px;line-height:1;flex-shrink:0}
.modal-close:hover{color:var(--text)}
.modal-footer{display:flex;justify-content:flex-end;gap:10px;margin-top:20px;flex-wrap:wrap}

/* Misc */
.empty-state{text-align:center;padding:48px 24px;color:var(--text2)}
.empty-icon{font-size:3rem;margin-bottom:12px}
.text-success{color:var(--success)}.text-danger{color:var(--danger)}.text-warning{color:var(--warning)}
.flex{display:flex}.items-center{align-items:center}.justify-between{justify-content:space-between}.gap-2{gap:8px}.gap-3{gap:12px}
.mt-2{margin-top:8px}.mt-4{margin-top:16px}.mb-4{margin-bottom:16px}
.text-sm{font-size:.85rem}.text-xs{font-size:.75rem}.text-muted{color:var(--text2)}
.domain-name{font-family:monospace;font-size:.9rem;font-weight:600}

/* Tooltip global - z-index 9999 */
.whois-tooltip-wrap{position:relative;display:inline-flex;align-items:center;gap:5px}
.whois-tooltip{position:absolute;left:0;top:calc(100% + 6px);z-index:9999;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:10px 12px;min-width:180px;max-width:280px;box-shadow:0 12px 32px rgba(0,0,0,.6);opacity:0;pointer-events:none;transform:translateY(-4px);transition:opacity .15s,transform .15s;white-space:nowrap}
.whois-tooltip-wrap:hover .whois-tooltip{opacity:1;pointer-events:all;transform:translateY(0)}
.whois-info-dot{display:inline-flex;align-items:center;justify-content:center;width:15px;height:15px;border-radius:50%;background:rgba(59,130,246,.2);border:1px solid rgba(59,130,246,.4);color:var(--accent2);font-size:9px;font-weight:700;cursor:pointer;flex-shrink:0;transition:.15s}
.whois-info-dot:hover{background:rgba(59,130,246,.4)}
.whois-tooltip-title{font-size:.7rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.whois-tooltip-tag{display:inline-block;font-size:.72rem;padding:2px 7px;border-radius:4px;background:var(--surface2);color:var(--text2);border:1px solid var(--border);margin:2px 2px 2px 0}
.whois-tooltip-tag.danger{background:rgba(239,68,68,.15);color:#fca5a5;border-color:rgba(239,68,68,.3)}
.whois-tooltip-tag.warning{background:rgba(245,158,11,.15);color:#fbbf24;border-color:rgba(245,158,11,.3)}
.whois-tooltip-tag.ok{background:rgba(16,185,129,.1);color:#6ee7b7;border-color:rgba(16,185,129,.2)}

/* Pulse dot */
.pulse-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--success);box-shadow:0 0 0 0 rgba(16,185,129,.4);animation:pulse-ring 1.5s infinite}
@keyframes pulse-ring{0%{box-shadow:0 0 0 0 rgba(16,185,129,.4)}70%{box-shadow:0 0 0 8px rgba(16,185,129,0)}100%{box-shadow:0 0 0 0 rgba(16,185,129,0)}}

/* ===================== RESPONSIVE ===================== */
@media(max-width:768px){
  .topbar{display:flex}
  .sidebar{transform:translateX(-100%);pointer-events:none}
  .sidebar.open{transform:translateX(0);pointer-events:all}
  .sidebar-overlay{display:block;pointer-events:none}
  .main{margin-left:0;padding:16px;padding-top:72px}
  .page-header{margin-bottom:20px}
  .page-header h1{font-size:1.2rem}
  .card{padding:16px}
  .stats-grid{grid-template-columns:1fr 1fr;gap:10px;margin-bottom:20px}
  .stat-value{font-size:1.6rem}
  .btn{padding:8px 14px;font-size:.82rem}
  .btn-sm{padding:5px 10px;font-size:.78rem}
  .btn-icon{padding:7px 9px}
  .modal{padding:18px;border-radius:12px;max-height:85vh}
  .modal-footer{justify-content:stretch}
  .modal-footer .btn{flex:1;justify-content:center}
  .modal [style*="grid-template-columns"]{grid-template-columns:1fr !important}
  .hide-mobile{display:none!important}
  .flex-wrap-mobile{flex-wrap:wrap}
  .topbar-alerts{
    display:flex;align-items:center;gap:6px;
    background:var(--surface2);border:1px solid var(--border);
    border-radius:8px;padding:5px 10px;font-size:.78rem;color:var(--text2);
    text-decoration:none;
  }
}

@media(max-width:480px){
  .stats-grid{grid-template-columns:1fr 1fr}
  .stat-value{font-size:1.4rem}
  .main{padding:12px;padding-top:68px}
  .card{padding:14px;border-radius:12px}
  .btn-icon{padding:6px 8px;font-size:.8rem}
}
</style>
</head>
<body>

<!-- TOPBAR MOBILE -->
<div class="topbar" id="topbar">
  <button class="hamburger" id="hamburgerBtn" onclick="toggleSidebar()" aria-label="Meniu">
    <span></span><span></span><span></span>
  </button>
  <a href="/dashboard" class="topbar-logo">
    <svg viewBox="0 0 34 34" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="17" cy="17" r="16" stroke="#3b82f6" stroke-width="1.5" opacity="0.3"/>
      <circle cx="17" cy="17" r="11" stroke="#3b82f6" stroke-width="1.5" opacity="0.5"/>
      <circle cx="17" cy="17" r="6" stroke="#60a5fa" stroke-width="1.5"/>
      <circle cx="17" cy="17" r="2" fill="#60a5fa"/>
      <line x1="17" y1="17" x2="28" y2="6" stroke="#60a5fa" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
      <circle cx="26" cy="8" r="2" fill="#10b981"/>
      <circle cx="26" cy="8" r="4" stroke="#10b981" stroke-width="1" opacity="0.4"/>
    </svg>
    <span>Domain <em>Monitor</em></span>
  </a>
  <?php
    try {
      $db2 = getDB();
      $availM = $db2->query("SELECT COUNT(*) FROM domains WHERE current_status='available' AND monitoring_active=1")->fetchColumn();
      if ($availM > 0) {
        echo "<a href='/domains?filter=available' class='topbar-alerts' style='color:var(--success);border-color:rgba(16,185,129,.3)'>";
        echo "<span style='width:8px;height:8px;background:var(--success);border-radius:50%;display:inline-block'></span> $availM disponibil";
        echo "</a>";
      }
    } catch(Exception $e){}
  ?>
</div>

<!-- OVERLAY MOBILE -->
<div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>

<!-- SIDEBAR -->
<aside class="sidebar" id="sidebar">
  <div class="sidebar-logo">
    <a href="/dashboard" style="text-decoration:none;color:inherit;display:block" onclick="closeSidebarMobile()">
      <div class="sidebar-logo-inner">
        <div class="sidebar-logo-icon">
          <svg viewBox="0 0 34 34" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="17" cy="17" r="16" stroke="#3b82f6" stroke-width="1.5" opacity="0.3"/>
            <circle cx="17" cy="17" r="11" stroke="#3b82f6" stroke-width="1.5" opacity="0.5"/>
            <circle cx="17" cy="17" r="6" stroke="#60a5fa" stroke-width="1.5"/>
            <circle cx="17" cy="17" r="2" fill="#60a5fa"/>
            <line x1="17" y1="17" x2="28" y2="6" stroke="#60a5fa" stroke-width="1.5" stroke-linecap="round" opacity="0.8"/>
            <circle cx="26" cy="8" r="2" fill="#10b981"/>
            <circle cx="26" cy="8" r="4" stroke="#10b981" stroke-width="1" opacity="0.4"/>
          </svg>
        </div>
        <h2>Domain <span class="accent">Monitor</span></h2>
      </div>
    </a>
  </div>
  <nav>
    <?php try { $db = getDB(); } catch(Exception $e) { $db = null; } ?>

    <div class="nav-section">Principal</div>
    <a href="/dashboard" class="nav-item <?= $currentPage === 'dashboard' ? 'active' : '' ?>" onclick="closeSidebarMobile()">
      <span class="icon">&#128202;</span> Dashboard
    </a>

    <div class="nav-section" style="margin-top:14px">Domenii</div>
    <a href="/domains" class="nav-item <?= $currentPage === 'domains' ? 'active' : '' ?>" onclick="closeSidebarMobile()">
      <span class="icon">&#127760;</span> Domenii
      <?php try {
          $avail = $db->query("SELECT COUNT(*) FROM domains WHERE current_status='available' AND monitoring_active=1")->fetchColumn();
          $total = $db->query("SELECT COUNT(*) FROM domains WHERE monitoring_active=1")->fetchColumn();
          if ($avail > 0) echo "<span class='nav-badge success'>$avail</span>";
          elseif ($total > 0) echo "<span class='nav-badge'>$total</span>";
      } catch(Exception $e){} ?>
    </a>
    <a href="/alerts" class="nav-item <?= $currentPage === 'alerts' ? 'active' : '' ?>" onclick="closeSidebarMobile()">
      <span class="icon">&#128241;</span> Alerte SMS
      <?php try {
          $today = $db->query("SELECT COUNT(*) FROM sms_alerts WHERE DATE(sent_at)=CURDATE()")->fetchColumn();
          if ($today > 0) echo "<span class='nav-badge'>$today</span>";
      } catch(Exception $e){} ?>
    </a>
    <a href="/history" class="nav-item <?= $currentPage === 'history' ? 'active' : '' ?>" onclick="closeSidebarMobile()">
      <span class="icon">&#128203;</span> Istoric Stari
    </a>

    <div class="nav-section" style="margin-top:14px">Monitorizare</div>
    <a href="/uptime" class="nav-item <?= $currentPage === 'uptime' ? 'active' : '' ?>" onclick="closeSidebarMobile()">
      <span class="icon">&#128268;</span> Uptime Monitor
      <?php try {
          $down = $db->query("SELECT COUNT(*) FROM uptime_monitors WHERE current_status='down' AND monitoring_active=1")->fetchColumn();
          if ($down > 0) echo "<span class='nav-badge' style='background:var(--danger)'>$down</span>";
      } catch(Exception $e){} ?>
    </a>

    <div class="nav-section" style="margin-top:14px">Unelte</div>
    <a href="/lookup" class="nav-item <?= $currentPage === 'lookup' ? 'active' : '' ?>" onclick="closeSidebarMobile()">
      <span class="icon">&#128270;</span> WHOIS Lookup
    </a>
    <a href="/network" class="nav-item <?= $currentPage === 'network' ? 'active' : '' ?>" onclick="closeSidebarMobile()">
      <span class="icon">&#128225;</span> IP / NS Lookup
    </a>
    <a href="/timeline" class="nav-item <?= $currentPage === 'timeline' ? 'active' : '' ?>" onclick="closeSidebarMobile()">
      <span class="icon">&#128336;</span> Timeline
    </a>

    <div class="nav-section" style="margin-top:14px">Sistem</div>
    <?php if (function_exists('isAdmin') && isAdmin()): ?>
    <a href="/users" class="nav-item <?= $currentPage === 'users' ? 'active' : '' ?>" onclick="closeSidebarMobile()">
      <span class="icon">&#128100;</span> Utilizatori
      <?php try {
          $uc = $db->query("SELECT COUNT(*) FROM users")->fetchColumn();
          if ($uc > 1) echo "<span class='nav-badge'>$uc</span>";
      } catch(Exception $e){} ?>
    </a>
    <?php endif; ?>
    <a href="/settings" class="nav-item <?= $currentPage === 'settings' ? 'active' : '' ?>" onclick="closeSidebarMobile()">
      <span class="icon">&#9881;</span> Setari
    </a>
  </nav>
  <div class="sidebar-footer">
    <div class="sf-row">
      <a href="/settings" class="user-pill" onclick="closeSidebarMobile()">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;color:var(--text3)"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        <div class="user-name"><?= htmlspecialchars($user['username'] ?? '') ?></div>
      </a>
      <form method="post" action="/logout" style="flex-shrink:0">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">
        <button type="submit" class="logout-btn-row">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
          Iesire
        </button>
      </form>
    </div>
    <div class="sf-version">v<?= APP_VERSION ?></div>
  </div>
</aside>

<main class="main">

<script>
function toggleSidebar() {
  const sidebar   = document.getElementById('sidebar');
  const overlay   = document.getElementById('sidebarOverlay');
  const hamburger = document.getElementById('hamburgerBtn');
  const isOpen    = sidebar.classList.contains('open');
  if (isOpen) {
    sidebar.classList.remove('open');
    overlay.classList.remove('visible');
    hamburger.classList.remove('open');
    document.body.style.overflow = '';
  } else {
    sidebar.classList.add('open');
    overlay.classList.add('visible');
    hamburger.classList.add('open');
    document.body.style.overflow = 'hidden';
  }
}
function closeSidebarMobile() {
  if (window.innerWidth <= 768) {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebarOverlay').classList.remove('visible');
    document.getElementById('hamburgerBtn').classList.remove('open');
    document.body.style.overflow = '';
  }
}
window.addEventListener('resize', function() {
  if (window.innerWidth > 768) {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebarOverlay').classList.remove('visible');
    document.getElementById('hamburgerBtn').classList.remove('open');
    document.body.style.overflow = '';
  }
});
</script>
