<?php
require_once 'config.php';
require_once 'includes/auth.php';
require_once 'includes/db.php';
require_once 'includes/whois.php';
require_once 'includes/intelligence.php';
requireLogin();

$db        = getDB();
$csrfToken = getCsrfToken();
$pageTitle = 'WHOIS Lookup';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // CSRF obligatoriu doar pentru actiunile care modifica starea.
    // Cererile AJAX read-only (whois_check, intel_section, batch_check)
    // nu rotesc tokenul — altfel cererile paralele ar primi 403.
    $stateMutatingActions = ['add_to_monitor'];
    if (in_array($action, $stateMutatingActions, true)) {
        validateCsrf();
    }

    if ($action === 'add_to_monitor') {
        $d       = strtolower(trim($_POST['domain'] ?? ''));
        $label   = in_array($_POST['label'] ?? '', array_keys(LABELS)) ? $_POST['label'] : null;
        $notes   = trim($_POST['notes'] ?? '');
        $dtype   = ($_POST['domain_type'] ?? 'monitor') === 'owned' ? 'owned' : 'monitor';
        $expires = !empty($_POST['expires_on']) ? $_POST['expires_on'] : null;
        $interval = $label ? LABELS[$label]['interval'] : 5;
        if (isValidDomain($d)) {
            try {
                $tld = extractTld($d);
                $db->prepare("INSERT INTO domains (domain, tld, notes, label, check_interval_minutes, domain_type, expires_on, added_by) VALUES (?,?,?,?,?,?,?,?)")
                   ->execute([$d, $tld, $notes, $label, $interval, $dtype, $expires, $_SESSION['user_id']]);
                header('Location: /domains');
                exit;
            } catch (PDOException $e) {
                $addError = ($e->getCode() === '23000') ? 'Domeniu deja in lista.' : 'Eroare la salvare. Incearca din nou.';
            }
        }
    }

    if ($action === 'whois_check') {
        header('Content-Type: application/json');
        $d = strtolower(trim($_POST['domain'] ?? ''));
        $d = preg_replace('/^(https?:\/\/)?(www\.)?/', '', $d);
        $d = rtrim($d, '/');
        if (!isValidDomain($d)) { echo json_encode(['error' => 'Domeniu invalid']); exit; }
        $result = checkDomain($d);
        $chk = $db->prepare("SELECT id FROM domains WHERE domain=?");
        $chk->execute([$d]);
        $existing = $chk->fetch();
        echo json_encode([
            'domain'         => $d,
            'status'         => $result['status'],
            'registrar'      => $result['registrar'],
            'registered_on'  => $result['registered_on'],
            'expires_on'     => $result['expires_on'],
            'whois_statuses' => $result['whois_statuses'],
            'raw'            => $result['raw'],
            'already_in'     => $existing ? $d : false,
        ]);
        exit;
    }

    if ($action === 'intel_section') {
        header('Content-Type: application/json');
        $d       = strtolower(trim($_POST['domain'] ?? ''));
        $section = $_POST['section'] ?? '';
        $d = preg_replace('/^(https?:\/\/)?(www\.)?/', '', $d);
        $d = rtrim($d, '/');
        if (!isValidDomain($d)) { echo json_encode(['error' => 'Domeniu invalid']); exit; }

        set_time_limit(30);
        $data = match($section) {
            'dns'     => getDnsRecords($d),
            'ssl'     => getSslInfo($d),
            'email'   => getEmailSecurity($d),
            'hosting' => getHostingInfo($d),
            'subdoms' => getSubdomains($d),
            'ports'   => getOpenPorts($d),
            'history' => getDomainHistory($d),
            'tech'    => getTechFingerprint($d),
            'infra'   => getDbInfraMatches($d, $db),
            default   => ['error' => 'Sectiune invalida'],
        };
        echo json_encode($data);
        exit;
    }

    if ($action === 'batch_check') {
        header('Content-Type: application/json');
        $d = strtolower(trim($_POST['domain'] ?? ''));
        $d = preg_replace('/^(https?:\/\/)?(www\.)?/', '', $d);
        $d = rtrim($d, '/');
        if (!isValidDomain($d)) { echo json_encode(['domain' => $d, 'error' => 'Invalid']); exit; }
        $result = checkDomain($d);
        $chk = $db->prepare("SELECT id FROM domains WHERE domain=?");
        $chk->execute([$d]);
        $existing = $chk->fetch();
        echo json_encode([
            'domain'         => $d,
            'status'         => $result['status'],
            'registrar'      => $result['registrar'],
            'expires_on'     => $result['expires_on'],
            'whois_statuses' => $result['whois_statuses'],
            'already_in'     => $existing ? $d : false,
        ]);
        exit;
    }
}

$recentDomains = $db->query("SELECT domain, current_status FROM domains ORDER BY last_checked_at DESC LIMIT 16")->fetchAll();

include 'includes/header.php';
?>

<style>
.lookup-hero{background:linear-gradient(135deg,rgba(59,130,246,.08),rgba(139,92,246,.06));border:1px solid var(--border);border-radius:16px;padding:36px 40px;margin-bottom:24px;text-align:center;position:relative;overflow:hidden}
.lookup-hero::before{content:'';position:absolute;top:-60%;left:50%;transform:translateX(-50%);width:500px;height:500px;background:radial-gradient(circle,rgba(59,130,246,.05) 0%,transparent 70%);pointer-events:none}
.lookup-hero h2{font-size:1.4rem;font-weight:700;margin-bottom:6px}
.lookup-hero p{color:var(--text2);font-size:.9rem;margin-bottom:24px}
.lookup-tabs{display:flex;gap:8px;justify-content:center;margin-bottom:20px}
.lookup-tab{padding:7px 18px;border-radius:8px;font-size:.85rem;font-weight:500;cursor:pointer;border:1px solid var(--border);background:transparent;color:var(--text2);font-family:inherit;transition:.15s}
.lookup-tab.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.lookup-form{display:flex;gap:10px;max-width:640px;margin:0 auto}
.lookup-input{flex:1;background:var(--surface);border:1.5px solid var(--border);border-radius:12px;padding:13px 18px;color:var(--text);font-size:1rem;font-family:monospace;transition:.2s}
.lookup-input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.lookup-btn{padding:13px 28px;background:var(--accent);border:none;border-radius:12px;color:#fff;font-size:.95rem;font-weight:600;cursor:pointer;font-family:inherit;transition:.2s;display:flex;align-items:center;gap:8px;white-space:nowrap}
.lookup-btn:hover{background:#2563eb}
.lookup-btn:disabled{opacity:.6;cursor:not-allowed}
.result-card{border-radius:14px;border:1px solid var(--border);overflow:hidden;margin-bottom:16px;animation:fadeUp .25s ease}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.result-header{padding:20px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.result-header.available{background:linear-gradient(135deg,rgba(16,185,129,.12),rgba(16,185,129,.04));border-bottom:1px solid rgba(16,185,129,.2)}
.result-header.registered{background:linear-gradient(135deg,rgba(59,130,246,.1),rgba(59,130,246,.03));border-bottom:1px solid rgba(59,130,246,.2)}
.result-header.pending_delete{background:linear-gradient(135deg,rgba(245,158,11,.12),rgba(245,158,11,.04));border-bottom:1px solid rgba(245,158,11,.2)}
.result-header.error,.result-header.unknown{background:linear-gradient(135deg,rgba(239,68,68,.08),rgba(239,68,68,.02));border-bottom:1px solid rgba(239,68,68,.15)}
.result-domain{font-family:monospace;font-size:1.4rem;font-weight:700}
.result-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));background:var(--surface)}
.result-field{padding:14px 20px;border-right:1px solid var(--border);border-bottom:1px solid var(--border)}
.result-field:last-child{border-right:none}
.result-field-label{font-size:.7rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px}
.result-field-value{font-size:.88rem;font-weight:500;color:var(--text)}
.result-field-value.mono{font-family:monospace}
.result-field-value.muted{color:var(--text2)}
.ws-tag{display:inline-block;font-size:.7rem;padding:2px 7px;border-radius:4px;background:var(--surface2);color:var(--text2);border:1px solid var(--border);margin:2px 2px 0 0}
.ws-tag.danger{background:rgba(239,68,68,.15);color:#fca5a5;border-color:rgba(239,68,68,.3)}
.ws-tag.warning{background:rgba(245,158,11,.15);color:#fbbf24;border-color:rgba(245,158,11,.3)}
.ws-tag.ok{background:rgba(16,185,129,.1);color:#6ee7b7;border-color:rgba(16,185,129,.2)}
.result-actions{padding:14px 20px;background:var(--surface2);display:flex;align-items:center;gap:10px;flex-wrap:wrap;border-top:1px solid var(--border)}
.whois-raw-wrap{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:14px 16px;font-family:monospace;font-size:.77rem;color:var(--text2);max-height:260px;overflow-y:auto;white-space:pre-wrap;line-height:1.6;margin-top:14px}
.intel-panel{margin-bottom:16px}
.intel-section{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:10px;animation:fadeUp .2s ease}
.intel-section-header{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;cursor:pointer;user-select:none;transition:.15s}
.intel-section-header:hover{background:var(--surface2)}
.intel-section-title{display:flex;align-items:center;gap:10px;font-weight:600;font-size:.9rem}
.intel-section-icon{width:28px;height:28px;border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.intel-section-body{padding:0 18px 16px;display:none}
.intel-section.open .intel-section-body{display:block}
.intel-section.open .intel-chevron{transform:rotate(180deg)}
.intel-chevron{transition:transform .2s;color:var(--text3);font-size:.8rem}
.intel-badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:600}
.intel-badge.ok{background:rgba(16,185,129,.15);color:#6ee7b7;border:1px solid rgba(16,185,129,.25)}
.intel-badge.warn{background:rgba(245,158,11,.15);color:#fbbf24;border:1px solid rgba(245,158,11,.25)}
.intel-badge.bad{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.25)}
.intel-badge.info{background:rgba(59,130,246,.15);color:var(--accent2);border:1px solid rgba(59,130,246,.25)}
.intel-badge.neutral{background:var(--surface2);color:var(--text2);border:1px solid var(--border)}
.dns-table{width:100%;border-collapse:collapse;font-size:.83rem}
.dns-table td,.dns-table th{padding:7px 10px;text-align:left;border-bottom:1px solid rgba(30,45,69,.5)}
.dns-table tr:last-child td{border-bottom:none}
.dns-table th{color:var(--text3);font-size:.72rem;text-transform:uppercase;letter-spacing:.4px;font-weight:600}
.dns-table .mono{font-family:monospace;color:var(--accent2)}
.dns-table .provider{color:var(--text2);font-size:.78rem}
.email-score{display:flex;gap:6px;margin-bottom:14px}
.email-score-item{flex:1;padding:10px 12px;border-radius:8px;text-align:center;border:1px solid var(--border)}
.email-score-item .label{font-size:.7rem;color:var(--text3);text-transform:uppercase;font-weight:600;margin-bottom:4px}
.email-score-item .val{font-size:.85rem;font-weight:600}
.email-score-item.pass{background:rgba(16,185,129,.08);border-color:rgba(16,185,129,.2)}
.email-score-item.fail{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.2)}
.email-score-item.pass .val{color:#6ee7b7}
.email-score-item.fail .val{color:#fca5a5}
.port-row{display:flex;align-items:center;justify-content:space-between;padding:8px 10px;border-radius:8px;margin-bottom:4px;background:var(--surface2)}
.port-row.risk-high{background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2)}
.port-row.risk-medium{background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2)}
.port-row.risk-low{background:rgba(16,185,129,.06);border:1px solid rgba(16,185,129,.15)}
.port-num{font-family:monospace;font-weight:700;font-size:.85rem}
.port-name{color:var(--text2);font-size:.82rem}
.subdomain-grid{display:flex;flex-wrap:wrap;gap:6px}
.subdomain-chip{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:4px 10px;font-family:monospace;font-size:.78rem;color:var(--text2)}
.ssl-days{font-size:1.4rem;font-weight:700}
.ssl-days.ok{color:var(--success)}
.ssl-days.warn{color:var(--warning)}
.ssl-days.bad{color:var(--danger)}
.hosting-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.hosting-item{padding:10px 12px;background:var(--surface2);border-radius:8px}
.hosting-item .label{font-size:.7rem;color:var(--text3);text-transform:uppercase;font-weight:600;margin-bottom:4px}
.hosting-item .val{font-size:.85rem;font-weight:500}
.intel-loading{padding:20px;text-align:center;color:var(--text3);font-size:.85rem}
.intel-loading .spinner-sm{width:16px;height:16px;border-width:2px;display:inline-block;margin-right:8px;vertical-align:middle}
.batch-textarea{width:100%;background:var(--surface);border:1.5px solid var(--border);border-radius:12px;padding:14px 18px;color:var(--text);font-size:.9rem;font-family:monospace;min-height:140px;resize:vertical;transition:.2s}
.batch-textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.batch-bar-wrap{height:6px;background:var(--surface2);border-radius:999px;overflow:hidden;margin-bottom:10px}
.batch-bar{height:100%;background:var(--accent);border-radius:999px;width:0;transition:width .3s}
.batch-table{width:100%;border-collapse:collapse}
.batch-table th{text-align:left;font-size:.72rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.5px;padding:8px 12px;border-bottom:1px solid var(--border)}
.batch-table td{padding:10px 12px;border-bottom:1px solid rgba(30,45,69,.5);font-size:.85rem}
.batch-table tr:last-child td{border-bottom:none}
.recent-chip{display:inline-flex;align-items:center;gap:5px;padding:4px 11px;background:var(--surface2);border:1px solid var(--border);border-radius:999px;font-size:.78rem;font-family:monospace;color:var(--text2);cursor:pointer;transition:.15s;text-decoration:none}
.recent-chip:hover{background:var(--surface);color:var(--text);border-color:var(--accent)}
.spinner-sm{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.25);border-top-color:var(--accent2);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle}
.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
</style>

<div class="page-header">
    <h1>&#128270; WHOIS Lookup</h1>
    <p>WHOIS, Intelligence OSINT, Batch check</p>
</div>

<div class="lookup-hero">
    <h2>Domain Lookup & Intelligence</h2>
    <p>WHOIS simplu, raport tehnic complet sau verificare bulk</p>
    <div class="lookup-tabs">
        <button class="lookup-tab active" onclick="switchTab('single',this)">Single WHOIS</button>
        <button class="lookup-tab" onclick="switchTab('intel',this)">&#128202; Intelligence</button>
        <button class="lookup-tab" onclick="switchTab('batch',this)">Batch</button>
    </div>

    <div id="tabSingle">
        <div class="lookup-form">
            <input type="text" id="singleInput" class="lookup-input" placeholder="exemplu.ro"
                   autocomplete="off" spellcheck="false" maxlength="255"
                   onkeydown="if(event.key==='Enter')doSingleLookup()">
            <button class="lookup-btn" id="singleBtn" onclick="doSingleLookup()">
                <span id="singleBtnText">Verifica</span>
            </button>
        </div>
    </div>

    <div id="tabIntel" style="display:none">
        <div class="lookup-form">
            <input type="text" id="intelInput" class="lookup-input" placeholder="exemplu.ro"
                   autocomplete="off" spellcheck="false" maxlength="255"
                   onkeydown="if(event.key==='Enter')doIntelLookup()">
            <button class="lookup-btn" id="intelBtn" onclick="doIntelLookup()">
                <span id="intelBtnText">&#128202; Analizeaza</span>
            </button>
        </div>
    </div>

    <div id="tabBatch" style="display:none;max-width:640px;margin:0 auto">
        <textarea id="batchInput" class="batch-textarea" placeholder="domeniu1.ro&#10;domeniu2.com&#10;domeniu3.net"></textarea>
        <div style="margin-top:10px">
            <button class="lookup-btn" style="margin:0 auto" id="batchBtn" onclick="doBatchLookup()">Verifica toate</button>
        </div>
    </div>
</div>

<div id="singleResult" style="display:none"></div>
<div id="intelResult" style="display:none"></div>

<div id="batchProgress" style="display:none">
    <div class="card">
        <div class="card-header">
            <div class="card-title">Rezultate Batch</div>
            <span id="batchCounter" class="text-sm text-muted"></span>
        </div>
        <div class="batch-bar-wrap"><div class="batch-bar" id="batchBar"></div></div>
        <div class="table-wrap">
            <table class="batch-table">
                <thead><tr><th>Domeniu</th><th>Status</th><th>Registrar</th><th>Expira</th><th>Actiuni</th></tr></thead>
                <tbody id="batchTbody"></tbody>
            </table>
        </div>
    </div>
</div>

<?php if (!empty($recentDomains)): ?>
<div class="card">
    <div class="card-header"><div class="card-title">&#128336; Domenii Recente</div></div>
    <div style="display:flex;flex-wrap:wrap;gap:8px;padding:4px 0">
        <?php foreach ($recentDomains as $r):
            $dotColor = ['available'=>'#10b981','registered'=>'#3b82f6','pending_delete'=>'#f59e0b','error'=>'#ef4444'][$r['current_status']] ?? '#64748b';
        ?>
        <a href="javascript:void(0)" class="recent-chip" onclick="quickLookup('<?= htmlspecialchars($r['domain']) ?>')">
            <span style="width:6px;height:6px;border-radius:50%;background:<?= $dotColor ?>;display:inline-block"></span>
            <?= htmlspecialchars($r['domain']) ?>
        </a>
        <?php endforeach; ?>
    </div>
</div>
<?php endif; ?>

<div class="modal-overlay" id="addMonitorModal">
    <div class="modal" style="max-width:520px">
        <div class="modal-header">
            <div class="modal-title">+ Adauga in Monitorizare</div>
            <button class="modal-close" onclick="closeModal('addMonitorModal')">&#10005;</button>
        </div>
        <p style="color:var(--text2);margin-bottom:16px;font-size:.9rem">
            Domeniu: <strong id="monitorDomain" style="color:var(--text);font-family:monospace"></strong>
        </p>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="add_to_monitor">
            <input type="hidden" name="domain" id="monitorDomainInput">
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
                        <option value="owned">Il detin</option>
                    </select>
                </div>
            </div>
            <div class="form-group" style="margin-bottom:20px">
                <label class="form-label">Note (optional)</label>
                <input type="text" name="notes" class="form-input" maxlength="500">
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-ghost" onclick="closeModal('addMonitorModal')">Anuleaza</button>
                <button type="submit" class="btn btn-primary">Adauga</button>
            </div>
        </form>
    </div>
</div>

<script>
const CSRF = <?= json_encode($csrfToken) ?>;
const dangerWS  = ['DeleteProhibited','Hold','Locked','RegistrantTransferProhibited','ServerDeleteProhibited','ServerTransferProhibited','ClientDeleteProhibited','ClientTransferProhibited','ClientHold'];
const warningWS = ['PendingDelete','PendingTransfer','Inactive','Expired'];

function openModal(id){ document.getElementById(id).classList.add('open'); }
function closeModal(id){ document.getElementById(id).classList.remove('open'); }
document.querySelectorAll('.modal-overlay').forEach(el=>{
    el.addEventListener('click',function(e){if(e.target===this)this.classList.remove('open');});
});

function switchTab(tab, btn) {
    document.querySelectorAll('.lookup-tab').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    ['tabSingle','tabIntel','tabBatch'].forEach(id=>document.getElementById(id).style.display='none');
    document.getElementById('tab'+tab.charAt(0).toUpperCase()+tab.slice(1)).style.display='';
    document.getElementById('singleResult').style.display='none';
    document.getElementById('intelResult').style.display='none';
    document.getElementById('batchProgress').style.display='none';
}

function statusColor(s){ return {available:'#10b981',registered:'#3b82f6',pending_delete:'#f59e0b',error:'#ef4444',unknown:'#64748b'}[s]||'#64748b'; }
function statusLabel(s){ return {available:'Available',registered:'Registered',pending_delete:'Pending Delete',error:'Error',unknown:'Unknown'}[s]||s; }
function wsTagHtml(ws){ let c=dangerWS.includes(ws)?'danger':(warningWS.includes(ws)?'warning':(ws.toLowerCase()==='ok'?'ok':'')); return `<span class="ws-tag ${c}">${ws}</span>`; }

// ---- SINGLE WHOIS ----
async function doSingleLookup() {
    const input = document.getElementById('singleInput');
    const btn   = document.getElementById('singleBtn');
    const txt   = document.getElementById('singleBtnText');
    let domain  = input.value.trim().toLowerCase().replace(/^(https?:\/\/)?(www\.)?/,'').replace(/\/$/,'');
    if (!domain){ input.focus(); return; }
    btn.disabled=true; txt.innerHTML='<span class="spinner-sm"></span> Se verifica...';
    document.getElementById('singleResult').style.display='none';
    try {
        const fd=new FormData(); fd.append('csrf_token',CSRF); fd.append('action','whois_check'); fd.append('domain',domain);
        const data = await (await fetch('/lookup',{method:'POST',body:fd})).json();
        renderSingleResult(data);
    } catch(e){
        document.getElementById('singleResult').innerHTML='<div class="alert alert-danger">Eroare de retea.</div>';
        document.getElementById('singleResult').style.display='';
    } finally { btn.disabled=false; txt.textContent='Verifica'; }
}

function renderSingleResult(d) {
    if(d.error){ document.getElementById('singleResult').innerHTML=`<div class="alert alert-danger">${d.error}</div>`; document.getElementById('singleResult').style.display=''; return; }
    const sc=d.status||'unknown';
    const wt=(d.whois_statuses||[]).map(w=>wsTagHtml(w)).join('');
    const raw=(d.raw||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');
    let act='';
    if(d.status==='available') act+=`<a href="https://portal.chroot.ro/cart.php?a=add&domain=register&query=${encodeURIComponent(d.domain)}" target="_blank" class="btn btn-success btn-sm">&#128722; Cumpara</a>`;
    act+=d.already_in
        ? `<span class="alert alert-info" style="margin:0;padding:6px 12px;font-size:.82rem">&#10003; Monitorizat &mdash; <a href="/history?domain=${encodeURIComponent(d.already_in)}" style="color:var(--accent2)">Istoric</a></span>`
        : `<button class="btn btn-primary btn-sm" onclick="openAddMonitor('${d.domain}')">+ Monitor</button>`;
    act+=`<button class="btn btn-ghost btn-sm" onclick="openIntelForDomain('${d.domain}')">&#128202; Intelligence</button>`;
    act+=`<button class="btn btn-ghost btn-sm" onclick="doSingleLookup()">&#8635; Re-verifica</button>`;
    document.getElementById('singleResult').innerHTML=`
    <div class="result-card">
        <div class="result-header ${sc}">
            <div><div class="result-domain">${d.domain}</div><div class="text-xs text-muted" style="margin-top:4px">Verificat ${new Date().toLocaleString('ro-RO')}</div></div>
            <div style="display:flex;align-items:center;gap:8px">${d.status==='available'?'<span class="pulse-dot" style="margin-right:4px"></span>':''}<span class="badge ${sc}" style="font-size:.85rem;padding:6px 14px">${statusLabel(d.status)}</span></div>
        </div>
        <div class="result-grid">
            <div class="result-field"><div class="result-field-label">Registrar</div><div class="result-field-value ${d.registrar?'':'muted'}">${d.registrar||'—'}</div></div>
            <div class="result-field"><div class="result-field-label">Inregistrat</div><div class="result-field-value mono">${d.registered_on||'<span class="muted">—</span>'}</div></div>
            <div class="result-field"><div class="result-field-label">Expira</div><div class="result-field-value mono">${d.expires_on||'<span class="muted">—</span>'}</div></div>
            ${wt?`<div class="result-field" style="border-right:none"><div class="result-field-label">WHOIS Status</div><div style="margin-top:4px">${wt}</div></div>`:''}
        </div>
        <div class="result-actions">${act}</div>
        ${raw?`<div style="padding:0 20px 16px"><button class="btn btn-ghost btn-sm" style="width:100%;justify-content:center" onclick="toggleRaw(this)">&#128196; Arata Raw WHOIS</button><div class="whois-raw-wrap" style="display:none">${raw}</div></div>`:''}
    </div>`;
    document.getElementById('singleResult').style.display='';
}

function toggleRaw(btn){
    const raw=btn.nextElementSibling;
    if(raw.style.display==='none'){
        raw.style.display='';
        btn.textContent='▲ Ascunde Raw WHOIS';
        raw.innerHTML=raw.textContent.replace(/^(%.*)/gm,'<span style="color:var(--text3)">$1</span>').replace(/^([A-Za-z][A-Za-z ]+):\s*(.+)/gm,'<span style="color:var(--accent2)">$1:</span> <span style="color:var(--text)">$2</span>');
    } else { raw.style.display='none'; btn.textContent='📄 Arata Raw WHOIS'; }
}

// ---- INTELLIGENCE ----
let currentIntelDomain = '';

function openIntelForDomain(domain) {
    document.querySelectorAll('.lookup-tab')[1].click();
    document.getElementById('intelInput').value = domain;
    doIntelLookup();
}

async function doIntelLookup() {
    const input = document.getElementById('intelInput');
    const btn   = document.getElementById('intelBtn');
    const txt   = document.getElementById('intelBtnText');
    let domain  = input.value.trim().toLowerCase().replace(/^(https?:\/\/)?(www\.)?/,'').replace(/\/$/,'');
    if(!domain){ input.focus(); return; }
    currentIntelDomain = domain;

    btn.disabled=true; txt.innerHTML='<span class="spinner-sm"></span> Se analizeaza...';
    document.getElementById('intelResult').style.display='none';
    document.getElementById('intelResult').innerHTML = renderIntelSkeleton(domain);
    document.getElementById('intelResult').style.display='';
    btn.disabled=false; txt.innerHTML='&#128202; Analizeaza';

    const sections = ['dns','ssl','email','hosting','subdoms','ports','history','tech','infra'];
    sections.forEach(sec => loadIntelSection(domain, sec));
}

function renderIntelSkeleton(domain) {
    const sections = [
        {id:'dns',    icon:'🌐', color:'rgba(59,130,246,.15)',  title:'DNS Records'},
        {id:'ssl',    icon:'🔐', color:'rgba(16,185,129,.15)',  title:'SSL / TLS'},
        {id:'email',  icon:'📧', color:'rgba(139,92,246,.15)',  title:'Email Security'},
        {id:'hosting',icon:'🏠', color:'rgba(245,158,11,.15)',  title:'Hosting & IP'},
        {id:'subdoms',icon:'🔍', color:'rgba(59,130,246,.12)',  title:'Subdomenii (CT Logs)'},
        {id:'ports',  icon:'🚪', color:'rgba(239,68,68,.12)',   title:'Porturi Deschise'},
        {id:'history',icon:'🕐', color:'rgba(139,92,246,.12)', title:'Istoric & Reputatie'},
        {id:'tech',   icon:'⚙️',  color:'rgba(16,185,129,.12)',  title:'Tech Stack'},
        {id:'infra',  icon:'🔗',  color:'rgba(245,158,11,.12)',  title:'Infrastructura Comuna'},
    ];
    let html = `<div class="card" style="margin-bottom:16px">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
            <div>
                <div style="font-family:monospace;font-size:1.2rem;font-weight:700">${domain}</div>
                <div class="text-xs text-muted">Intelligence Report — ${new Date().toLocaleString('ro-RO')}</div>
            </div>
            <button class="btn btn-ghost btn-sm" onclick="openAddMonitor('${domain}')">+ Adauga in Monitor</button>
        </div>
    </div>
    <div class="intel-panel">`;

    sections.forEach(s => {
        html += `
        <div class="intel-section open" id="intel-sec-${s.id}">
            <div class="intel-section-header" onclick="toggleIntelSection('${s.id}')">
                <div class="intel-section-title">
                    <div class="intel-section-icon" style="background:${s.color}">${s.icon}</div>
                    ${s.title}
                    <span id="intel-badge-${s.id}"></span>
                </div>
                <span class="intel-chevron">▼</span>
            </div>
            <div class="intel-section-body" id="intel-body-${s.id}">
                <div class="intel-loading"><span class="spinner-sm"></span> Se incarca...</div>
            </div>
        </div>`;
    });

    html += '</div>';
    return html;
}

function toggleIntelSection(id) {
    document.getElementById('intel-sec-' + id).classList.toggle('open');
}

async function loadIntelSection(domain, section) {
    const body = document.getElementById('intel-body-' + section);
    if(!body) return;
    try {
        const fd = new FormData();
        fd.append('csrf_token', CSRF);
        fd.append('action', 'intel_section');
        fd.append('domain', domain);
        fd.append('section', section);
        const data = await (await fetch('/lookup', {method:'POST', body:fd})).json();
        body.innerHTML = renderSection(section, data, domain);
        updateBadge(section, data);
    } catch(e) {
        body.innerHTML = `<div class="text-muted text-sm" style="padding:8px 0">Eroare la incarcare.</div>`;
    }
}

function updateBadge(section, data) {
    const el = document.getElementById('intel-badge-' + section);
    if(!el) return;
    let badge = '';
    switch(section) {
        case 'dns':
            const aCount = (data.a||[]).length;
            if(aCount) badge = `<span class="intel-badge info">${aCount} A record${aCount>1?'s':''}</span>`;
            break;
        case 'ssl':
            if(data.error) badge = `<span class="intel-badge bad">Eroare SSL</span>`;
            else if(data.days_left <= 7) badge = `<span class="intel-badge bad">Expira in ${data.days_left}z</span>`;
            else if(data.days_left <= 30) badge = `<span class="intel-badge warn">Expira in ${data.days_left}z</span>`;
            else badge = `<span class="intel-badge ok">Valid ${data.days_left}z</span>`;
            break;
        case 'email':
            const score = data.score||0;
            const cls = score===3?'ok':(score>=1?'warn':'bad');
            badge = `<span class="intel-badge ${cls}">${score}/3</span>`;
            break;
        case 'hosting':
            if(data.org) badge = `<span class="intel-badge info">${data.org}</span>`;
            break;
        case 'subdoms':
            const cnt = (data.list||[]).length;
            if(cnt) badge = `<span class="intel-badge info">${cnt} subdomenii</span>`;
            break;
        case 'ports':
            const open = (data||[]).length;
            if(open===0) badge = `<span class="intel-badge ok">Niciun port expus</span>`;
            else {
                const hasHigh = data.some(p=>p.risk==='high');
                badge = `<span class="intel-badge ${hasHigh?'bad':'warn'}">${open} deschis${open>1?'e':''}</span>`;
            }
            break;
        case 'history':
            const wb = data.wayback || {};
            const vt2 = data.virustotal || {};
            if(wb.available && wb.first_snapshot) badge = `<span class="intel-badge info">Din ${wb.first_snapshot.year}</span>`;
            if(vt2.malicious_votes > 0) badge += `<span class="intel-badge bad" style="margin-left:4px">&#9888; VT: ${vt2.malicious_votes} detect.</span>`;
            break;
        case 'tech':
            if(data.cms) badge = `<span class="intel-badge info">${data.cms}</span>`;
            else if((data.tech_stack||[]).length) badge = `<span class="intel-badge neutral">${data.tech_stack[0]}</span>`;
            break;
        case 'infra':
            const sameIpCount = (data.same_ip||[]).length;
            const sameNsCount = (data.same_ns||[]).length;
            if(sameIpCount || sameNsCount) badge = `<span class="intel-badge warn">${sameIpCount+sameNsCount} comune</span>`;
            else badge = `<span class="intel-badge ok">Unic</span>`;
            break;
    }
    el.innerHTML = badge;
}

function renderSection(section, data, domain) {
    switch(section) {
        case 'dns':     return renderDNS(data);
        case 'ssl':     return renderSSL(data);
        case 'email':   return renderEmail(data);
        case 'hosting': return renderHosting(data, domain);
        case 'subdoms': return renderSubdomains(data);
        case 'ports':   return renderPorts(data);
        case 'history': return renderHistory(data, domain);
        case 'tech':    return renderTech(data);
        case 'infra':   return renderInfra(data, domain);
        default: return '<span class="text-muted">N/A</span>';
    }
}

function renderDNS(d) {
    let html = '';
    if((d.a||[]).length) {
        html += `<div style="margin-bottom:14px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:600">A Records (IPv4)</div>`;
        html += `<table class="dns-table"><thead><tr><th>IP Address</th><th>Reverse DNS</th></tr></thead><tbody>`;
        (d.a||[]).forEach(ip => { html += `<tr><td class="mono">${ip}</td><td class="provider">—</td></tr>`; });
        html += '</tbody></table></div>';
    }
    if((d.mx||[]).length) {
        html += `<div style="margin-bottom:14px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:600">MX Records (Email)</div>`;
        html += `<table class="dns-table"><thead><tr><th>Server</th><th>Prioritate</th><th>Provider detectat</th></tr></thead><tbody>`;
        (d.mx||[]).forEach(mx => { html += `<tr><td class="mono">${mx.host}</td><td>${mx.priority}</td><td><span class="intel-badge info">${mx.provider}</span></td></tr>`; });
        html += '</tbody></table></div>';
    }
    if((d.ns||[]).length) {
        html += `<div style="margin-bottom:14px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:600">NS Records (DNS Hosting)</div>`;
        html += `<table class="dns-table"><thead><tr><th>Nameserver</th><th>Provider</th></tr></thead><tbody>`;
        (d.ns||[]).forEach(ns => { html += `<tr><td class="mono">${ns.host}</td><td><span class="intel-badge neutral">${ns.provider}</span></td></tr>`; });
        html += '</tbody></table></div>';
    }
    if((d.txt||[]).length) {
        html += `<div style="margin-bottom:14px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:600">TXT Records</div>`;
        html += `<table class="dns-table"><thead><tr><th>Tip</th><th>Valoare</th></tr></thead><tbody>`;
        (d.txt||[]).forEach(t => {
            const val = t.value.length > 80 ? t.value.substring(0, 80) + '…' : t.value;
            html += `<tr><td><span class="intel-badge neutral">${t.type}</span></td><td class="mono" style="font-size:.75rem;color:var(--text2)">${escHtml(val)}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    if((d.caa||[]).length) {
        html += `<div style="margin-bottom:6px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:600">CAA (Certificate Authorities autorizate)</div>`;
        d.caa.forEach(c => { html += `<span class="intel-badge info" style="margin-right:4px">${c}</span>`; });
        html += '</div>';
    }
    if(d.soa) html += `<div class="text-xs text-muted" style="margin-top:10px">SOA: <span style="font-family:monospace">${d.soa}</span></div>`;
    return html || '<div class="text-muted text-sm">Niciun record DNS gasit.</div>';
}

function renderSSL(d) {
    if(d.error) return `<div class="alert alert-warning" style="margin:0">${d.error}</div>`;
    let daysClass = d.days_left > 30 ? 'ok' : (d.days_left > 7 ? 'warn' : 'bad');
    let html = `<div style="display:flex;align-items:flex-start;gap:20px;flex-wrap:wrap;margin-bottom:14px">
        <div><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;font-weight:600">Zile ramase</div><div class="ssl-days ${daysClass}">${d.days_left}</div></div>
        <div><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;font-weight:600">Emitent</div><div style="font-size:.88rem;font-weight:500">${d.issuer||'—'}</div></div>
        <div><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;font-weight:600">Expira</div><div style="font-family:monospace;font-size:.88rem">${d.expires||'—'}</div></div>
    </div>`;
    if((d.sans||[]).length) {
        html += `<div><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;font-weight:600">Subject Alternative Names (${d.sans.length})</div><div class="subdomain-grid">`;
        d.sans.forEach(san => { html += `<span class="subdomain-chip">${san}</span>`; });
        html += '</div></div>';
    }
    return html;
}

function renderEmail(d) {
    const spf   = d.spf   ? 'pass' : 'fail';
    const dmarc = d.dmarc ? 'pass' : 'fail';
    const dkim  = d.dkim_hint ? 'pass' : 'fail';
    let html = `<div class="email-score">
        <div class="email-score-item ${spf}"><div class="label">SPF</div><div class="val">${spf==='pass'?'✓ OK':'✗ Lipseste'}</div></div>
        <div class="email-score-item ${dkim}"><div class="label">DKIM</div><div class="val">${dkim==='pass'?'✓ OK':'? Nedetectat'}</div></div>
        <div class="email-score-item ${dmarc}"><div class="label">DMARC</div><div class="val">${dmarc==='pass'?'✓ OK':'✗ Lipseste'}</div></div>
    </div>`;
    if(d.spf) html += `<div style="margin-bottom:8px"><span class="intel-badge ok">SPF</span> <span class="text-sm text-muted" style="margin-left:6px">${d.spf.summary}</span></div>`;
    if(d.dmarc) html += `<div style="margin-bottom:8px"><span class="intel-badge ok">DMARC</span> <span class="text-sm text-muted" style="margin-left:6px">${d.dmarc.summary}</span></div>`;
    if(d.dkim_hint) html += `<div style="margin-bottom:8px"><span class="intel-badge ok">DKIM</span> <span class="text-sm text-muted" style="margin-left:6px">${d.dkim_hint}</span></div>`;
    if((d.issues||[]).length) {
        html += `<div style="margin-top:10px">`;
        d.issues.forEach(issue => { html += `<div class="alert alert-warning" style="margin-bottom:6px;padding:8px 12px;font-size:.82rem">⚠️ ${issue}</div>`; });
        html += '</div>';
    }
    return html;
}

function renderHosting(d, domain) {
    if(!d.ip) return '<div class="text-muted text-sm">IP negasit. Domeniu posibil neinregistrat.</div>';
    let html = `<div class="hosting-grid" style="margin-bottom:12px">
        <div class="hosting-item"><div class="label">IP Address</div><div class="val" style="font-family:monospace">${d.ip||'—'}</div></div>
        <div class="hosting-item"><div class="label">Hosting / Org</div><div class="val">${d.org||d.asn||'—'}</div></div>
        <div class="hosting-item"><div class="label">Tara</div><div class="val">${d.country||'—'}${d.city?' · '+d.city:''}</div></div>
        <div class="hosting-item"><div class="label">ASN</div><div class="val" style="font-family:monospace">${d.asn||'—'}</div></div>
    </div>`;
    if(d.reverse_dns) html += `<div style="margin-bottom:8px"><span class="intel-badge neutral">Reverse DNS</span> <span class="text-sm" style="font-family:monospace;margin-left:6px">${d.reverse_dns}</span></div>`;
    if(d.shared_count !== null) {
        const cls = d.shared_count > 50 ? 'bad' : (d.shared_count > 10 ? 'warn' : 'ok');
        html += `<div><span class="intel-badge ${cls}">Shared Hosting</span> <span class="text-sm text-muted" style="margin-left:6px">IP-ul este impartit cu ~${d.shared_count} alte domenii${d.shared_count>20?' — hosting shared tipic':''}</span></div>`;
    }
    return html;
}

function renderSubdomains(d) {
    if(d.fallback && !(d.list||[]).length) {
        return `<div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.2);border-radius:8px;padding:14px 16px">
            <div style="color:#fbbf24;font-weight:600;font-size:.85rem;margin-bottom:6px">&#9888; Servicii externe inaccesibile de pe server</div>
            <div style="color:var(--text2);font-size:.83rem;line-height:1.6;margin-bottom:10px">${d.error||'crt.sh si HackerTarget sunt blocate de serverul de hosting.'}</div>
            <a href="https://crt.sh/?q=%25.${currentIntelDomain}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm">&#128279; Verifica pe crt.sh</a>
            <a href="https://api.hackertarget.com/hostsearch/?q=${currentIntelDomain}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm" style="margin-left:6px">&#128279; HackerTarget</a>
        </div>`;
    }
    if(d.error && !(d.list||[]).length) return `<div class="text-muted text-sm">${d.error}</div>`;
    if(!(d.list||[]).length) return '<div class="text-muted text-sm">Niciun subdomeniu gasit.</div>';
    let html = `<div style="margin-bottom:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">
        <span class="intel-badge info">${d.count} subdomenii${d.count > d.list.length ? ' (afisate ' + d.list.length + ')' : ''}</span>`;
    if(d.source) html += `<span class="text-xs text-muted">Sursa: ${d.source}</span>`;
    if(d.first_seen) html += `<span class="text-xs text-muted">&#183; Prima aparitie CT: ${d.first_seen}</span>`;
    if(d.note) html += `<span class="intel-badge warn" style="font-size:.72rem">${d.note}</span>`;
    html += `</div><div class="subdomain-grid">`;
    (d.list||[]).forEach(sub => { html += `<a href="javascript:void(0)" class="subdomain-chip" onclick="lookupSubdomain('${sub}')" title="Lookup ${sub}">${sub}</a>`; });
    html += '</div>';
    return html;
}

function renderPorts(data) {
    if(!Array.isArray(data) || data.length===0) return `<div class="alert alert-success" style="margin:0;padding:10px 14px">✓ Niciun port expus public. Foarte bine.</div>`;
    let html = `<div style="margin-bottom:10px;font-size:.83rem;color:var(--text2)">Porturi deschise detectate — verifica daca accesul public este intentionat:</div>`;
    data.forEach(p => {
        const labels = {high:'🔴 Risc Mare',medium:'🟡 Atentie',low:'🟢 Normal'};
        const tips = {
            3306: 'MySQL expus public — acces potential neautorizat la baza de date',
            5432: 'PostgreSQL expus public — recomanda firewall',
            6379: 'Redis fara autentificare implicita — risc major',
            27017: 'MongoDB expus public — vulnerabil daca fara auth',
            21: 'FTP nesecurizat — foloseste SFTP in schimb',
            23: 'Telnet — protocol nesecurizat, inlocuieste cu SSH',
            22: 'SSH deschis — verifica daca ai fail2ban si autentificare prin chei',
        };
        const tip = tips[p.port] || '';
        html += `<div class="port-row risk-${p.risk}">
            <div style="display:flex;align-items:center;gap:10px">
                <span class="port-num">${p.port}</span>
                <span class="port-name">${p.name}</span>
                ${tip ? `<span class="text-xs text-muted">— ${tip}</span>` : ''}
            </div>
            <span class="intel-badge ${p.risk==='high'?'bad':(p.risk==='medium'?'warn':'ok')}">${labels[p.risk]}</span>
        </div>`;
    });
    return html;
}

function lookupSubdomain(sub) {
    document.getElementById('intelInput').value = sub;
    doIntelLookup();
}

function escHtml(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ---- BATCH ----
let batchRunning = false;
async function doBatchLookup() {
    if(batchRunning) return;
    const lines = document.getElementById('batchInput').value.split(/[\r\n,;]+/)
        .map(l=>l.trim().toLowerCase().replace(/^(https?:\/\/)?(www\.)?/,'').replace(/\/$/,''))
        .filter(l=>l.length>0);
    if(!lines.length){ document.getElementById('batchInput').focus(); return; }
    if(lines.length>50){ alert('Maximum 50 domenii.'); return; }
    batchRunning=true;
    const btn=document.getElementById('batchBtn');
    btn.disabled=true; btn.textContent='Se verifica...';
    document.getElementById('batchProgress').style.display='';
    document.getElementById('batchTbody').innerHTML='';
    document.getElementById('batchBar').style.width='0';
    document.getElementById('batchCounter').textContent=`0 / ${lines.length}`;
    for(let i=0;i<lines.length;i++){
        const domain=lines[i];
        const tr=document.createElement('tr'); tr.id=`brow_${i}`;
        tr.innerHTML=`<td><span class="domain-name">${domain}</span></td><td><span class="spinner-sm"></span> ...</td><td>—</td><td>—</td><td>—</td>`;
        document.getElementById('batchTbody').appendChild(tr);
        tr.scrollIntoView({behavior:'smooth',block:'nearest'});
        try {
            const fd=new FormData(); fd.append('csrf_token',CSRF); fd.append('action','batch_check'); fd.append('domain',domain);
            const data=await (await fetch('/lookup',{method:'POST',body:fd})).json();
            const dot=`<span class="status-dot" style="background:${statusColor(data.status)}"></span>`;
            const wt=(data.whois_statuses||[]).slice(0,2).map(w=>wsTagHtml(w)).join('');
            let act=data.status==='available'?`<a href="https://portal.chroot.ro/cart.php?a=add&domain=register&query=${encodeURIComponent(domain)}" target="_blank" class="btn btn-success btn-sm" style="padding:4px 10px">Cumpara</a> `:'';
            act+=!data.already_in?`<button class="btn btn-ghost btn-sm" style="padding:4px 10px" onclick="openAddMonitor('${domain}')">+ Monitor</button>`:'<span style="color:var(--success);font-size:.8rem">✓ Monitorizat</span>';
            document.getElementById(`brow_${i}`).innerHTML=`
                <td><span class="domain-name">${domain}</span></td>
                <td>${dot}<span class="badge ${data.status}" style="font-size:.72rem;padding:3px 8px">${statusLabel(data.status)}</span>${wt?'<br><span style="font-size:.7rem;margin-top:2px;display:inline-block">'+wt+'</span>':''}</td>
                <td class="text-sm text-muted">${data.registrar||'—'}</td>
                <td class="text-sm text-muted">${data.expires_on||'—'}</td>
                <td>${act}</td>`;
        } catch(e){ document.getElementById(`brow_${i}`).innerHTML=`<td>${domain}</td><td colspan="4" class="text-muted">Eroare</td>`; }
        const pct=Math.round(((i+1)/lines.length)*100);
        document.getElementById('batchBar').style.width=pct+'%';
        document.getElementById('batchCounter').textContent=`${i+1} / ${lines.length}`;
    }
    btn.disabled=false; btn.textContent='Verifica toate'; batchRunning=false;
}

function quickLookup(domain) {
    document.querySelectorAll('.lookup-tab')[0].click();
    document.getElementById('singleInput').value=domain;
    doSingleLookup();
}

function openAddMonitor(domain) {
    document.getElementById('monitorDomain').textContent=domain;
    document.getElementById('monitorDomainInput').value=domain;
    openModal('addMonitorModal');
}

document.getElementById('singleInput').focus();

function renderHistory(d, domain) {
    let html = '';
    const rdap = d.rdap || {};
    if(rdap.available) {
        html += `<div style="margin-bottom:18px">
            <div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;font-weight:600">&#128196; Date Inregistrare (WHOIS)</div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px">`;
        if(rdap.registered_on)    html += histCard('Inregistrat', rdap.registered_on, '&#128197;');
        if(rdap.expires_on)       html += histCard('Expira', rdap.expires_on, '&#9203;');
        if(rdap.updated_on)       html += histCard('Ultima modificare', rdap.updated_on, '&#9997;');
        if(rdap.registrar)        html += histCard('Registrar', escHtml(rdap.registrar), '&#127970;');
        if(rdap.registrant)       html += histCard('Registrant', escHtml(rdap.registrant), '&#128100;');
        if(rdap.registrant_country) html += histCard('Tara', escHtml(rdap.registrant_country), '&#127988;');
        if(rdap.dnssec)           html += histCard('DNSSEC', escHtml(rdap.dnssec), '&#128274;');
        html += `</div>`;
        if((rdap.nameservers||[]).length) {
            html += `<div style="margin-top:10px"><div class="text-xs text-muted" style="margin-bottom:5px">Nameservers:</div>`;
            rdap.nameservers.forEach(ns => { html += `<span class="intel-badge neutral" style="margin-right:4px;margin-bottom:4px;font-family:monospace">${ns}</span>`; });
            html += `</div>`;
        }
        if((rdap.status||[]).length) {
            html += `<div style="margin-top:8px"><div class="text-xs text-muted" style="margin-bottom:5px">Status WHOIS:</div>`;
            rdap.status.forEach(s => { html += `<span class="intel-badge neutral" style="margin-right:4px;margin-top:4px">${s}</span>`; });
            html += `</div>`;
        }
        html += `</div>`;
    } else if(rdap.error) {
        html += `<div style="margin-bottom:14px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:600">&#128196; WHOIS</div><div class="text-muted text-sm">${rdap.error}</div></div>`;
    }

    const wb = d.wayback || {};
    html += `<div style="margin-bottom:18px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;font-weight:600">&#128190; Wayback Machine (web.archive.org)</div>`;
    if(wb.available) {
        html += `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px;margin-bottom:10px">`;
        if(wb.first_snapshot) html += histCard('Prima arhivare', wb.first_snapshot.date, '&#9196;', `<a href="${wb.first_snapshot.url}" target="_blank" style="color:var(--accent2);font-size:.75rem">Vezi snapshot &#8599;</a>`);
        if(wb.last_snapshot)  html += histCard('Ultima arhivare', wb.last_snapshot.date, '&#9197;', `<a href="${wb.last_snapshot.url}" target="_blank" style="color:var(--accent2);font-size:.75rem">Vezi snapshot &#8599;</a>`);
        if(wb.total_snapshots) html += histCard('Snapshot-uri', wb.total_snapshots.toLocaleString(), '&#128247;');
        html += `</div>`;
        if(Object.keys(wb.years_active||{}).length) {
            const years = wb.years_active;
            const maxVal = Math.max(...Object.values(years));
            html += `<div style="margin-top:10px"><div class="text-xs text-muted" style="margin-bottom:6px">Activitate arhivata pe ani:</div><div style="display:flex;align-items:flex-end;gap:3px;height:50px">`;
            Object.entries(years).forEach(([yr, cnt]) => {
                const h = Math.max(4, Math.round((cnt/maxVal)*46));
                const color = cnt > maxVal*0.7 ? 'var(--accent)' : (cnt > maxVal*0.3 ? 'var(--accent2)' : 'var(--border)');
                html += `<div title="${yr}: ${cnt} snapshot-uri" style="flex:1;height:${h}px;background:${color};border-radius:2px 2px 0 0;cursor:default;min-width:8px"></div>`;
            });
            html += `</div><div style="display:flex;justify-content:space-between;color:var(--text3);font-size:.7rem;margin-top:2px"><span>${Object.keys(years)[0]}</span><span>${Object.keys(years)[Object.keys(years).length-1]}</span></div></div>`;
        }
        html += `<div style="margin-top:10px"><a href="${wb.archive_url}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm">&#128279; Vezi toate arhivele pe Wayback Machine</a></div>`;
    } else {
        html += `<div style="color:var(--text2);font-size:.85rem">Domeniu negasit in arhiva Wayback Machine.</div>`;
        html += `<div style="margin-top:8px"><a href="https://web.archive.org/web/*/${domain}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm">&#128279; Cauta pe Wayback Machine</a></div>`;
    }
    html += `</div>`;

    const ct = d.cert_timeline || {};
    html += `<div style="margin-bottom:18px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;font-weight:600">&#128274; Istoric Certificate SSL (crt.sh)</div>`;
    if(ct.available) {
        html += `<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px">`;
        if(ct.total_certs) html += `<span class="intel-badge info">${ct.total_certs} certificate emise</span>`;
        if(ct.first_cert)  html += `<span class="intel-badge neutral">Primul SSL: ${ct.first_cert}</span>`;
        Object.entries(ct.issuers||{}).slice(0,3).forEach(([iss,cnt]) => { html += `<span class="intel-badge neutral">${iss}: ${cnt}</span>`; });
        html += `</div>`;
        if(Object.keys(ct.by_year||{}).length > 1) {
            const years = ct.by_year;
            const maxVal = Math.max(...Object.values(years));
            html += `<div style="display:flex;align-items:flex-end;gap:3px;height:40px;margin-bottom:6px">`;
            Object.entries(years).forEach(([yr, cnt]) => {
                const h = Math.max(3, Math.round((cnt/maxVal)*38));
                html += `<div title="${yr}: ${cnt} certificate" style="flex:1;height:${h}px;background:rgba(16,185,129,.5);border-radius:2px 2px 0 0;min-width:8px"></div>`;
            });
            html += `</div><div style="display:flex;justify-content:space-between;color:var(--text3);font-size:.7rem"><span>${Object.keys(years)[0]}</span><span>${Object.keys(years)[Object.keys(years).length-1]}</span></div>`;
        }
        if((ct.recent_certs||[]).length) {
            html += `<div style="margin-top:12px"><div class="text-xs text-muted" style="margin-bottom:6px">Ultimele certificate:</div>`;
            html += `<table class="dns-table"><thead><tr><th>Emis</th><th>Expira</th><th>Emitent</th><th>SAN</th></tr></thead><tbody>`;
            ct.recent_certs.forEach(c => {
                html += `<tr><td class="mono" style="font-size:.78rem">${c.not_before||'—'}</td><td class="mono" style="font-size:.78rem">${c.not_after||'—'}</td><td><span class="intel-badge neutral">${escHtml(c.issuer||'')}</span></td><td style="font-size:.75rem;color:var(--text2)">${escHtml(c.san||'')}${c.url?` <a href="${c.url}" target="_blank" style="color:var(--accent2)">&#8599;</a>`:''}</td></tr>`;
            });
            html += `</tbody></table></div>`;
        }
    } else {
        html += `<div class="text-muted text-sm">${ct.error||'Indisponibil'}</div>`;
        html += `<div style="margin-top:6px"><a href="https://crt.sh/?q=${domain}" target="_blank" class="btn btn-ghost btn-sm">&#128279; Cauta pe crt.sh</a></div>`;
    }
    html += `</div>`;

    const vt = d.virustotal || {};
    html += `<div style="margin-bottom:10px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;font-weight:600">&#128737; Reputatie & Securitate (VirusTotal)</div>`;
    if(vt.available) {
        const rep = vt.reputation || 0;
        const repClass = rep > 0 ? 'ok' : (rep < -5 ? 'bad' : 'warn');
        const repLabel = rep > 0 ? 'Reputatie pozitiva' : (rep < -5 ? 'Reputatie negativa' : 'Reputatie neutra');
        html += `<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px"><span class="intel-badge ${repClass}">&#127775; Scor: ${rep} — ${repLabel}</span>`;
        if(vt.malicious_votes)  html += `<span class="intel-badge bad">&#9888; ${vt.malicious_votes} detectari malitioase</span>`;
        if(vt.suspicious_votes) html += `<span class="intel-badge warn">${vt.suspicious_votes} suspecte</span>`;
        if(vt.harmless_votes)   html += `<span class="intel-badge ok">${vt.harmless_votes} curate</span>`;
        html += `</div>`;
        if(vt.creation_date) html += `<div style="font-size:.83rem;color:var(--text2);margin-bottom:4px">Inregistrat (VT): <span style="color:var(--text)">${vt.creation_date}</span></div>`;
        if(vt.registrar)     html += `<div style="font-size:.83rem;color:var(--text2);margin-bottom:4px">Registrar (VT): <span style="color:var(--text)">${escHtml(vt.registrar)}</span></div>`;
        const cats = vt.categories || {};
        if(Object.keys(cats).length) html += `<div style="margin-top:8px;font-size:.82rem;color:var(--text2)">Categorii: `+Object.values(cats).filter((v,i,a)=>a.indexOf(v)===i).slice(0,4).map(c=>`<span class="intel-badge neutral" style="margin-right:3px">${escHtml(c)}</span>`).join('')+`</div>`;
    } else {
        html += `<div style="color:var(--text2);font-size:.83rem;margin-bottom:8px">${vt.error||'Date indisponibile'}</div>`;
    }
    html += `<div style="margin-top:8px"><a href="${vt.vt_url||'https://www.virustotal.com/gui/domain/'+domain}" target="_blank" rel="noopener" class="btn btn-ghost btn-sm">&#128279; Verifica pe VirusTotal</a></div>`;
    html += `</div>`;
    return html || '<div class="text-muted text-sm">Date istorice indisponibile.</div>';
}

function renderTech(d) {
    if(d.error && !(d.tech_stack||[]).length) return `<div class="text-muted text-sm">${d.error}</div>`;
    let html = '';
    if(d.status_code) {
        const sc = d.status_code;
        const cls = sc >= 200 && sc < 300 ? 'ok' : (sc >= 300 && sc < 400 ? 'warn' : 'bad');
        html += `<div style="margin-bottom:12px"><span class="intel-badge ${cls}">HTTP ${sc}</span>${d.redirect ? `<span class="intel-badge warn" style="margin-left:6px">&#8594; ${d.redirect}</span>` : ''}</div>`;
    }
    html += `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px;margin-bottom:14px">`;
    if(d.server)     html += techCard('Web Server', d.server, '&#128421;');
    if(d.cms)        html += techCard('CMS', d.cms, '&#128196;');
    if(d.cdn)        html += techCard('CDN', d.cdn, '&#127760;');
    if(d.waf)        html += techCard('WAF', d.waf, '&#128737;');
    if(d.language)   html += techCard('Limbaj', d.language, '&#128187;');
    if(d.powered_by) html += techCard('Powered By', d.powered_by, '&#9889;');
    html += `</div>`;
    if((d.tech_stack||[]).length) {
        html += `<div style="margin-bottom:10px"><div class="text-xs text-muted" style="margin-bottom:6px">Tech Stack detectat:</div>`;
        d.tech_stack.forEach(t => { html += `<span class="intel-badge neutral" style="margin-right:4px;margin-bottom:4px">${escHtml(t)}</span>`; });
        html += `</div>`;
    }
    const relevantHeaders = ['content-type','cache-control','x-frame-options','strict-transport-security',
        'content-security-policy','x-content-type-options','permissions-policy'];
    const h = d.headers || {};
    const shownHeaders = relevantHeaders.filter(k => h[k]);
    if(shownHeaders.length) {
        html += `<div style="margin-top:10px"><div class="text-xs text-muted" style="margin-bottom:6px">HTTP Headers relevante:</div>`;
        html += `<table class="dns-table"><thead><tr><th>Header</th><th>Valoare</th></tr></thead><tbody>`;
        shownHeaders.forEach(k => {
            const val = h[k].length > 80 ? h[k].substring(0,80)+'\u2026' : h[k];
            html += `<tr><td style="font-family:monospace;font-size:.78rem;color:var(--accent2)">${k}</td><td style="font-size:.78rem;color:var(--text2)">${escHtml(val)}</td></tr>`;
        });
        html += `</tbody></table></div>`;
    }
    return html || '<div class="text-muted text-sm">Nu s-au putut detecta tehnologii.</div>';
}

function techCard(label, value, icon) {
    return `<div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:8px 10px"><div style="font-size:.68rem;color:var(--text3);text-transform:uppercase;font-weight:600;margin-bottom:3px">${icon} ${label}</div><div style="font-size:.82rem;font-weight:600">${escHtml(value)}</div></div>`;
}

function renderInfra(d, domain) {
    let html = '';
    const sameIp = d.same_ip || [];
    const sameNs = d.same_ns || [];
    if(d.current_ip) html += `<div style="margin-bottom:12px"><span style="font-size:.82rem;color:var(--text2)">IP curent: </span><span style="font-family:monospace;font-weight:600">${d.current_ip}</span></div>`;
    if(sameIp.length) {
        html += `<div style="margin-bottom:16px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;font-weight:600">&#127968; ${sameIp.length} domeniu${sameIp.length>1?'i':''} din lista ta pe acelasi IP</div>`;
        sameIp.forEach(row => {
            html += `<div style="display:flex;align-items:center;gap:10px;padding:7px 10px;background:var(--surface2);border-radius:7px;margin-bottom:5px">`+
                `<span class="domain-name" style="font-size:.85rem">${row.domain}</span>`+
                `<span class="badge ${row.status}" style="font-size:.7rem;padding:2px 7px">${row.status}</span>`+
                `<span style="color:var(--text3);font-size:.75rem;margin-left:auto">${row.type}</span>`+
                `<a href="/lookup?domain=${encodeURIComponent(row.domain)}" style="color:var(--accent2);font-size:.78rem">&#128270;</a></div>`;
        });
        html += `</div>`;
    } else if(d.current_ip) {
        html += `<div style="margin-bottom:14px;color:var(--text2);font-size:.84rem">&#10003; Niciun alt domeniu din lista ta nu este pe acelasi IP.</div>`;
    }
    if((d.current_ns||[]).length) {
        html += `<div style="margin-bottom:8px"><div class="text-xs text-muted" style="margin-bottom:5px">Nameservere curente:</div>`;
        d.current_ns.forEach(ns => { html += `<span class="intel-badge neutral" style="margin-right:4px;font-family:monospace">${ns}</span>`; });
        html += `</div>`;
    }
    if(sameNs.length) {
        html += `<div style="margin-top:12px"><div class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;font-weight:600">&#128279; ${sameNs.length} domeniu${sameNs.length>1?'i':''} din lista ta cu NS comun</div>`;
        sameNs.forEach(row => {
            html += `<div style="display:flex;align-items:center;gap:10px;padding:7px 10px;background:var(--surface2);border-radius:7px;margin-bottom:5px">`+
                `<span class="domain-name" style="font-size:.85rem">${row.domain}</span>`+
                `<span class="badge ${row.status}" style="font-size:.7rem;padding:2px 7px">${row.status}</span>`+
                `<span style="color:var(--text3);font-size:.75rem">${row.common_ns.join(', ')}</span>`+
                `<a href="/lookup?domain=${encodeURIComponent(row.domain)}" style="color:var(--accent2);font-size:.78rem;margin-left:auto">&#128270;</a></div>`;
        });
        html += `</div>`;
    } else if((d.current_ns||[]).length) {
        html += `<div style="margin-top:8px;color:var(--text2);font-size:.84rem">&#10003; Niciun alt domeniu din lista ta nu foloseste aceiasi nameservere.</div>`;
    }
    if(!d.current_ip && !(d.current_ns||[]).length) html = '<div class="text-muted text-sm">Nu s-a putut determina IP-ul sau NS-urile domeniului.</div>';
    return html;
}

function histCard(label, value, icon, extra) {
    return `<div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px"><div style="font-size:.7rem;color:var(--text3);text-transform:uppercase;font-weight:600;margin-bottom:4px">${icon} ${label}</div><div style="font-size:.85rem;font-weight:600;font-family:monospace">${value}</div>${extra ? '<div style="margin-top:4px">'+extra+'</div>' : ''}</div>`;
}
</script>

<?php include 'includes/footer.php'; ?>
