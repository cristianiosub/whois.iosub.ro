<?php
require_once 'config.php';
require_once 'includes/auth.php';
require_once 'includes/db.php';
requireLogin();
requireAdmin();

$db        = getDB();
$csrfToken = getCsrfToken();
$pageTitle = 'Utilizatori';
$msg       = '';
$msgType   = 'success';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
    $action = $_POST['action'] ?? '';

    if ($action === 'add_user') {
        $username = trim($_POST['username'] ?? '');
        $phone    = preg_replace('/\D/', '', trim($_POST['phone_number'] ?? ''));
        $password = $_POST['password'] ?? '';
        $role     = ($_POST['role'] ?? 'user') === 'admin' ? 'admin' : 'user';
        $sms      = isset($_POST['sms_alerts']) ? 1 : 0;

        if (strlen($username) < 3 || strlen($username) > 50) {
            $msg = 'Username trebuie sa aiba intre 3 si 50 caractere.'; $msgType = 'danger';
        } elseif (!preg_match('/^[a-zA-Z0-9_.-]+$/', $username)) {
            $msg = 'Username poate contine doar litere, cifre, _, ., -'; $msgType = 'danger';
        } elseif (strlen($password) < 6) {
            $msg = 'Parola trebuie sa aiba minim 6 caractere.'; $msgType = 'danger';
        } elseif (strlen($phone) < 10) {
            $msg = 'Numar de telefon invalid (ex: 40727363767).'; $msgType = 'danger';
        } else {
            try {
                $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
                $db->prepare("INSERT INTO users (username, password_hash, phone_number, sms_alerts, role, created_by) VALUES (?,?,?,?,?,?)")
                   ->execute([$username, $hash, $phone, $sms, $role, $_SESSION['user_id']]);
                $msg = "Utilizator <strong>" . htmlspecialchars($username) . "</strong> creat cu succes!";
            } catch (PDOException $e) {
                $msg = ($e->getCode() === '23000') ? 'Username deja existent.' : 'Eroare: ' . $e->getMessage();
                $msgType = 'danger';
            }
        }
    }
    elseif ($action === 'update_user') {
        $id    = (int)($_POST['id'] ?? 0);
        $phone = preg_replace('/\D/', '', trim($_POST['phone_number'] ?? ''));
        $role  = ($_POST['role'] ?? 'user') === 'admin' ? 'admin' : 'user';
        $sms   = isset($_POST['sms_alerts']) ? 1 : 0;
        $pass  = $_POST['password'] ?? '';

        // Nu se poate degrada singurul admin
        if ($id === (int)$_SESSION['user_id'] && $role !== 'admin') {
            $msg = 'Nu iti poti schimba propriul rol din admin.'; $msgType = 'danger';
        } elseif ($id > 0) {
            if ($pass !== '') {
                if (strlen($pass) < 6) {
                    $msg = 'Parola trebuie sa aiba minim 6 caractere.'; $msgType = 'danger';
                } else {
                    $hash = password_hash($pass, PASSWORD_BCRYPT, ['cost' => 12]);
                    $db->prepare("UPDATE users SET phone_number=?, sms_alerts=?, role=?, password_hash=? WHERE id=?")
                       ->execute([$phone, $sms, $role, $hash, $id]);
                    $msg = 'Utilizator actualizat (parola schimbata).';
                }
            } else {
                $db->prepare("UPDATE users SET phone_number=?, sms_alerts=?, role=? WHERE id=?")
                   ->execute([$phone, $sms, $role, $id]);
                $msg = 'Utilizator actualizat.';
            }
        }
    }
    elseif ($action === 'delete_user') {
        $id = (int)($_POST['id'] ?? 0);
        if ($id === (int)$_SESSION['user_id']) {
            $msg = 'Nu te poti sterge pe tine insuti.'; $msgType = 'danger';
        } elseif ($id > 0) {
            // Verifica sa nu stergem singurul admin
            $adminCount = (int)$db->query("SELECT COUNT(*) FROM users WHERE role='admin'")->fetchColumn();
            $targetRole = $db->prepare("SELECT role FROM users WHERE id=?");
            $targetRole->execute([$id]);
            $tr = $targetRole->fetch();
            if ($tr && $tr['role'] === 'admin' && $adminCount <= 1) {
                $msg = 'Nu poti sterge singurul administrator.'; $msgType = 'danger';
            } else {
                $db->prepare("DELETE FROM users WHERE id=?")->execute([$id]);
                $msg = 'Utilizator sters.';
            }
        }
    }
}

$users = $db->query("SELECT u.*, (SELECT COUNT(*) FROM domains WHERE added_by=u.id) as domain_count FROM users u ORDER BY u.role DESC, u.id ASC")->fetchAll();

include 'includes/header.php';
?>

<div class="page-header">
    <div class="flex justify-between items-center">
        <div>
            <h1>&#128100; Utilizatori</h1>
            <p>Gestioneaza accesul la Domain Monitor</p>
        </div>
        <button class="btn btn-primary" onclick="openModal('addUserModal')">+ Utilizator nou</button>
    </div>
</div>

<?php if ($msg): ?>
<div class="alert alert-<?= $msgType ?>"><?= $msg ?></div>
<?php endif; ?>

<div class="card">
    <div class="card-header"><div class="card-title"><?= count($users) ?> utilizatori</div></div>
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Rol</th>
                    <th>Telefon</th>
                    <th>SMS Alerte</th>
                    <th>Domenii adaugate</th>
                    <th>Creat la</th>
                    <th>Actiuni</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($users as $u): ?>
            <tr>
                <td>
                    <div style="display:flex;align-items:center;gap:10px">
                        <?= userAvatarHtml($u['username'], 32, 8, .85) ?>
                        <div>
                            <div style="font-weight:600"><?= htmlspecialchars($u['username']) ?></div>
                            <?php if ((int)$u['id'] === (int)$_SESSION['user_id']): ?>
                            <div class="text-xs" style="color:var(--accent2)">Tu</div>
                            <?php endif; ?>
                        </div>
                    </div>
                </td>
                <td>
                    <?php if ($u['role'] === 'admin'): ?>
                    <span style="display:inline-flex;align-items:center;padding:3px 10px;border-radius:4px;font-size:.75rem;font-weight:600;background:rgba(245,158,11,.15);color:#fbbf24;border:1px solid rgba(245,158,11,.3)">Admin</span>
                    <?php else: ?>
                    <span style="display:inline-flex;align-items:center;padding:3px 10px;border-radius:4px;font-size:.75rem;font-weight:600;background:rgba(100,116,139,.15);color:var(--text2);border:1px solid var(--border)">User</span>
                    <?php endif; ?>
                </td>
                <td class="text-sm" style="font-family:monospace"><?= htmlspecialchars($u['phone_number']) ?></td>
                <td>
                    <span style="color:<?= $u['sms_alerts'] ? 'var(--success)' : 'var(--text3)' ?>">
                        <?= $u['sms_alerts'] ? '✓ Activ' : '✗ Oprit' ?>
                    </span>
                </td>
                <td class="text-sm text-muted"><?= (int)$u['domain_count'] ?></td>
                <td class="text-sm text-muted"><?= date('d.m.Y', strtotime($u['created_at'])) ?></td>
                <td>
                    <div class="flex gap-2">
                        <button class="btn btn-ghost btn-sm" onclick="openEditUser(<?= htmlspecialchars(json_encode($u)) ?>)">&#9998; Editeaza</button>
                        <?php if ((int)$u['id'] !== (int)$_SESSION['user_id']): ?>
                        <button class="btn btn-danger btn-sm" onclick="confirmDeleteUser(<?= (int)$u['id'] ?>, '<?= htmlspecialchars($u['username']) ?>')">&#128465;</button>
                        <?php endif; ?>
                    </div>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Info card -->
<div class="card mt-4" style="border-color:rgba(59,130,246,.2);background:rgba(59,130,246,.04)">
    <div style="display:flex;gap:12px;align-items:flex-start">
        <span style="font-size:1.2rem">&#8505;</span>
        <div style="font-size:.875rem;color:var(--text2);line-height:1.6">
            <strong style="color:var(--text)">Roluri:</strong>
            <strong>Admin</strong> — acces complet, poate gestiona utilizatori.
            <strong>User</strong> — poate vedea domenii si istoricul, dar nu poate gestiona alti utilizatori.<br>
            <strong>SMS:</strong> Fiecare utilizator cu SMS activ primeste alerte pe numarul sau de telefon cand un domeniu isi schimba statusul.
        </div>
    </div>
</div>

<!-- Modal Add User -->
<div class="modal-overlay" id="addUserModal">
    <div class="modal" style="max-width:520px">
        <div class="modal-header">
            <div class="modal-title">+ Utilizator Nou</div>
            <button class="modal-close" onclick="closeModal('addUserModal')">&#10005;</button>
        </div>
        <form method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="add_user">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
                <div class="form-group">
                    <label class="form-label">Username</label>
                    <input type="text" name="username" class="form-input" placeholder="ion.popescu" required maxlength="50" pattern="[a-zA-Z0-9_.\-]+">
                </div>
                <div class="form-group">
                    <label class="form-label">Parola</label>
                    <input type="password" name="password" class="form-input" placeholder="minim 6 caractere" required autocomplete="new-password">
                </div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
                <div class="form-group">
                    <label class="form-label">Telefon (E.164)</label>
                    <input type="text" name="phone_number" class="form-input" placeholder="40727363767" required maxlength="20">
                    <div class="form-hint">Fara + (ex: 40727363767)</div>
                </div>
                <div class="form-group">
                    <label class="form-label">Rol</label>
                    <select name="role" class="form-select">
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                    </select>
                </div>
            </div>
            <div class="form-group" style="margin-bottom:20px">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" name="sms_alerts" value="1" checked style="width:16px;height:16px">
                    <span class="form-label" style="margin:0">Alerte SMS activate</span>
                </label>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-ghost" onclick="closeModal('addUserModal')">Anuleaza</button>
                <button type="submit" class="btn btn-primary">Creeaza</button>
            </div>
        </form>
    </div>
</div>

<!-- Modal Edit User -->
<div class="modal-overlay" id="editUserModal">
    <div class="modal" style="max-width:520px">
        <div class="modal-header">
            <div class="modal-title">Editeaza Utilizator</div>
            <button class="modal-close" onclick="closeModal('editUserModal')">&#10005;</button>
        </div>
        <form method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="update_user">
            <input type="hidden" name="id" id="editUserId">
            <div style="margin-bottom:16px;padding:12px;background:var(--surface2);border-radius:10px;font-family:monospace;color:var(--accent2)" id="editUserName"></div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
                <div class="form-group">
                    <label class="form-label">Telefon</label>
                    <input type="text" name="phone_number" id="editUserPhone" class="form-input" maxlength="20">
                </div>
                <div class="form-group">
                    <label class="form-label">Rol</label>
                    <select name="role" id="editUserRole" class="form-select">
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                    </select>
                </div>
            </div>
            <div class="form-group" style="margin-bottom:16px">
                <label class="form-label">Parola noua (lasa gol pentru a nu schimba)</label>
                <input type="password" name="password" class="form-input" placeholder="Lasa gol = parola ramane neschimbata" autocomplete="new-password">
            </div>
            <div class="form-group" style="margin-bottom:20px">
                <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
                    <input type="checkbox" name="sms_alerts" id="editUserSms" value="1" style="width:16px;height:16px">
                    <span class="form-label" style="margin:0">Alerte SMS activate</span>
                </label>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-ghost" onclick="closeModal('editUserModal')">Anuleaza</button>
                <button type="submit" class="btn btn-primary">Salveaza</button>
            </div>
        </form>
    </div>
</div>

<!-- Modal Delete User -->
<div class="modal-overlay" id="deleteUserModal">
    <div class="modal" style="max-width:400px">
        <div class="modal-header">
            <div class="modal-title" style="color:var(--danger)">Sterge Utilizator</div>
            <button class="modal-close" onclick="closeModal('deleteUserModal')">&#10005;</button>
        </div>
        <p style="color:var(--text2);margin-bottom:20px">Stergi utilizatorul <strong id="deleteUserName" style="color:var(--text)"></strong>? Domeniile adaugate de el raman in sistem.</p>
        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <input type="hidden" name="action" value="delete_user">
            <input type="hidden" name="id" id="deleteUserId">
            <div class="modal-footer">
                <button type="button" class="btn btn-ghost" onclick="closeModal('deleteUserModal')">Anuleaza</button>
                <button type="submit" class="btn btn-danger">Sterge</button>
            </div>
        </form>
    </div>
</div>

<script>
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

function openEditUser(u) {
    document.getElementById('editUserId').value    = u.id;
    document.getElementById('editUserName').textContent = u.username;
    document.getElementById('editUserPhone').value = u.phone_number;
    document.getElementById('editUserRole').value  = u.role;
    document.getElementById('editUserSms').checked = u.sms_alerts == 1;
    openModal('editUserModal');
}

function confirmDeleteUser(id, name) {
    document.getElementById('deleteUserId').value = id;
    document.getElementById('deleteUserName').textContent = name;
    openModal('deleteUserModal');
}

document.querySelectorAll('.modal-overlay').forEach(el => {
    el.addEventListener('click', function(e) { if(e.target===this) this.classList.remove('open'); });
});
</script>

<?php include 'includes/footer.php'; ?>
