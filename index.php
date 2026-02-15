<?php
session_start();
$config = require __DIR__ . '/config.php';

const USER_STORAGE_LIMIT = 1099511627776; // 1 TB

if (!is_dir($config['upload_dir'])) {
    mkdir($config['upload_dir'], 0775, true);
}

function db(array $config): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s', $config['db']['host'], $config['db']['name'], $config['db']['charset']);
    $pdo = new PDO($dsn, $config['db']['user'], $config['db']['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    return $pdo;
}

function ensure_schema(PDO $pdo): void {
    $pdo->exec("CREATE TABLE IF NOT EXISTS folders (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(50) NOT NULL,
        name VARCHAR(255) NOT NULL,
        parent_id BIGINT UNSIGNED NULL,
        shared_token VARCHAR(64) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_folder_token (shared_token),
        INDEX idx_user_parent (user_id, parent_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS files (
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      user_id VARCHAR(50) NOT NULL,
      user_name VARCHAR(120) NOT NULL,
      folder_id BIGINT UNSIGNED NULL,
      filename VARCHAR(255) NOT NULL,
      stored_name VARCHAR(255) NOT NULL,
      mime_type VARCHAR(120) NOT NULL,
      size_bytes BIGINT UNSIGNED NOT NULL,
      relative_path VARCHAR(255) NOT NULL,
      shared_token VARCHAR(64) NULL,
      is_starred TINYINT(1) NOT NULL DEFAULT 0,
      is_trashed TINYINT(1) NOT NULL DEFAULT 0,
      download_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
      uploader_ip VARCHAR(64) NULL,
      uploader_country CHAR(2) NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_file_token (shared_token),
      INDEX idx_user_status (user_id, is_trashed, is_starred),
      INDEX idx_user_created (user_id, created_at),
      INDEX idx_user_folder (user_id, folder_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $cols = $pdo->query("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='files'")->fetchAll(PDO::FETCH_COLUMN);
    if (!in_array('folder_id', $cols, true)) $pdo->exec("ALTER TABLE files ADD COLUMN folder_id BIGINT UNSIGNED NULL, ADD INDEX idx_user_folder (user_id, folder_id)");
    if (!in_array('shared_token', $cols, true)) $pdo->exec("ALTER TABLE files ADD COLUMN shared_token VARCHAR(64) NULL, ADD UNIQUE KEY uq_file_token (shared_token)");
    if (!in_array('download_count', $cols, true)) $pdo->exec("ALTER TABLE files ADD COLUMN download_count BIGINT UNSIGNED NOT NULL DEFAULT 0");
    if (!in_array('uploader_ip', $cols, true)) $pdo->exec("ALTER TABLE files ADD COLUMN uploader_ip VARCHAR(64) NULL");
    if (!in_array('uploader_country', $cols, true)) $pdo->exec("ALTER TABLE files ADD COLUMN uploader_country CHAR(2) NULL");

    $pdo->exec("CREATE TABLE IF NOT EXISTS app_settings (
      `key` VARCHAR(100) PRIMARY KEY,
      `value` TEXT NOT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $fcols = $pdo->query("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='folders'")->fetchAll(PDO::FETCH_COLUMN);
    if (!in_array('shared_token', $fcols, true)) $pdo->exec("ALTER TABLE folders ADD COLUMN shared_token VARCHAR(64) NULL, ADD UNIQUE KEY uq_folder_token (shared_token)");
}

function xf_auth(array $config, string $login, string $password): ?array {
    $ch = curl_init($config['xf']['base_url'] . '/api/auth');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POSTFIELDS => http_build_query(['login' => $login, 'password' => $password]),
        CURLOPT_HTTPHEADER => ['XF-Api-Key: ' . $config['xf']['api_key']],
        CURLOPT_TIMEOUT => 20,
    ]);
    $res = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if (!$res || $code >= 400) return null;
    $decoded = json_decode($res, true);
    if (empty($decoded['success']) || empty($decoded['user'])) return null;
    $u = $decoded['user'];
    return [
        'id' => (string)($u['user_id'] ?? $u['id'] ?? $login),
        'name' => $u['username'] ?? $login,
        'avatar' => $u['avatar_urls']['o'] ?? $u['avatar_urls']['h'] ?? $u['avatar_urls']['l'] ?? null,
    ];
}

function require_login(): void {
    if (empty($_SESSION['user'])) {
        header('Location: /login');
        exit;
    }
}

function is_admin_user(array $config, ?array $user): bool {
    if (!$user) return false;
    $allowed = $config['admin_user_ids'] ?? [];
    if (!is_array($allowed)) return false;
    return in_array((string)($user['id'] ?? ''), array_map('strval', $allowed), true);
}

function require_admin(array $config): void {
    require_login();
    if (!is_admin_user($config, $_SESSION['user'] ?? null)) {
        http_response_code(403);
        exit('Forbidden');
    }
}

function get_setting(PDO $pdo, string $key, ?string $default = null): ?string {
    $st = $pdo->prepare('SELECT `value` FROM app_settings WHERE `key`=? LIMIT 1');
    $st->execute([$key]);
    $v = $st->fetchColumn();
    return $v === false ? $default : (string)$v;
}

function set_setting(PDO $pdo, string $key, string $value): void {
    $st = $pdo->prepare('INSERT INTO app_settings (`key`,`value`) VALUES (?,?) ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)');
    $st->execute([$key, $value]);
}

function get_allowed_extensions(PDO $pdo): ?array {
    $raw = trim((string)get_setting($pdo, 'allowed_extensions', ''));
    if ($raw === '' || $raw === '*') return null;
    $items = array_values(array_filter(array_map(static fn($v)=>strtolower(trim($v)), explode(',', $raw))));
    return $items ?: null;
}

function is_extension_allowed(PDO $pdo, string $filename): bool {
    $allowed = get_allowed_extensions($pdo);
    if ($allowed === null) return true;
    $ext = strtolower((string)pathinfo($filename, PATHINFO_EXTENSION));
    return $ext !== '' && in_array($ext, $allowed, true);
}

function get_client_ip(): string {
    $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
    foreach ($keys as $k) {
        if (!empty($_SERVER[$k])) {
            $raw = (string)$_SERVER[$k];
            $ip = trim(explode(',', $raw)[0]);
            if ($ip !== '') return substr($ip, 0, 64);
        }
    }
    return '0.0.0.0';
}

function get_country_code_from_request(): string {
    $code = strtoupper(trim((string)($_SERVER['HTTP_CF_IPCOUNTRY'] ?? $_SERVER['GEOIP_COUNTRY_CODE'] ?? '')));
    if (preg_match('/^[A-Z]{2}$/', $code)) return $code;
    return 'ZZ';
}

function format_bytes(int $bytes): string {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($units) - 1) { $bytes /= 1024; $i++; }
    return round($bytes, 2) . ' ' . $units[$i];
}

function get_user_storage(PDO $pdo, string $userId): int {
    $sum = $pdo->prepare('SELECT COALESCE(SUM(size_bytes),0) FROM files WHERE user_id=? AND is_trashed=0');
    $sum->execute([$userId]);
    return (int)$sum->fetchColumn();
}

function file_url(array $f): string { return '/d/' . (int)$f['id'] . '/' . rawurlencode((string)$f['filename']); }
function share_url(string $token, string $filename): string {
    $ext = strtolower((string)pathinfo($filename, PATHINFO_EXTENSION));
    if ($ext === '') $ext = 'bin';
    return '/s/' . $token . '.' . $ext;
}
function token(): string { return substr(bin2hex(random_bytes(3)), 0, 5); }

function generate_share_token(PDO $pdo): string {
    for ($i = 0; $i < 20; $i++) {
        $candidate = token();
        $q = $pdo->prepare('SELECT 1 FROM files WHERE shared_token=? LIMIT 1');
        $q->execute([$candidate]);
        if (!$q->fetchColumn()) return $candidate;
    }
    return substr(bin2hex(random_bytes(8)), 0, 12);
}

function issue_download_gate(array $file, bool $isShared): string {
    if (!isset($_SESSION['download_gate']) || !is_array($_SESSION['download_gate'])) {
        $_SESSION['download_gate'] = [];
    }
    $gate = bin2hex(random_bytes(24));
    $_SESSION['download_gate'][$gate] = [
        'file_id' => (int)$file['id'],
        'is_shared' => $isShared ? 1 : 0,
        'expires_at' => time() + 300,
    ];
    return $gate;
}

function validate_download_gate(array $file, bool $isShared, ?string $gate): bool {
    if (!$gate || empty($_SESSION['download_gate'][$gate])) return false;
    $meta = $_SESSION['download_gate'][$gate];
    unset($_SESSION['download_gate'][$gate]);
    return (int)($meta['file_id'] ?? 0) === (int)$file['id']
        && (int)($meta['is_shared'] ?? -1) === ($isShared ? 1 : 0)
        && (int)($meta['expires_at'] ?? 0) >= time();
}

function increment_download_count(PDO $pdo, int $fileId): void {
    $st = $pdo->prepare('UPDATE files SET download_count = COALESCE(download_count,0) + 1 WHERE id=?');
    $st->execute([$fileId]);
}

function should_show_download_page(string $filename, string $mime): bool {
    $ext = strtolower((string)pathinfo($filename, PATHINFO_EXTENSION));
    $blocked = ['zip','rar','7z','iso','pkg','tar','gz','bz2','xz','img'];
    if (in_array($ext, $blocked, true)) return true;
    if (str_starts_with($mime, 'video/')) return false;
    if (str_starts_with($mime, 'audio/')) return false;
    if (str_starts_with($mime, 'image/')) return false;
    if ($mime === 'application/pdf' || $mime === 'text/plain') return false;
    return in_array($ext, ['exe','msi','dmg','apk','bin'], true);
}

function render_download_page(array $file, string $downloadUrl, bool $isShared=false): void {
    $name = htmlspecialchars((string)$file['filename']);
    $uploader = htmlspecialchars((string)($file['user_name'] ?? 'unknown'));
    $size = format_bytes((int)($file['size_bytes'] ?? 0));
    $date = htmlspecialchars((string)($file['created_at'] ?? ''));
    $ext = htmlspecialchars(strtolower((string)pathinfo((string)$file['filename'], PATHINFO_EXTENSION)) ?: 'file');
    $title = $name . ' | تحميل';
    $downloadUrlJs = json_encode($downloadUrl, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $downloads = (int)($file['download_count'] ?? 0);
    echo "<!doctype html><html lang='ar' dir='rtl'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{$title}</title>
    <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css'>
    <style>
      :root{--primary:#1e88e5;--bg:#f2f2f2;--text:#1f2937;--muted:#6b7280;--border:#dbe3ea}*{box-sizing:border-box}
      body{margin:0;background:var(--bg);font-family:Cairo,Tahoma,sans-serif;color:var(--text);min-height:100vh;display:flex;flex-direction:column}
      .topbar{background:#fff;border-bottom:1px solid var(--border);padding:12px 20px}.topbar .brand{display:flex;align-items:center;gap:9px;font-weight:700}.topbar i{color:var(--primary)}
      .wrap{max-width:1080px;margin:22px auto;padding:0 12px;width:100%;flex:1}
      .file-name{font-size:37px;text-align:center;margin:0 0 10px;color:#30363d;word-break:break-word}
      .file-sub{text-align:center;color:#7a8699;font-size:34px;margin-bottom:10px}
      .blue-line{height:3px;background:var(--primary);margin-bottom:26px}
      .box{display:grid;grid-template-columns:1fr 1fr;gap:14px}
      .card{background:#fff;border:1px solid var(--border);border-radius:12px;padding:16px}
      .download-card{display:flex;flex-direction:column;justify-content:center;align-items:center;min-height:320px;background:#f6fbef}
      .status{font-weight:700;color:#4a7d16;margin-bottom:16px}.status i{margin-left:6px}
      .btn{display:flex;align-items:center;justify-content:center;gap:10px;width:82%;height:120px;background:var(--primary);color:#fff;font-size:38px;font-weight:700;border-radius:8px;text-decoration:none;cursor:not-allowed;opacity:.65}
      .btn.active{cursor:pointer;opacity:1}.note{margin-top:12px;font-size:14px;color:var(--muted)}
      .meta-title{font-size:22px;margin:0 0 14px;display:flex;align-items:center;gap:8px;color:#d97706}
      .meta{width:100%;border-collapse:collapse}.meta td{border:1px solid #ececec;padding:9px 11px}.meta td:first-child{background:#fafafa;width:170px;font-weight:700}
      .footer{background:#fff;border-top:1px solid var(--border);padding:14px 20px;text-align:center;color:#6b7280;font-size:13px;margin-top:auto}
      @media(max-width:900px){.box{grid-template-columns:1fr}.file-name{font-size:30px}.btn{width:100%;font-size:32px}}
    </style></head><body>
    <header class='topbar'><div class='brand'><i class='fa-solid fa-cloud-arrow-down'></i> Safe Drive Download</div></header>
    <main class='wrap'>
      <h1 class='file-name'>{$name}</h1>
      <div class='file-sub'>{$title}</div>
      <div class='blue-line'></div>
      <div class='box'>
        <section class='card download-card'>
          <div class='status'><i class='fa-solid fa-circle-check'></i> [ تم إيجاد الملف ]</div>
          <a id='dlBtn' class='btn'><i class='fa-solid fa-download'></i> <span>تحميل الملف خلال <span id='count'>8</span> ثوانٍ</span></a>
          <div class='note'>" . ($isShared ? 'رابط مشاركة عام' : 'رابط خاص بالمستخدم') . "</div>
        </section>
        <section class='card meta-card'>
          <h2 class='meta-title'><i class='fa-regular fa-file-lines'></i> معلومات عن الملف</h2>
          <table class='meta'>
            <tr><td>قام برفعه</td><td>{$uploader}</td></tr>
            <tr><td>نوع الملف</td><td>{$ext}</td></tr>
            <tr><td>حجم الملف</td><td>{$size}</td></tr>
            <tr><td>تاريخ الملف</td><td>{$date}</td></tr>
            <tr><td>عدد التحميلات</td><td>{$downloads}</td></tr>
          </table>
        </section>
      </div>
    </main>
    <footer class='footer'>جميع الحقوق محفوظة - Safe Drive</footer>
    <script>
      let c=8;const el=document.getElementById('count');const b=document.getElementById('dlBtn');
      const finalUrl={$downloadUrlJs};
      const t=setInterval(()=>{c--;el.textContent=c;if(c<=0){clearInterval(t);b.classList.add('active');b.innerHTML=`<i class='fa-solid fa-download'></i> <span>لتحميل الملف انقر هنا</span>`;b.href=finalUrl;}},1000);
    </script></body></html>";
    exit;
}

$pdo = null;
$dbError = null;
try {
    $pdo = db($config);
    ensure_schema($pdo);
} catch (Throwable $e) {
    $dbError = $e->getMessage();
}

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '/';
$path = trim($uri, '/');
$segments = $path === '' ? [] : explode('/', $path);
$cssVersion = @filemtime(__DIR__ . '/public/assets/style.css') ?: time();

if (!empty($segments[0]) && $segments[0] === 's' && isset($segments[1])) {
    if (!$pdo) { http_response_code(500); exit('DB error'); }
    $part = $segments[1];
    $token = $part;
    if (str_contains($part, '.')) {
        $token = explode('.', $part, 2)[0];
    }
    $q = $pdo->prepare('SELECT * FROM files WHERE shared_token=? LIMIT 1');
    $q->execute([$token]);
    $file = $q->fetch();
    if (!$file) { http_response_code(404); exit('Shared file not found'); }

    $downloadFlag = isset($_GET['download']) && $_GET['download'] === '1';
    $gate = $_GET['gate'] ?? null;
    $shareUrl = share_url((string)$file['shared_token'], (string)$file['filename']);
    $requiresGate = should_show_download_page((string)$file['filename'], (string)$file['mime_type']);
    if ($requiresGate) {
        if (!$downloadFlag || !validate_download_gate($file, true, is_string($gate) ? $gate : null)) {
            $newGate = issue_download_gate($file, true);
            render_download_page($file, $shareUrl . '?download=1&gate=' . rawurlencode($newGate), true);
        }
    }

    $abs = __DIR__ . '/' . $file['relative_path'];
    if (!is_file($abs)) { http_response_code(404); exit('Missing file'); }
    increment_download_count($pdo, (int)$file['id']);
    header('Content-Type: ' . ($file['mime_type'] ?: 'application/octet-stream'));
    header('Content-Length: ' . filesize($abs));
    $disp = $downloadFlag ? 'attachment' : 'inline';
    header("Content-Disposition: {$disp}; filename*=UTF-8''" . rawurlencode($file['filename']));
    readfile($abs);
    exit;
}

if (!empty($segments[0]) && $segments[0] === 'd' && isset($segments[1])) {
    require_login();
    if (!$pdo) { http_response_code(500); exit('Database unavailable'); }
    $id = (int)$segments[1];
    $q = $pdo->prepare('SELECT * FROM files WHERE id=? AND user_id=? LIMIT 1');
    $q->execute([$id, $_SESSION['user']['id']]);
    $file = $q->fetch();
    if (!$file) { http_response_code(404); exit('Not found'); }

    $downloadFlag = isset($_GET['download']) && $_GET['download'] === '1';
    $gate = $_GET['gate'] ?? null;
    $privateUrl = file_url($file);
    $requiresGate = should_show_download_page((string)$file['filename'], (string)$file['mime_type']);
    if ($requiresGate) {
        if (!$downloadFlag || !validate_download_gate($file, false, is_string($gate) ? $gate : null)) {
            $newGate = issue_download_gate($file, false);
            render_download_page($file, $privateUrl . '?download=1&gate=' . rawurlencode($newGate), false);
        }
    }

    $abs = __DIR__ . '/' . $file['relative_path'];
    if (!is_file($abs)) { http_response_code(404); exit('Missing'); }
    increment_download_count($pdo, (int)$file['id']);
    header('Content-Type: ' . ($file['mime_type'] ?: 'application/octet-stream'));
    header('Content-Length: ' . filesize($abs));
    $disp = $downloadFlag ? 'attachment' : 'inline';
    header("Content-Disposition: {$disp}; filename*=UTF-8''" . rawurlencode($file['filename']));
    readfile($abs);
    exit;
}

if (!empty($segments[0]) && $segments[0] === 'logout') {
    session_destroy();
    header('Location: /login');
    exit;
}

$route = 'login';
$currentFolderId = null;
if (empty($segments)) $route = empty($_SESSION['user']) ? 'login' : 'drive';
elseif ($segments[0] === 'login') $route = 'login';
elseif ($segments[0] === 'drive' || $segments[0] === 'home') $route = 'drive';
elseif ($segments[0] === 'recent') $route = 'recent';
elseif ($segments[0] === 'starred') $route = 'starred';
elseif ($segments[0] === 'trash') $route = 'trash';
elseif ($segments[0] === 'search') $route = 'search';
elseif ($segments[0] === 'folders' && isset($segments[1])) { $route = 'folder'; $currentFolderId = (int)$segments[1]; }
elseif ($segments[0] === 'admin') {
    $route = 'admin';
    if (isset($segments[1])) {
        if ($segments[1] === 'files') $route = 'admin_files';
        elseif ($segments[1] === 'images') $route = 'admin_images';
        elseif ($segments[1] === 'settings') $route = 'admin_settings';
    }
}

$flash = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    try {
        if ($action === 'login') {
            $xf = xf_auth($config, trim($_POST['username'] ?? ''), (string)($_POST['password'] ?? ''));
            if (!$xf) throw new RuntimeException('فشل تسجيل الدخول عبر XenForo API.');
            $_SESSION['user'] = $xf;
            header('Location: /drive'); exit;
        }

        require_login();
        if (!$pdo) throw new RuntimeException('قاعدة البيانات غير متاحة حالياً.');
        $user = $_SESSION['user'];
        $redirect = $_POST['redirect'] ?? '/drive';

        if (str_starts_with($action, 'admin_')) {
            require_admin($config);

            if ($action === 'admin_set_extensions') {
                $extRaw = trim((string)($_POST['extensions'] ?? '*'));
                $clean = $extRaw === '*' ? '*' : implode(',', array_values(array_unique(array_filter(array_map(static fn($x)=>strtolower(trim($x, " .\t\n\r\0\x0B")), explode(',', $extRaw))))));
                if ($clean === '') $clean = '*';
                set_setting($pdo, 'allowed_extensions', $clean);
                $redirect = '/admin';
            }

            if ($action === 'admin_bulk_files') {
                $ids = $_POST['file_ids'] ?? [];
                if (!is_array($ids) || !$ids) throw new RuntimeException('اختر ملفات أولاً.');
                $ids = array_values(array_filter(array_map('intval', $ids), static fn($v)=>$v>0));
                if (!$ids) throw new RuntimeException('اختر ملفات صحيحة.');
                $op = (string)($_POST['bulk_op'] ?? '');
                $pl = implode(',', array_fill(0, count($ids), '?'));

                if ($op === 'delete') {
                    $q = $pdo->prepare("SELECT relative_path FROM files WHERE id IN ($pl)");
                    $q->execute($ids);
                    foreach ($q->fetchAll() as $r) { $abs = __DIR__ . '/' . $r['relative_path']; if (is_file($abs)) @unlink($abs); }
                    $d = $pdo->prepare("DELETE FROM files WHERE id IN ($pl)");
                    $d->execute($ids);
                } elseif ($op === 'trash') {
                    $u = $pdo->prepare("UPDATE files SET is_trashed=1 WHERE id IN ($pl)");
                    $u->execute($ids);
                } elseif ($op === 'unshare') {
                    $u = $pdo->prepare("UPDATE files SET shared_token=NULL WHERE id IN ($pl)");
                    $u->execute($ids);
                } elseif ($op === 'move') {
                    $targetRaw = $_POST['target_folder_id'] ?? '';
                    $target = ($targetRaw === '' ? null : (int)$targetRaw);
                    $u = $pdo->prepare("UPDATE files SET folder_id=? WHERE id IN ($pl)");
                    $u->execute(array_merge([$target], $ids));
                } else {
                    throw new RuntimeException('عملية غير مدعومة.');
                }
                $redirect = '/admin';
            }

            if ($action === 'admin_purge_user') {
                $uid = trim((string)($_POST['target_user_id'] ?? ''));
                if ($uid === '') throw new RuntimeException('اختر مستخدم أولاً.');
                $q = $pdo->prepare('SELECT relative_path FROM files WHERE user_id=?');
                $q->execute([$uid]);
                foreach ($q->fetchAll() as $r) { $abs = __DIR__ . '/' . $r['relative_path']; if (is_file($abs)) @unlink($abs); }
                $pdo->prepare('DELETE FROM files WHERE user_id=?')->execute([$uid]);
                $pdo->prepare('DELETE FROM folders WHERE user_id=?')->execute([$uid]);
                $redirect = '/admin';
            }
        }

        if ($action === 'create_folder') {
            $name = trim((string)($_POST['folder_name'] ?? ''));
            if ($name === '') throw new RuntimeException('اكتب اسم المجلد.');
            $parentRaw = $_POST['folder_id'] ?? null;
            $parentId = ($parentRaw === '' || $parentRaw === null) ? null : (int)$parentRaw;
            $st = $pdo->prepare('INSERT INTO folders (user_id,name,parent_id) VALUES (?,?,?)');
            $st->execute([$user['id'], $name, $parentId]);
        }

        if ($action === 'rename_file') {
            $id = (int)($_POST['id'] ?? 0);
            $newName = trim((string)($_POST['new_name'] ?? ''));
            if ($newName === '') throw new RuntimeException('الاسم الجديد فارغ.');
            $st = $pdo->prepare('UPDATE files SET filename=? WHERE id=? AND user_id=?');
            $st->execute([$newName, $id, $user['id']]);
        }

        if ($action === 'rename_folder') {
            $id = (int)($_POST['id'] ?? 0);
            $newName = trim((string)($_POST['new_name'] ?? ''));
            if ($newName === '') throw new RuntimeException('الاسم الجديد فارغ.');
            $st = $pdo->prepare('UPDATE folders SET name=? WHERE id=? AND user_id=?');
            $st->execute([$newName, $id, $user['id']]);
        }

        if ($action === 'toggle_share_file') {
            $id = (int)($_POST['id'] ?? 0);
            $q = $pdo->prepare('SELECT shared_token FROM files WHERE id=? AND user_id=?');
            $q->execute([$id, $user['id']]);
            $row = $q->fetch();
            if ($row) {
                $tokenValue = $row['shared_token'] ? null : generate_share_token($pdo);
                $st = $pdo->prepare('UPDATE files SET shared_token=? WHERE id=? AND user_id=?');
                $st->execute([$tokenValue, $id, $user['id']]);
            }
        }

        if ($action === 'upload' || $action === 'upload_ajax' || $action === 'upload_folder') {
            if (empty($_FILES['file']['name']) && empty($_FILES['files']['name'])) throw new RuntimeException('اختر ملفاً أو مجلداً أولاً.');
            $currentStorage = get_user_storage($pdo, $user['id']);
            $uploadIp = get_client_ip();
            $uploadCountry = get_country_code_from_request();

            $processSingle = function(array $one, ?int $folderId, ?string $displayName=null) use (&$currentStorage, $config, $pdo, $user, $uploadIp, $uploadCountry) {
                if ($one['error'] !== UPLOAD_ERR_OK) throw new RuntimeException('فشل رفع ملف.');
                if ((int)$one['size'] > (int)$config['max_upload_size']) throw new RuntimeException('الملف أكبر من 5 جيجابايت.');
                if (($currentStorage + (int)$one['size']) > USER_STORAGE_LIMIT) throw new RuntimeException('تم تجاوز سعة المستخدم 1 تيرابايت.');
                $name = $displayName ?: (string)$one['name'];
                if (!is_extension_allowed($pdo, $name)) throw new RuntimeException('امتداد الملف غير مسموح به من الإدارة.');
                $ext = pathinfo($name, PATHINFO_EXTENSION);
                $stored = bin2hex(random_bytes(20)) . ($ext ? '.' . $ext : '');
                $dest = $config['upload_dir'] . '/' . $stored;
                if (!move_uploaded_file($one['tmp_name'], $dest)) throw new RuntimeException('تعذر حفظ الملف.');
                $mime = mime_content_type($dest) ?: 'application/octet-stream';
                $st = $pdo->prepare('INSERT INTO files (user_id,user_name,folder_id,filename,stored_name,mime_type,size_bytes,relative_path,uploader_ip,uploader_country) VALUES (?,?,?,?,?,?,?,?,?,?)');
                $st->execute([$user['id'], $user['name'], $folderId, $name, $stored, $mime, (int)$one['size'], 'uploads/' . $stored, $uploadIp, $uploadCountry]);
                $currentStorage += (int)$one['size'];
            };

            if ($action === 'upload' || $action === 'upload_ajax') {
                $folderRaw = $_POST['folder_id'] ?? null;
                $folderId = ($folderRaw === '' || $folderRaw === null) ? null : (int)$folderRaw;
                $processSingle($_FILES['file'], $folderId);
            } else {
                $parentRaw = $_POST['folder_id'] ?? null;
                $parentId = ($parentRaw === '' || $parentRaw === null) ? null : (int)$parentRaw;

                $names = $_FILES['files']['name'] ?? [];
                $tmpNames = $_FILES['files']['tmp_name'] ?? [];
                $sizes = $_FILES['files']['size'] ?? [];
                $errors = $_FILES['files']['error'] ?? [];
                $relPaths = $_POST['relative_paths'] ?? [];
                if (!is_array($names)) $names = [$names];

                $folderMap = []; // path => id
                foreach ($names as $i => $nm) {
                    if (($errors[$i] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) continue;
                    $rel = (string)($relPaths[$i] ?? $nm);
                    $parts = array_values(array_filter(explode('/', str_replace('\\', '/', $rel)), 'strlen'));
                    if (!$parts) continue;
                    $filename = array_pop($parts);
                    $currParent = $parentId;
                    $built = '';
                    foreach ($parts as $segment) {
                        $built .= '/' . $segment;
                        if (isset($folderMap[$built])) { $currParent = $folderMap[$built]; continue; }
                        $q = $pdo->prepare('SELECT id FROM folders WHERE user_id=? AND name=? AND ((parent_id IS NULL AND ? IS NULL) OR parent_id=?) LIMIT 1');
                        $q->execute([$user['id'], $segment, $currParent, $currParent]);
                        $f = $q->fetch();
                        if ($f) $newId = (int)$f['id'];
                        else {
                            $ins = $pdo->prepare('INSERT INTO folders (user_id,name,parent_id) VALUES (?,?,?)');
                            $ins->execute([$user['id'], $segment, $currParent]);
                            $newId = (int)$pdo->lastInsertId();
                        }
                        $folderMap[$built] = $newId;
                        $currParent = $newId;
                    }
                    $processSingle([
                        'name' => $filename,
                        'tmp_name' => $tmpNames[$i],
                        'size' => $sizes[$i],
                        'error' => $errors[$i]
                    ], $currParent, $filename);
                }
            }

            if ($action === 'upload_ajax') {
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(['ok' => true, 'message' => 'تم رفع الملف بنجاح']);
                exit;
            }
        }

        if ($action === 'delete_folder') {
            $id = (int)($_POST['id'] ?? 0);
            $move = $pdo->prepare('UPDATE files SET folder_id=NULL WHERE folder_id=? AND user_id=?');
            $move->execute([$id, $user['id']]);
            $del = $pdo->prepare('DELETE FROM folders WHERE id=? AND user_id=?');
            $del->execute([$id, $user['id']]);
        }

        if ($action === 'move_file') {
            $id = (int)($_POST['id'] ?? 0);
            $toRaw = $_POST['target_folder_id'] ?? '';
            $to = ($toRaw === '') ? null : (int)$toRaw;
            $st = $pdo->prepare('UPDATE files SET folder_id=? WHERE id=? AND user_id=?');
            $st->execute([$to, $id, $user['id']]);
        }

        if (in_array($action, ['toggle_star','trash','restore','delete'], true)) {
            $id = (int)($_POST['id'] ?? 0);
            if ($action === 'toggle_star') {
                $st = $pdo->prepare('UPDATE files SET is_starred=1-is_starred WHERE id=? AND user_id=?');
                $st->execute([$id, $user['id']]);
            } elseif ($action === 'trash') {
                $st = $pdo->prepare('UPDATE files SET is_trashed=1 WHERE id=? AND user_id=?');
                $st->execute([$id, $user['id']]);
            } elseif ($action === 'restore') {
                $st = $pdo->prepare('UPDATE files SET is_trashed=0 WHERE id=? AND user_id=?');
                $st->execute([$id, $user['id']]);
            } else {
                $q = $pdo->prepare('SELECT relative_path FROM files WHERE id=? AND user_id=?');
                $q->execute([$id, $user['id']]);
                $row = $q->fetch();
                if ($row && is_file(__DIR__ . '/' . $row['relative_path'])) unlink(__DIR__ . '/' . $row['relative_path']);
                $st = $pdo->prepare('DELETE FROM files WHERE id=? AND user_id=?');
                $st->execute([$id, $user['id']]);
            }
        }

        header('Location: ' . $redirect);
        exit;
    } catch (Throwable $e) {
        if ($action === 'upload_ajax') {
            header('Content-Type: application/json; charset=utf-8', true, 400);
            echo json_encode(['ok' => false, 'message' => $e->getMessage()]);
            exit;
        }
        $flash = ['type' => 'error', 'msg' => $e->getMessage()];
    }
}

$user = $_SESSION['user'] ?? null;
if ($route !== 'login') require_login();
if (str_starts_with($route, 'admin')) require_admin($config);

$files = [];
$folders = [];
$allFolders = [];
$storage = 0;
$search = trim((string)($_GET['q'] ?? ''));
$pageTitle = 'My Drive';
$adminStats = ['files'=>0,'users'=>0,'shared'=>0,'size'=>0,'downloads'=>0];
$adminFiles = [];
$adminUsers = [];
$adminFolders = [];
$adminCountryStats = [];
$adminUploadsByMonth = [];
$adminImageFiles = [];
$allowedExtDisplay = '*';

if ($user && str_starts_with($route, 'admin') && $pdo) {
    $adminStats = [
        'files' => (int)$pdo->query('SELECT COUNT(*) FROM files')->fetchColumn(),
        'users' => (int)$pdo->query('SELECT COUNT(DISTINCT user_id) FROM files')->fetchColumn(),
        'shared' => (int)$pdo->query('SELECT COUNT(*) FROM files WHERE shared_token IS NOT NULL')->fetchColumn(),
        'size' => (int)$pdo->query('SELECT COALESCE(SUM(size_bytes),0) FROM files')->fetchColumn(),
        'downloads' => (int)$pdo->query('SELECT COALESCE(SUM(download_count),0) FROM files')->fetchColumn(),
    ];
    $adminFiles = $pdo->query('SELECT id,user_id,user_name,filename,mime_type,size_bytes,folder_id,shared_token,is_trashed,created_at,uploader_country FROM files ORDER BY created_at DESC LIMIT 800')->fetchAll();
    $adminUsers = $pdo->query('SELECT user_id, MIN(user_name) user_name, COUNT(*) files_count, COALESCE(SUM(size_bytes),0) total_size FROM files GROUP BY user_id ORDER BY files_count DESC LIMIT 500')->fetchAll();
    $adminFolders = $pdo->query('SELECT id,name,user_id FROM folders ORDER BY id DESC LIMIT 1000')->fetchAll();

    $stCountry = $pdo->query("SELECT COALESCE(NULLIF(uploader_country,''),'ZZ') country, COUNT(*) files_count, COUNT(DISTINCT user_id) uploaders_count FROM files GROUP BY COALESCE(NULLIF(uploader_country,''),'ZZ') ORDER BY files_count DESC");
    $adminCountryStats = $stCountry->fetchAll();

    $stMonth = $pdo->query("SELECT DATE_FORMAT(created_at, '%Y-%m') month_key, COUNT(*) files_count FROM files GROUP BY DATE_FORMAT(created_at, '%Y-%m') ORDER BY month_key ASC LIMIT 12");
    $adminUploadsByMonth = $stMonth->fetchAll();

    $stImages = $pdo->query("SELECT id,filename,relative_path,size_bytes,user_name,user_id,created_at FROM files WHERE mime_type LIKE 'image/%' AND is_trashed=0 ORDER BY created_at DESC LIMIT 120");
    $adminImageFiles = $stImages->fetchAll();

    $allowedExtDisplay = get_setting($pdo, 'allowed_extensions', '*') ?: '*';
    $pageTitle = 'لوحة تحكم الإدارة';
}

if ($user && $route !== 'login' && $route !== 'admin' && $pdo) {
    $storage = get_user_storage($pdo, $user['id']);

    $all = $pdo->prepare('SELECT id,name,parent_id FROM folders WHERE user_id=? ORDER BY name');
    $all->execute([$user['id']]);
    $allFolders = $all->fetchAll();

    if (in_array($route, ['drive','folder'], true)) {
        $parent = $route === 'folder' ? $currentFolderId : null;
        $fdr = $pdo->prepare("SELECT f.*, 
            (SELECT relative_path FROM files x WHERE x.user_id=f.user_id AND x.folder_id=f.id AND x.is_trashed=0 AND x.mime_type LIKE 'image/%' ORDER BY x.created_at DESC LIMIT 1) preview_image,
            (SELECT COUNT(*) FROM files x WHERE x.user_id=f.user_id AND x.folder_id=f.id AND x.is_trashed=0) items_count
            FROM folders f WHERE f.user_id=? AND ((f.parent_id IS NULL AND ? IS NULL) OR f.parent_id=?) ORDER BY f.name");
        $fdr->execute([$user['id'], $parent, $parent]);
        $folders = $fdr->fetchAll();
    }

    $where = 'user_id=:uid';
    if ($route === 'trash') $where .= ' AND is_trashed=1'; else $where .= ' AND is_trashed=0';
    if ($route === 'starred') $where .= ' AND is_starred=1';
    if ($route === 'search') $where .= ' AND filename LIKE :search';
    if ($route === 'folder') $where .= ' AND folder_id=:folder';
    if ($route === 'drive') $where .= ' AND folder_id IS NULL';

    $st = $pdo->prepare("SELECT * FROM files WHERE $where ORDER BY created_at DESC");
    $st->bindValue(':uid', $user['id']);
    if ($route === 'search') $st->bindValue(':search', "%$search%");
    if ($route === 'folder') $st->bindValue(':folder', $currentFolderId, PDO::PARAM_INT);
    $st->execute();
    $files = $st->fetchAll();

    $map = ['drive'=>'My Drive','recent'=>'Recent','starred'=>'Starred','trash'=>'Trash','search'=>'Search Results','folder'=>'Folder'];
    $pageTitle = $map[$route] ?? 'My Drive';
}

$usedPercent = min(100, round(($storage / USER_STORAGE_LIMIT) * 100, 2));
?>
<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Safe Drive</title>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" />
  <link rel="stylesheet" href="/public/assets/style.css?v=<?= $cssVersion ?>" />
</head>
<body>
<?php if ($route === 'login'): ?>
<main class="login-wrap">
  <section class="login-card">
    <img src="/public/drive.svg" class="logo" alt="logo" />
    <h1>سيف درايف</h1>
    <p>سجّل دخولك بحساب المنتدى</p>
    <?php if ($dbError): ?><div class="flash error">خطأ قاعدة البيانات: <?= htmlspecialchars($dbError) ?></div><?php endif; ?>
    <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>
    <form method="post" class="login-form">
      <input type="hidden" name="action" value="login" />
      <input name="username" placeholder="اسم المستخدم أو البريد" required />
      <input name="password" type="password" placeholder="كلمة المرور" required />
      <button type="submit">ابدأ الآن</button>
    </form>
  </section>
  <img src="/public/login.gif" class="hero" alt="login" />
</main>
<?php elseif (str_starts_with($route, 'admin')): ?>
<?php
  $countryMap = [];
  foreach ($adminCountryStats as $row) {
    $code = strtoupper((string)($row['country'] ?? 'ZZ'));
    if (!preg_match('/^[A-Z]{2}$/', $code)) $code = 'ZZ';
    $countryMap[$code] = [
      'files' => (int)$row['files_count'],
      'uploaders' => (int)$row['uploaders_count'],
    ];
  }
  $countryChartRows = [];
  foreach ($countryMap as $code => $v) {
    if ($code === 'ZZ') continue;
    $countryChartRows[] = [$code, $v['uploaders'], $v['files']];
  }
  $monthLabels = [];
  $monthCounts = [];
  foreach ($adminUploadsByMonth as $m) {
    $monthLabels[] = (string)$m['month_key'];
    $monthCounts[] = (int)$m['files_count'];
  }
?>
<style>
.admin-shell{display:grid;grid-template-columns:270px 1fr;gap:14px;min-height:calc(100vh - 0px);padding:14px}
.admin-side{background:#1f2933;color:#d5dbe2;padding:18px 14px;border-radius:14px;border:1px solid #2e3743;box-shadow:0 10px 24px #00000022}
.admin-side h2{margin:0 0 16px;font-size:30px;color:#fff}
.admin-side a{display:block;color:#d5dbe2;text-decoration:none;padding:10px 8px;border-radius:8px;margin-bottom:4px}
.admin-side a:hover,.admin-side a.active{background:#323f4b}
.admin-main{padding:18px;background:#eef2f5}
.admin-top{display:flex;justify-content:space-between;align-items:center;background:#fff;border:1px solid #d7dde3;border-radius:10px;padding:12px 16px;margin-bottom:14px}
.admin-top h1{margin:0;font-size:44px}
.stat-grid{display:grid;grid-template-columns:repeat(5,minmax(140px,1fr));gap:10px;margin-bottom:14px}
.stat{padding:14px;border-radius:10px;color:#fff}
.stat b{font-size:28px;display:block}
.stat.blue{background:#1f7aec}.stat.red{background:#dc3545}.stat.orange{background:#f0ad00}.stat.green{background:#28a745}.stat.dark{background:#4b5563}
.panel{background:#fff;border:1px solid #d7dde3;border-radius:10px;padding:12px;margin-bottom:14px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.world-map{height:360px}
.image-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px}
.image-card{background:#fff;border:1px solid #d7dde3;border-radius:10px;overflow:hidden}
.image-card img{width:100%;height:230px;object-fit:cover;background:#111}
.image-meta{padding:8px;font-size:12px;line-height:1.5}
@media(max-width:1300px){.image-grid{grid-template-columns:repeat(3,minmax(0,1fr));}.stat-grid{grid-template-columns:repeat(3,minmax(140px,1fr));}}
@media(max-width:900px){.admin-shell{grid-template-columns:1fr}.two-col{grid-template-columns:1fr}.image-grid{grid-template-columns:repeat(2,minmax(0,1fr));}.stat-grid{grid-template-columns:repeat(2,minmax(140px,1fr));}}
</style>
<div class="admin-shell">
  <aside class="admin-side">
    <h2>Uploady</h2>
    <a class="<?= $route==='admin'?'active':'' ?>" href="/admin">📊 Dashboard</a>
    <a class="<?= $route==='admin_files'?'active':'' ?>" href="/admin/files">📁 Manage Files</a>
    <a class="<?= $route==='admin_images'?'active':'' ?>" href="/admin/images">🖼 Review Images</a>
    <a class="<?= $route==='admin_settings'?'active':'' ?>" href="/admin/settings">⚙ Edit Settings</a>
    <a href="/drive">↩ العودة للدرايف</a>
    <a href="/logout">🚪 خروج</a>
  </aside>
  <main class="admin-main">
    <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>" style="margin-bottom:10px"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>
    <div class="admin-top">
      <h1>Dashboard</h1>
      <div><?= htmlspecialchars($user['name']) ?></div>
    </div>

    <?php if ($route === "admin"): ?>
    <section class="stat-grid">
      <div class="stat blue"><b><?= (int)$adminStats['files'] ?></b> Total Files</div>
      <div class="stat red"><b><?= (int)$adminStats['users'] ?></b> Total Uploaders</div>
      <div class="stat orange"><b><?= (int)$adminStats['shared'] ?></b> Shared Files</div>
      <div class="stat green"><b><?= (int)$adminStats['downloads'] ?></b> Total Downloads</div>
      <div class="stat dark"><b><?= format_bytes((int)$adminStats['size']) ?></b> Total Storage</div>
    </section>

    <section class="two-col">
      <div class="panel">
        <h3>Uploads per Month</h3>
        <canvas id="uploadsByMonthChart" height="170"></canvas>
      </div>
      <div class="panel">
        <h3>Uploads per Country</h3>
        <div id="worldMapChart" class="world-map"></div>
      </div>
    </section>
    <?php endif; ?>

    <?php if ($route === "admin" || $route === "admin_settings"): ?>
    <section class="panel" id="settings">
      <h3>Allowed Upload Extensions</h3>
      <form method="post" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input type="hidden" name="action" value="admin_set_extensions">
        <input type="hidden" name="redirect" value="/admin">
        <input name="extensions" value="<?= htmlspecialchars($allowedExtDisplay) ?>" style="min-width:380px;padding:8px" placeholder="zip,rar,pdf أو *">
        <button type="submit">Save</button>
      </form>
    </section>

    <section class="panel" id="users">
      <h3>Users / Purge User Files</h3>
      <form method="post" onsubmit="return confirm('تأكيد حذف جميع ملفات ومجلدات هذا المستخدم؟');" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input type="hidden" name="action" value="admin_purge_user"><input type="hidden" name="redirect" value="/admin">
        <select name="target_user_id" required>
          <option value="">اختر المستخدم</option>
          <?php foreach($adminUsers as $au): ?>
          <option value="<?= htmlspecialchars($au['user_id']) ?>"><?= htmlspecialchars(($au['user_name'] ?: $au['user_id']) . ' | files: ' . $au['files_count']) ?></option>
          <?php endforeach; ?>
        </select>
        <button type="submit" style="background:#b91c1c;color:#fff">Purge User</button>
      </form>
    </section>
    <?php endif; ?>

    <?php if ($route === "admin_files"): ?>
    <section class="panel" id="files" style="overflow:auto">
      <h3>Latest Files / Bulk Actions</h3>
      <form method="post" id="adminBulkForm">
        <input type="hidden" name="action" value="admin_bulk_files"><input type="hidden" name="redirect" value="/admin">
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
          <select name="bulk_op" id="bulkOp" required>
            <option value="">اختر العملية</option>
            <option value="trash">Move to trash</option>
            <option value="delete">Delete forever</option>
            <option value="move">Move folder</option>
            <option value="unshare">Disable share</option>
          </select>
          <select name="target_folder_id" id="targetFolderSelect">
            <option value="">Root</option>
            <?php foreach($adminFolders as $fd): ?>
            <option value="<?= (int)$fd['id'] ?>">#<?= (int)$fd['id'] ?> - <?= htmlspecialchars($fd['name']) ?> (<?= htmlspecialchars($fd['user_id']) ?>)</option>
            <?php endforeach; ?>
          </select>
          <button type="submit">Apply</button>
          <button type="button" onclick="document.querySelectorAll('.admin-file-check').forEach(c=>c.checked=true)">Select all</button>
          <button type="button" onclick="document.querySelectorAll('.admin-file-check').forEach(c=>c.checked=false)">Clear</button>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead><tr style="background:#f3f4f6"><th></th><th>ID</th><th>Filename</th><th>Uploader</th><th>Country</th><th>Size</th><th>Shared</th><th>Uploaded at</th></tr></thead>
          <tbody>
          <?php foreach($adminFiles as $af): ?>
            <tr>
              <td><input class="admin-file-check" type="checkbox" name="file_ids[]" value="<?= (int)$af['id'] ?>"></td>
              <td><?= (int)$af['id'] ?></td>
              <td><?= htmlspecialchars($af['filename']) ?></td>
              <td><?= htmlspecialchars($af['user_name'] ?: $af['user_id']) ?></td>
              <td><?= htmlspecialchars((string)($af['uploader_country'] ?: 'ZZ')) ?></td>
              <td><?= format_bytes((int)$af['size_bytes']) ?></td>
              <td><?= $af['shared_token'] ? '✅' : '—' ?></td>
              <td><?= htmlspecialchars((string)$af['created_at']) ?></td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </form>
    </section>
    <?php endif; ?>

    <?php if ($route === "admin_images"): ?>
    <section class="panel" id="images">
      <h3>Image Moderation (5 per row)</h3>
      <div class="image-grid">
        <?php foreach($adminImageFiles as $img): ?>
          <div class="image-card">
            <a href="<?= htmlspecialchars(file_url($img)) ?>" target="_blank"><img src="/<?= htmlspecialchars($img['relative_path']) ?>" alt="<?= htmlspecialchars($img['filename']) ?>"></a>
            <div class="image-meta">
              <div><strong><?= htmlspecialchars($img['filename']) ?></strong></div>
              <div><?= htmlspecialchars($img['user_name'] ?: $img['user_id']) ?> · <?= format_bytes((int)$img['size_bytes']) ?></div>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    </section>
    <?php endif; ?>
  </main>
</div>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://www.gstatic.com/charts/loader.js"></script>
<script>
const monthLabels = <?= json_encode($monthLabels, JSON_UNESCAPED_UNICODE) ?>;
const monthCounts = <?= json_encode($monthCounts, JSON_UNESCAPED_UNICODE) ?>;
const countryRows = <?= json_encode($countryChartRows, JSON_UNESCAPED_UNICODE) ?>;
const countryMap = <?= json_encode($countryMap, JSON_UNESCAPED_UNICODE) ?>;

const bulkOp=document.getElementById('bulkOp');
const folderSel=document.getElementById('targetFolderSelect');
if(bulkOp&&folderSel){
  const sync=()=>{folderSel.style.display=(bulkOp.value==='move')?'inline-block':'none';};
  bulkOp.addEventListener('change',sync);sync();
}

if (window.Chart) {
  const ctx = document.getElementById('uploadsByMonthChart');
  if (ctx) new Chart(ctx, {
    type: 'bar',
    data: { labels: monthLabels, datasets: [{ label: 'Uploads', data: monthCounts, backgroundColor: '#1f7aec' }] },
    options: { responsive: true, plugins: { legend: { display: false } } }
  });
}

google.charts.load('current', {'packages':['geochart']});
google.charts.setOnLoadCallback(drawRegionsMap);
function drawRegionsMap() {
  const arr = [['Country', 'Uploaders', 'Files']].concat(countryRows);
  const data = google.visualization.arrayToDataTable(arr.length > 1 ? arr : [['Country','Uploaders','Files'], ['US',0,0]]);
  const options = {
    legend: 'none',
    datalessRegionColor: '#e5e7eb',
    colorAxis: { colors: ['#93c5fd', '#1d4ed8'] },
    tooltip: { textStyle: { fontName: 'Cairo' } }
  };
  const chart = new google.visualization.GeoChart(document.getElementById('worldMapChart'));
  chart.draw(data, options);
  google.visualization.events.addListener(chart, 'select', function() {
    const sel = chart.getSelection();
    if (!sel.length) return;
    const row = sel[0].row;
    if (row == null) return;
    const code = data.getValue(row, 0);
    const info = countryMap[code] || {files:0,uploaders:0};
    alert(`Country ${code}
Total uploaders: ${info.uploaders}
Total files: ${info.files}`);
  });
}
</script>
<?php else: ?>
<header class="topbar">
  <div class="brand"><span class="menu">☰</span><img src="/public/google-logo.png" alt=""/><span>Drive</span></div>
  <form class="search" method="get" action="/search"><input name="q" placeholder="ابحث في درايف" value="<?= htmlspecialchars($search) ?>"/></form>
  <div class="header-icons"><span>?</span><span>⚙</span></div>
  <div class="profile"><img width="38" height="38" src="<?= htmlspecialchars($user['avatar'] ?: '/public/myimg.png') ?>" alt="avatar"/><span><?= htmlspecialchars($user['name']) ?></span><a class="header-logout" href="/logout">خروج</a></div>
</header>

<div class="layout">
  <aside class="sidebar">
    <div class="new-wrap">
      <button id="newBtn" class="new-btn" type="button">＋ جديد</button>
      <div id="newMenu" class="new-menu hidden">
        <button type="button" data-open="uploadModal">📄 تحميل ملف</button>
        <button type="button" data-open="uploadFolderModal">📁 تحميل مجلد</button>
        <button type="button" data-open="folderModal">📁 مجلد جديد</button>
      </div>
    </div>

    <nav>
      <a href="/drive" class="<?= $route==='drive'?'active':'' ?>">📁 ملفاتي</a>
      <a href="/recent" class="<?= $route==='recent'?'active':'' ?>">🕒 الأحدث</a>
      <a href="/starred" class="<?= $route==='starred'?'active':'' ?>">⭐ المميزة</a>
      <a href="/trash" class="<?= $route==='trash'?'active':'' ?>">🗑 سلة المحذوفات</a>
      <hr>
      <a href="#" onclick="alert('الدعم قريباً');return false;">❓ المساعدة</a>
      <a href="#" onclick="return false;">☁️ التخزين</a>
    </nav>

    <div class="storage-card">
      <div class="storage-bar"><span style="width: <?= $usedPercent ?>%"></span></div>
      <p>تم استخدام <?= format_bytes($storage) ?> من إجمالي 1 TB</p>
      <button type="button">الحصول على مساحة تخزين إضافية</button>
    </div>

    <a class="logout" href="/logout">خروج</a>
  </aside>

  <main class="content">
    <?php if ($dbError): ?><div class="flash error">خطأ قاعدة البيانات: <?= htmlspecialchars($dbError) ?></div><?php endif; ?>
    <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>

    <div id="uploadProgress" class="progress hidden"><div id="uploadProgressBar"></div><p id="uploadProgressText">0%</p><p id="uploadSpeedText">0 MB/s</p></div>

    <div class="section-head"><h2><?= htmlspecialchars($pageTitle) ?></h2><div>☰ ⓘ</div></div>
    <div id="selectionBar" class="selection-bar hidden">
      <div class="selection-count"><span id="selectionCount">0</span> تم اختيار ملف</div>
      <div class="selection-actions">
        <button type="button" data-select-cmd="download">⤓ تنزيل</button>
        <button type="button" data-select-cmd="rename">✎ إعادة تسمية</button>
        <button type="button" data-select-cmd="share">👥 مشاركة</button>
        <button type="button" data-select-cmd="copy">🔗 نسخ الرابط</button>
        <button type="button" data-select-cmd="delete">🗑 نقل للمهملات</button>
      </div>
    </div>

    <h4 class="recent-title">Recents</h4>

    <div class="folders-grid">
      <?php foreach ($folders as $fd): ?>
      <a href="/folders/<?= (int)$fd['id'] ?>" class="folder-card" data-type="folder" data-id="<?= (int)$fd['id'] ?>" data-name="<?= htmlspecialchars($fd['name']) ?>">
        <?php if (!empty($fd['preview_image'])): ?><img src="/<?= htmlspecialchars($fd['preview_image']) ?>" alt="preview" />
        <?php else: ?><div class="folder-placeholder">📁</div><?php endif; ?>
        <strong><?= htmlspecialchars($fd['name']) ?></strong>
      </a>
      <?php endforeach; ?>

      <?php foreach (array_slice($files, 0, 4) as $f): ?>
      <a href="<?= htmlspecialchars(file_url($f)) ?>" target="_blank" class="folder-card" data-type="file" data-id="<?= (int)$f['id'] ?>" data-name="<?= htmlspecialchars($f['filename']) ?>" data-shared="<?= $f['shared_token'] ? '1':'0' ?>" data-share-url="<?= $f['shared_token'] ? htmlspecialchars(share_url($f['shared_token'], (string)$f['filename'])) : '' ?>">
        <?php if (str_starts_with((string)$f['mime_type'], 'image/')): ?><img src="<?= htmlspecialchars(file_url($f)) ?>" alt="thumb" />
        <?php else: ?><div class="folder-placeholder">📄</div><?php endif; ?>
        <strong><?= htmlspecialchars($f['filename']) ?></strong>
      </a>
      <?php endforeach; ?>
    </div>

    <div class="table">
      <div class="row head"><div>الاسم</div><div>الحجم</div><div>آخر تعديل</div><div>الخيارات</div></div>
      <?php if (!$files): ?><div class="empty">لا توجد ملفات.</div><?php endif; ?>
      <?php foreach ($files as $f): ?>
      <div class="row" data-type="file" data-id="<?= (int)$f['id'] ?>" data-name="<?= htmlspecialchars($f['filename']) ?>" data-shared="<?= $f['shared_token'] ? '1':'0' ?>" data-share-url="<?= $f['shared_token'] ? htmlspecialchars(share_url($f['shared_token'], (string)$f['filename'])) : '' ?>">
        <div class="name-cell">
          <form method="post" class="inline-form"><input type="hidden" name="action" value="toggle_star"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><button class="star <?= (int)$f['is_starred']?'on':'' ?>">★</button></form>
          <a href="<?= htmlspecialchars(file_url($f)) ?>" target="_blank">
            <?php if (str_starts_with((string)$f['mime_type'], 'image/')): ?><img src="<?= htmlspecialchars(file_url($f)) ?>" class="thumb-mini" alt="thumb"><?php else: ?><span>📄</span><?php endif; ?>
            <span title="<?= htmlspecialchars($f['filename']) ?>"><?= htmlspecialchars($f['filename']) ?></span>
          </a>
        </div>
        <div><?= format_bytes((int)$f['size_bytes']) ?></div>
        <div><?= htmlspecialchars($f['created_at']) ?></div>
        <div class="actions">
          <?php if ($route === 'trash'): ?>
            <form method="post" class="inline-form"><input type="hidden" name="action" value="restore"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><button>استعادة</button></form>
            <form method="post" class="inline-form"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><button>حذف نهائي</button></form>
          <?php else: ?>
            <form method="post" class="inline-form"><input type="hidden" name="action" value="trash"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><button>نقل للسلة</button></form>
            <form method="post" class="inline-form"><input type="hidden" name="action" value="move_file"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><select name="target_folder_id"><option value="">الجذر</option><?php foreach ($allFolders as $op): ?><option value="<?= (int)$op['id'] ?>" <?= ((int)$f['folder_id']===(int)$op['id'])?'selected':'' ?>><?= htmlspecialchars($op['name']) ?></option><?php endforeach; ?></select><button>نقل</button></form>
          <?php endif; ?>
        </div>
      </div>
      <?php endforeach; ?>
    </div>
  </main>
</div>

<div id="uploadModal" class="modal hidden"><div class="modal-box"><button class="close" data-close>×</button><h3>اختر ملفاً لرفعه</h3>
  <form id="uploadForm" method="post" enctype="multipart/form-data">
    <input type="hidden" name="action" value="upload_ajax"/><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"/><input type="hidden" name="folder_id" value="<?= $route==='folder'?(int)$currentFolderId:'' ?>"/>
    <input id="singleFile" type="file" name="file" required>
    <small>الحد الأقصى للملف الواحد: 5 GB</small>
    <button type="submit">رفع الملف</button>
  </form></div></div>

<div id="uploadFolderModal" class="modal hidden"><div class="modal-box"><button class="close" data-close>×</button><h3>اختر مجلداً لرفعه</h3>
  <form method="post" enctype="multipart/form-data">
    <input type="hidden" name="action" value="upload_folder"/><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"/><input type="hidden" name="folder_id" value="<?= $route==='folder'?(int)$currentFolderId:'' ?>"/>
    <input type="file" id="folderInput" name="files[]" webkitdirectory directory multiple required>
    <div id="relativePathsContainer"></div>
    <button type="submit">تحميل المجلد</button>
  </form></div></div>

<div id="folderModal" class="modal hidden"><div class="modal-box"><button class="close" data-close>×</button><h3>إنشاء مجلد جديد</h3>
  <form method="post">
    <input type="hidden" name="action" value="create_folder"/><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"/><input type="hidden" name="folder_id" value="<?= $route==='folder'?(int)$currentFolderId:'' ?>"/>
    <input name="folder_name" placeholder="اسم المجلد" required>
    <button type="submit">إنشاء</button>
  </form></div></div>

<div id="shareModal" class="modal hidden"><div class="modal-box share-modal-box"><button class="close" data-close>×</button>
  <h3 id="shareTitle">مشاركة ملف</h3>
  <input id="sharePeopleInput" placeholder="إضافة مستخدمين ومجموعات ومساحات وأحداث في التقويم" />
  <div class="share-access-row"><span>وصول عام</span><select id="shareAccessSelect"><option value="public">أي شخص لديه الرابط</option><option value="private">حصري</option></select></div>
  <div class="share-note" id="shareNote">يمكن لأي شخص لديه الرابط الوصول في ظل الحصر.</div>
  <div class="share-actions"><button type="button" id="shareDoneBtn">تم</button><button type="button" id="shareCopyBtn">نسخ الرابط</button></div>
</div></div>

<div id="ctxMenu" class="ctx-menu hidden">
  <button data-cmd="open"><span>فتح باستخدام</span><b>✦</b></button>
  <button data-cmd="download"><span>تنزيل</span><b>⤓</b></button>
  <button data-cmd="rename"><span>إعادة تسمية</span><b>✎</b></button>
  <button data-cmd="copy"><span>إنشاء نسخة / نسخ الرابط</span><b>⧉</b></button>
  <hr>
  <button data-cmd="share"><span>مشاركة</span><b>👥</b></button>
  <button data-cmd="move"><span>تنظيم</span><b>🗂</b></button>
  <button data-cmd="info"><span>معلومات الملف</span><b>ⓘ</b></button>
  <hr>
  <button data-cmd="delete"><span>إزالة</span><b>🗑</b></button>
</div>

<form id="cmdForm" method="post" class="hidden">
  <input type="hidden" name="action" id="cmdAction"><input type="hidden" name="id" id="cmdId"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><input type="hidden" name="new_name" id="cmdName">
</form>

<script>
const MAX_FILE = 5 * 1024 * 1024 * 1024;
const newBtn=document.getElementById('newBtn');
const newMenu=document.getElementById('newMenu');
if(newBtn && newMenu){
  newBtn.addEventListener('click',(e)=>{e.stopPropagation();newMenu.classList.toggle('hidden');});
  document.querySelectorAll('[data-open]').forEach(el=>el.addEventListener('click',()=>{
    const target=document.getElementById(el.dataset.open);
    if(target) target.classList.remove('hidden');
    newMenu.classList.add('hidden');
  }));
  document.addEventListener('click',(e)=>{if(!newMenu.contains(e.target) && e.target!==newBtn)newMenu.classList.add('hidden');});
}
document.querySelectorAll('[data-close]').forEach(el=>el.addEventListener('click',()=>el.closest('.modal').classList.add('hidden')));
window.addEventListener('click',(e)=>{if(e.target.classList.contains('modal')) e.target.classList.add('hidden');});
window.addEventListener('keydown',(e)=>{if(e.key==='Escape'){document.querySelectorAll('.modal').forEach(m=>m.classList.add('hidden'));if(newMenu)newMenu.classList.add('hidden');ctxMenu.classList.add('hidden');}});

const folderInput = document.getElementById('folderInput');
const relContainer = document.getElementById('relativePathsContainer');
folderInput?.addEventListener('change', ()=>{
  relContainer.innerHTML='';
  [...folderInput.files].forEach(f=>{
    const i=document.createElement('input');
    i.type='hidden';
    i.name='relative_paths[]';
    i.value=f.webkitRelativePath || f.name;
    relContainer.appendChild(i);
  });
});

const uploadForm = document.getElementById('uploadForm');
const singleFile = document.getElementById('singleFile');
const pWrap = document.getElementById('uploadProgress');
const pBar = document.getElementById('uploadProgressBar');
const pText = document.getElementById('uploadProgressText');
const pSpeed = document.getElementById('uploadSpeedText');
uploadForm?.addEventListener('submit',(e)=>{
  e.preventDefault();
  if(!singleFile.files.length) return;
  const f=singleFile.files[0];
  if(f.size>MAX_FILE){ alert('الملف أكبر من 5 جيجابايت.'); return; }

  document.getElementById('uploadModal')?.classList.add('hidden');
  pWrap.classList.remove('hidden');
  pBar.style.width='0%';
  pText.textContent='0%';
  pSpeed.textContent='0 MB/s';

  const fd=new FormData(uploadForm);
  const xhr=new XMLHttpRequest();
  xhr.open('POST', window.location.pathname, true);

  let lastTime = performance.now();
  let lastLoaded = 0;
  xhr.upload.onprogress=(ev)=>{
    if(ev.lengthComputable){
      const percent=Math.round((ev.loaded/ev.total)*100);
      pBar.style.width=percent+'%';
      pText.textContent=percent+'%';

      const now = performance.now();
      const deltaBytes = ev.loaded - lastLoaded;
      const deltaSec = Math.max((now - lastTime)/1000, 0.001);
      const speedMB = (deltaBytes / deltaSec) / (1024*1024);
      pSpeed.textContent = speedMB.toFixed(2) + ' MB/s';
      lastLoaded = ev.loaded;
      lastTime = now;
    }
  };
  xhr.onload=()=>{
    if(xhr.status>=200 && xhr.status<300){
      pText.textContent='100%';
      pSpeed.textContent='اكتمل الرفع';
      location.reload();
    } else {
      pWrap.classList.add('hidden');
      try{const j=JSON.parse(xhr.responseText); alert(j.message||'فشل الرفع');}catch(_){alert('فشل الرفع');}
    }
  };
  xhr.onerror=()=>{ pWrap.classList.add('hidden'); alert('فشل الاتصال أثناء الرفع.'); };
  xhr.send(fd);
});

const ctxMenu=document.getElementById('ctxMenu');
const selectionBar=document.getElementById('selectionBar');
const selectionCount=document.getElementById('selectionCount');
const shareModal=document.getElementById('shareModal');
const shareTitle=document.getElementById('shareTitle');
const shareAccessSelect=document.getElementById('shareAccessSelect');
const shareNote=document.getElementById('shareNote');
const shareCopyBtn=document.getElementById('shareCopyBtn');
const shareDoneBtn=document.getElementById('shareDoneBtn');
let currentTarget=null;
let selectedItems=[];

function setSelected(items){
  document.querySelectorAll('.is-selected').forEach(el=>el.classList.remove('is-selected'));
  selectedItems=[...new Set(items)].filter(Boolean);
  selectedItems.forEach(el=>el.classList.add('is-selected'));
  selectionCount.textContent=String(selectedItems.length);
  if(selectionBar) selectionBar.classList.toggle('hidden', selectedItems.length===0);
}
function pickOne(el){ setSelected([el]); currentTarget=el; }
function getPrimary(){ return currentTarget || selectedItems[0] || null; }

function openMenu(ev, el){
  ev.preventDefault();
  if(!selectedItems.includes(el)) pickOne(el);
  currentTarget=el;
  const pad=10;
  const menuW=260, menuH=330;
  const left=Math.min(ev.clientX, window.innerWidth-menuW-pad);
  const top=Math.min(ev.clientY, window.innerHeight-menuH-pad);
  ctxMenu.style.left=left+'px';
  ctxMenu.style.top=top+'px';
  ctxMenu.classList.remove('hidden');
}

function openShareDialog(el){
  if(!el || el.dataset.type!=='file'){ alert('المشاركة متاحة للملفات فقط.'); return; }
  shareTitle.textContent='مشاركة "'+(el.dataset.name||'ملف')+'"';
  const isShared=!!el.dataset.shareUrl;
  shareAccessSelect.value=isShared?'public':'private';
  shareNote.textContent=isShared?'أي شخص لديه الرابط يمكنه الوصول.':'لا يمكن إلا للأشخاص الذين لديهم إذن الوصول.';
  shareModal.classList.remove('hidden');
}

function submitCmd(cmd, el){
  if(!el) return;
  const type=el.dataset.type;
  const id=el.dataset.id;
  if(cmd==='open'){
    const a=(el.tagName==='A')?el:el.querySelector('a[href]');
    if(a){ window.open(a.href, '_blank'); return; }
  }
  if(cmd==='download'){
    if(type!=='file') return;
    const a=(el.tagName==='A')?el:el.querySelector('a[href]');
    if(a) window.open(a.href + (a.href.includes('?')?'&':'?')+'download=1','_blank');
    return;
  }
  if(cmd==='info'){
    alert(`الاسم: ${el.dataset.name||'-'}\nالمعرف: ${id||'-'}\nالنوع: ${type}`);
    return;
  }
  if(cmd==='rename'){
    const n=prompt('الاسم الجديد:', el.dataset.name||'');
    if(!n) return;
    cmdAction.value=(type==='file'?'rename_file':'rename_folder'); cmdId.value=id; cmdName.value=n; cmdForm.submit();
  }
  if(cmd==='move' && type==='file'){
    const to=prompt('أدخل رقم المجلد الهدف (فارغ = الجذر):','');
    const form=document.createElement('form'); form.method='post'; form.className='hidden';
    form.innerHTML=`<input name="action" value="move_file"><input name="id" value="${id}"><input name="target_folder_id" value="${to}"><input name="redirect" value="${window.location.pathname}">`;
    document.body.appendChild(form); form.submit();
  }
  if(cmd==='share' && type==='file'){ openShareDialog(el); return; }
  if(cmd==='copy' && type==='file'){
    const url=el.dataset.shareUrl;
    if(!url){ alert('الملف غير مشارك. استخدم نافذة المشاركة أولاً.'); return; }
    navigator.clipboard.writeText(window.location.origin+url); alert('تم نسخ رابط المشاركة');
  }
  if(cmd==='delete'){
    cmdAction.value=(type==='file'?'trash':'delete_folder'); cmdId.value=id; cmdName.value=''; cmdForm.submit();
  }
}

document.querySelectorAll('[data-type]').forEach(el=>{
  el.classList.add('selectable-item');
  el.addEventListener('click',(e)=>{
    if(e.target.closest('button,form,.star')) return;
    if(e.metaKey || e.ctrlKey){
      const next=selectedItems.includes(el)?selectedItems.filter(x=>x!==el):[...selectedItems, el];
      setSelected(next);
    } else {
      pickOne(el);
    }
    if(el.tagName==='A') e.preventDefault();
  });
  el.addEventListener('dblclick',(e)=>{
    const a=(el.tagName==='A')?el:el.querySelector('a[href]');
    if(a){ window.open(a.href,'_blank'); }
  });
  el.addEventListener('contextmenu',(e)=>openMenu(e, el));
});

document.addEventListener('click',(e)=>{
  if(!e.target.closest('[data-type], #ctxMenu, #selectionBar, #shareModal .modal-box')){
    setSelected([]);
  }
  if(!e.target.closest('#ctxMenu')) ctxMenu.classList.add('hidden');
});

document.querySelectorAll('[data-select-cmd]').forEach(btn=>btn.addEventListener('click',()=>{
  const primary=getPrimary();
  if(!primary) return;
  if(selectedItems.length>1 && ['rename','move','share'].includes(btn.dataset.selectCmd)){
    alert('هذه العملية متاحة لعنصر واحد فقط حالياً.');
    return;
  }
  submitCmd(btn.dataset.selectCmd, primary);
}));

shareAccessSelect?.addEventListener('change',()=>{
  const isPrivate=shareAccessSelect.value==='private';
  shareNote.textContent=isPrivate?'لن يتمكن غير الأشخاص الذين لديهم إذن الوصول إلى الرابط':'أي شخص لديه الرابط سيتمكن من الوصول.';
});
shareCopyBtn?.addEventListener('click',()=>{
  const primary=getPrimary();
  if(!primary || primary.dataset.type!=='file'){ alert('اختر ملفاً أولاً.'); return; }
  if(!primary.dataset.shareUrl){
    if(confirm('الملف غير مشارك. تفعيل المشاركة الآن؟')){ cmdAction.value='toggle_share_file'; cmdId.value=primary.dataset.id; cmdName.value=''; cmdForm.submit(); }
    return;
  }
  navigator.clipboard.writeText(window.location.origin + primary.dataset.shareUrl);
  alert('تم نسخ الرابط');
});
shareDoneBtn?.addEventListener('click',()=>shareModal.classList.add('hidden'));

const cmdForm=document.getElementById('cmdForm');
const cmdAction=document.getElementById('cmdAction');
const cmdId=document.getElementById('cmdId');
const cmdName=document.getElementById('cmdName');
ctxMenu?.querySelectorAll('button').forEach(btn=>btn.addEventListener('click',(e)=>{
  e.stopPropagation();
  const primary=getPrimary();
  if(!primary) return;
  submitCmd(btn.dataset.cmd, primary);
}));
</script>
<?php endif; ?>
</body>
</html>
