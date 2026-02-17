<?php
// نتحكم بهيدرات الكاش يدويًا لكل مسار؛ نوقف cache limiter الافتراضي للجلسات لتجنب Expires=1981
session_cache_limiter('');
session_start();
$config = require __DIR__ . '/config.php';

const USER_STORAGE_LIMIT = 1099511627776; // 1 تيرابايت

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
    <header class='topbar'><div class='brand'><i class='fa-solid fa-cloud-arrow-down'></i> تنزيل سيف درايف</div></header>
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
    <footer class='footer'>جميع الحقوق محفوظة - سيف درايف</footer>
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
    $mimeOut = $file['mime_type'] ?: 'application/octet-stream';
    $fsize = filesize($abs);
    $mtime = filemtime($abs) ?: time();
    $etag = 'W/"' . md5($file['id'] . '|' . $fsize . '|' . $mtime) . '"';
    header('Content-Type: ' . $mimeOut);
    header('Content-Length: ' . $fsize);
    header('ETag: ' . $etag);
    header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $mtime) . ' GMT');
    if (str_starts_with((string)$mimeOut, 'image/')) header('Cache-Control: private, max-age=604800, immutable');
    else header('Cache-Control: private, max-age=3600');
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
    $mimeOut = $file['mime_type'] ?: 'application/octet-stream';
    $fsize = filesize($abs);
    $mtime = filemtime($abs) ?: time();
    $etag = 'W/"' . md5($file['id'] . '|' . $fsize . '|' . $mtime) . '"';
    header('Content-Type: ' . $mimeOut);
    header('Content-Length: ' . $fsize);
    header('ETag: ' . $etag);
    header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $mtime) . ' GMT');
    if (str_starts_with((string)$mimeOut, 'image/')) header('Cache-Control: private, max-age=604800, immutable');
    else header('Cache-Control: private, max-age=3600');
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
    $isAjax = strtolower((string)($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '')) === 'xmlhttprequest';
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
            $st = $pdo->prepare('UPDATE files SET folder_id=?, is_trashed=0 WHERE id=? AND user_id=?');
            $st->execute([$to, $id, $user['id']]);
        }

        if ($action === 'move_items') {
            $toRaw = $_POST['target_folder_id'] ?? '';
            $to = ($toRaw === '') ? null : (int)$toRaw;
            $fileIds = $_POST['file_ids'] ?? [];
            $folderIds = $_POST['folder_ids'] ?? [];
            if (!is_array($fileIds)) $fileIds = [];
            if (!is_array($folderIds)) $folderIds = [];

            $fileIds = array_values(array_filter(array_map('intval', $fileIds), fn($v) => $v > 0));
            $folderIds = array_values(array_filter(array_map('intval', $folderIds), fn($v) => $v > 0));

            if ($fileIds) {
                $stFile = $pdo->prepare('UPDATE files SET folder_id=?, is_trashed=0 WHERE id=? AND user_id=?');
                foreach ($fileIds as $fid) {
                    $stFile->execute([$to, $fid, $user['id']]);
                }
            }

            if ($folderIds) {
                $stFolder = $pdo->prepare('UPDATE folders SET parent_id=? WHERE id=? AND user_id=?');
                foreach ($folderIds as $folderId) {
                    if ($to !== null && $to === $folderId) {
                        throw new RuntimeException('لا يمكن نقل المجلد إلى نفسه.');
                    }
                    $stFolder->execute([$to, $folderId, $user['id']]);
                }
            }
        }

        if ($action === 'move_folder') {
            $id = (int)($_POST['id'] ?? 0);
            $toRaw = $_POST['target_folder_id'] ?? '';
            $to = ($toRaw === '') ? null : (int)$toRaw;
            if ($to === $id) throw new RuntimeException('لا يمكن نقل المجلد إلى نفسه.');
            $st = $pdo->prepare('UPDATE folders SET parent_id=? WHERE id=? AND user_id=?');
            $st->execute([$to, $id, $user['id']]);
        }

        if ($action === 'empty_trash') {
            $q = $pdo->prepare('SELECT relative_path FROM files WHERE user_id=? AND is_trashed=1');
            $q->execute([$user['id']]);
            foreach ($q->fetchAll() as $row) {
                $path = __DIR__ . '/' . $row['relative_path'];
                if (is_file($path)) @unlink($path);
            }
            $del = $pdo->prepare('DELETE FROM files WHERE user_id=? AND is_trashed=1');
            $del->execute([$user['id']]);
        }

        if (in_array($action, ['trash','restore','delete'], true)) {
            $id = (int)($_POST['id'] ?? 0);
            if ($action === 'trash') {
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

        if ($isAjax || $action === 'upload_ajax') {
            $payload = ['ok' => true, 'message' => 'تم التنفيذ بنجاح'];
            if ($action === 'toggle_share_file') {
                $fid = (int)($_POST['id'] ?? 0);
                $qf = $pdo->prepare('SELECT filename,shared_token FROM files WHERE id=? AND user_id=? LIMIT 1');
                $qf->execute([$fid, $user['id']]);
                $rf = $qf->fetch();
                $payload['share_url'] = (!empty($rf['shared_token']) && !empty($rf['filename'])) ? share_url((string)$rf['shared_token'], (string)$rf['filename']) : null;
            }
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($payload);
            exit;
        }

        header('Location: ' . $redirect);
        exit;
    } catch (Throwable $e) {
        if ($action === 'upload_ajax' || $isAjax) {
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
$pageTitle = 'ملفاتي';
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
    $adminFiles = $pdo->query("SELECT id,user_id,user_name,filename,mime_type,size_bytes,folder_id,shared_token,is_trashed,created_at,uploader_country,relative_path FROM files WHERE (mime_type NOT LIKE 'image/%' OR mime_type IS NULL OR mime_type='') ORDER BY created_at DESC LIMIT 800")->fetchAll();
    $adminUsers = $pdo->query('SELECT user_id, MIN(user_name) user_name, COUNT(*) files_count, COALESCE(SUM(size_bytes),0) total_size FROM files GROUP BY user_id ORDER BY files_count DESC LIMIT 500')->fetchAll();
    $adminFolders = $pdo->query('SELECT id,name,user_id FROM folders ORDER BY id DESC LIMIT 1000')->fetchAll();

    $stCountry = $pdo->query("SELECT COALESCE(NULLIF(uploader_country,''),'ZZ') country, COUNT(*) files_count, COUNT(DISTINCT user_id) uploaders_count FROM files GROUP BY COALESCE(NULLIF(uploader_country,''),'ZZ') ORDER BY files_count DESC");
    $adminCountryStats = $stCountry->fetchAll();

    $stMonth = $pdo->query("SELECT DATE_FORMAT(created_at, '%Y-%m') month_key, COUNT(*) files_count FROM files GROUP BY DATE_FORMAT(created_at, '%Y-%m') ORDER BY month_key ASC LIMIT 12");
    $adminUploadsByMonth = $stMonth->fetchAll();

    $stImages = $pdo->query("SELECT id,filename,relative_path,size_bytes,user_name,user_id,created_at,shared_token FROM files WHERE mime_type LIKE 'image/%' AND is_trashed=0 ORDER BY created_at DESC LIMIT 120");
    $adminImageFiles = $stImages->fetchAll();

    $allowedExtDisplay = get_setting($pdo, 'allowed_extensions', '*') ?: '*';
    $pageTitle = 'لوحة تحكم الإدارة';
}

if ($user && $route !== 'login' && !str_starts_with($route, 'admin') && $pdo) {
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
    if ($route === 'search') $where .= ' AND filename LIKE :search';
    if ($route === 'folder') $where .= ' AND folder_id=:folder';
    if ($route === 'drive') $where .= ' AND folder_id IS NULL';

    $st = $pdo->prepare("SELECT * FROM files WHERE $where ORDER BY created_at DESC");
    $st->bindValue(':uid', $user['id']);
    if ($route === 'search') $st->bindValue(':search', "%$search%");
    if ($route === 'folder') $st->bindValue(':folder', $currentFolderId, PDO::PARAM_INT);
    $st->execute();
    $files = $st->fetchAll();

    $map = ['drive'=>'ملفاتي','trash'=>'سلة المحذوفات','search'=>'نتائج البحث','folder'=>'مجلد'];
    $pageTitle = $map[$route] ?? 'ملفاتي';
}

$usedPercent = min(100, round(($storage / USER_STORAGE_LIMIT) * 100, 2));
?>
<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>سيف درايف</title>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap" />
  <script src="https://kit.fontawesome.com/ff30351e57.js" crossorigin="anonymous"></script>
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
.admin-side a{display:flex;align-items:center;gap:8px;color:#d5dbe2;text-decoration:none;padding:10px 8px;border-radius:8px;margin-bottom:4px}
.admin-side a i{width:18px;text-align:center}
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

.admin-hint{color:#64748b;margin:8px 0 14px}
.admin-files-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px}
.admin-file-card{background:linear-gradient(180deg,#fff,#f8fafc);border:1px solid #d8e2ee;border-radius:14px;padding:12px;display:flex;flex-direction:column;gap:8px;cursor:default;transition:.18s}
.admin-file-card:hover{transform:translateY(-2px);box-shadow:0 10px 20px #0b57d01a}
.admin-file-card strong{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:15px}
.admin-file-card small{color:#64748b;font-size:12px}
.admin-card-icon{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;background:#e8f0fe;color:#0b57d0;font-size:20px}
.admin-file-card.is-selected{outline:2px solid #0b57d0;background:#eaf1ff}
.admin-selection-surface{position:relative}
.admin-drag-selection-box{position:absolute;border:2px solid #7aa2ff;background:#7aa2ff44;border-radius:6px;pointer-events:none;z-index:6}
.admin-selection-meta{background:#1f2937;color:#f8fafc;border-radius:10px;padding:8px 10px;margin-bottom:10px;font-size:13px}
.admin-ctx-menu{position:fixed;z-index:1200;min-width:220px;background:#243248;color:#e5edf7;border:1px solid #3f536f;border-radius:12px;padding:6px;box-shadow:0 20px 40px #0006}
.admin-ctx-menu button{width:100%;height:40px;border:0;background:transparent;color:inherit;border-radius:8px;display:flex;align-items:center;gap:10px;padding:0 10px;text-align:right}
.admin-ctx-menu button:hover{background:#334760}
.admin-ctx-menu i{width:18px;text-align:center}
.admin-image-grid{grid-template-columns:repeat(auto-fill,minmax(220px,1fr))}
.admin-image-grid .image-card img{height:170px}
@media(max-width:1300px){.image-grid{grid-template-columns:repeat(3,minmax(0,1fr));}.stat-grid{grid-template-columns:repeat(3,minmax(140px,1fr));}}
@media(max-width:900px){.admin-shell{grid-template-columns:1fr}.two-col{grid-template-columns:1fr}.image-grid{grid-template-columns:repeat(2,minmax(0,1fr));}.stat-grid{grid-template-columns:repeat(2,minmax(140px,1fr));}}
</style>
<div class="admin-shell">
  <aside class="admin-side">
    <h2>لوحة الإدارة</h2>
    <a class="<?= $route==='admin'?'active':'' ?>" href="/admin"><i class="fas fa-chart-line"></i> الإحصائيات</a>
    <a class="<?= $route==='admin_files'?'active':'' ?>" href="/admin/files"><i class="fas fa-file-archive"></i> إدارة الملفات</a>
    <a class="<?= $route==='admin_images'?'active':'' ?>" href="/admin/images"><i class="fas fa-images"></i> إدارة الصور</a>
    <a class="<?= $route==='admin_settings'?'active':'' ?>" href="/admin/settings"><i class="fas fa-cog"></i> الإعدادات</a>
    <a href="/drive"><i class="fas fa-arrow-right"></i> العودة للدرايف</a>
    <a href="/logout"><i class="fas fa-sign-out-alt"></i> خروج</a>
  </aside>
  <main class="admin-main">
    <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>" style="margin-bottom:10px"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>
    <div class="admin-top">
      <h1>لوحة الإحصائيات</h1>
      <div><?= htmlspecialchars($user['name']) ?></div>
    </div>

    <?php if ($route === "admin"): ?>
    <section class="stat-grid">
      <div class="stat blue"><b><?= (int)$adminStats['files'] ?></b> إجمالي الملفات</div>
      <div class="stat red"><b><?= (int)$adminStats['users'] ?></b> إجمالي الرافعين</div>
      <div class="stat orange"><b><?= (int)$adminStats['shared'] ?></b> الملفات المشاركة</div>
      <div class="stat green"><b><?= (int)$adminStats['downloads'] ?></b> إجمالي التنزيلات</div>
      <div class="stat dark"><b><?= format_bytes((int)$adminStats['size']) ?></b> إجمالي المساحة</div>
    </section>

    <section class="two-col">
      <div class="panel">
        <h3>الرفع حسب الأشهر</h3>
        <canvas id="uploadsByMonthChart" height="170"></canvas>
      </div>
      <div class="panel">
        <h3>الرفع حسب الدولة</h3>
        <div id="worldMapChart" class="world-map"></div>
      </div>
    </section>
    <?php endif; ?>

    <?php if ($route === "admin" || $route === "admin_settings"): ?>
    <section class="panel" id="settings">
      <h3>امتدادات الرفع المسموحة</h3>
      <form method="post" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input type="hidden" name="action" value="admin_set_extensions">
        <input type="hidden" name="redirect" value="/admin">
        <input name="extensions" value="<?= htmlspecialchars($allowedExtDisplay) ?>" style="min-width:380px;padding:8px" placeholder="zip,rar,pdf أو *">
        <button type="submit">حفظ</button>
      </form>
    </section>

    <section class="panel" id="users">
      <h3>المستخدمون / مسح ملفات مستخدم</h3>
      <form method="post" onsubmit="return confirm('تأكيد حذف جميع ملفات ومجلدات هذا المستخدم؟');" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input type="hidden" name="action" value="admin_purge_user"><input type="hidden" name="redirect" value="/admin">
        <select name="target_user_id" required>
          <option value="">اختر المستخدم</option>
          <?php foreach($adminUsers as $au): ?>
          <option value="<?= htmlspecialchars($au['user_id']) ?>"><?= htmlspecialchars(($au['user_name'] ?: $au['user_id']) . ' | ملفات: ' . $au['files_count']) ?></option>
          <?php endforeach; ?>
        </select>
        <button type="submit" style="background:#b91c1c;color:#fff">مسح ملفات المستخدم</button>
      </form>
    </section>
    <?php endif; ?>

    <?php if ($route === "admin_files"): ?>
    <section class="panel" id="files">
      <h3><i class="fas fa-file-archive"></i> إدارة الملفات (غير الصور)</h3>
      <div class="admin-hint">يمكنك التحديد بالمؤشر، أو Ctrl/Cmd + نقرة، أو النقر بالزر الأيمن لإظهار الخيارات.</div>
      <div id="adminSelectionMeta" class="admin-selection-meta hidden"></div>
      <div id="adminSelectionSurface" class="admin-selection-surface">
        <div id="adminDragSelectionBox" class="admin-drag-selection-box hidden" aria-hidden="true"></div>
        <div id="adminFilesGrid" class="admin-files-grid">
          <?php foreach($adminFiles as $af): ?>
          <article class="admin-file-card" data-type="file" data-id="<?= (int)$af['id'] ?>" data-name="<?= htmlspecialchars($af['filename']) ?>" data-shared="<?= $af['shared_token'] ? '1':'0' ?>">
            <div class="admin-card-icon"><i class="fas fa-file-archive"></i></div>
            <strong title="<?= htmlspecialchars($af['filename']) ?>"><?= htmlspecialchars($af['filename']) ?></strong>
            <small><i class="fas fa-hdd"></i> <?= format_bytes((int)$af['size_bytes']) ?> • #<?= (int)$af['id'] ?></small>
            <small><i class="fas fa-user"></i> <?= htmlspecialchars($af['user_name'] ?: $af['user_id']) ?></small>
          </article>
          <?php endforeach; ?>
        </div>
      </div>
    </section>
    <?php endif; ?>

    <?php if ($route === "admin_images"): ?>
    <section class="panel" id="images">
      <h3><i class="fas fa-image"></i> إدارة الصور</h3>
      <div class="admin-hint">عرض شبكي كامل مع تحديد سريع ونقر أيمن لخيارات الإدارة.</div>
      <div id="adminSelectionMeta" class="admin-selection-meta hidden"></div>
      <div id="adminSelectionSurface" class="admin-selection-surface">
        <div id="adminDragSelectionBox" class="admin-drag-selection-box hidden" aria-hidden="true"></div>
        <div class="image-grid admin-image-grid">
          <?php foreach($adminImageFiles as $img): ?>
            <article class="image-card admin-file-card" data-type="file" data-id="<?= (int)$img['id'] ?>" data-name="<?= htmlspecialchars($img['filename']) ?>" data-shared="<?= $img['shared_token'] ? '1':'0' ?>">
              <img src="/<?= htmlspecialchars($img['relative_path']) ?>" alt="<?= htmlspecialchars($img['filename']) ?>">
              <div class="image-meta">
                <div><strong><?= htmlspecialchars($img['filename']) ?></strong></div>
                <div><?= htmlspecialchars($img['user_name'] ?: $img['user_id']) ?> · <?= format_bytes((int)$img['size_bytes']) ?></div>
              </div>
            </article>
          <?php endforeach; ?>
        </div>
      </div>
    </section>
    <?php endif; ?>
  <div id="adminCtxMenu" class="admin-ctx-menu hidden">
    <button type="button" data-admin-cmd="trash"><i class="fas fa-trash"></i><span>نقل إلى المهملات</span></button>
    <button type="button" data-admin-cmd="delete"><i class="fas fa-trash-alt"></i><span>حذف نهائي</span></button>
    <button type="button" data-admin-cmd="move"><i class="fas fa-folder-open"></i><span>نقل إلى مجلد...</span></button>
    <button type="button" data-admin-cmd="unshare"><i class="fas fa-link-slash"></i><span>إلغاء المشاركة</span></button>
  </div>
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

const adminCtxMenu=document.getElementById('adminCtxMenu');
if(adminCtxMenu){ document.addEventListener('contextmenu',(e)=>e.preventDefault()); }
const adminSelectionSurface=document.getElementById('adminSelectionSurface');
const adminDragSelectionBox=document.getElementById('adminDragSelectionBox');
const adminSelectionMeta=document.getElementById('adminSelectionMeta');
const adminCards=[...document.querySelectorAll('#adminSelectionSurface .admin-file-card[data-id]')];
let adminSelected=[];
let adminDragState=null;
let adminSuppressClear=false;

function setAdminSelected(items){
  adminCards.forEach(c=>c.classList.remove('is-selected'));
  adminSelected=[...new Set(items)].filter(Boolean);
  adminSelected.forEach(c=>c.classList.add('is-selected'));
  if(!adminSelectionMeta) return;
  if(!adminSelected.length){ adminSelectionMeta.classList.add('hidden'); adminSelectionMeta.textContent=''; return; }
  adminSelectionMeta.classList.remove('hidden');
  adminSelectionMeta.textContent=`تم تحديد ${adminSelected.length} عنصر`;
}

function openAdminMenu(e, card){
  e.preventDefault();
  if(!adminSelected.includes(card)) setAdminSelected([card]);
  if(!adminCtxMenu) return;
  const w=240,h=210,p=8;
  adminCtxMenu.style.left=Math.min(e.clientX, window.innerWidth-w-p)+'px';
  adminCtxMenu.style.top=Math.min(e.clientY, window.innerHeight-h-p)+'px';
  adminCtxMenu.classList.remove('hidden');
}

async function adminBulkAction(op, ids, targetFolder=''){
  const fd=new FormData();
  fd.append('action','admin_bulk_files');
  fd.append('bulk_op', op);
  fd.append('target_folder_id', targetFolder);
  fd.append('redirect', window.location.pathname);
  ids.forEach(id=>fd.append('file_ids[]', String(id)));
  const r=await fetch(window.location.pathname,{method:'POST',headers:{'X-Requested-With':'XMLHttpRequest'},body:fd});
  const j=await r.json();
  if(!r.ok || !j.ok) throw new Error(j.message||'فشلت العملية');
  return j;
}

adminCards.forEach(card=>{
  card.addEventListener('click',(e)=>{
    if(e.metaKey||e.ctrlKey){
      const next=adminSelected.includes(card)?adminSelected.filter(x=>x!==card):[...adminSelected, card];
      setAdminSelected(next);
    }else{
      setAdminSelected([card]);
    }
  });
  card.addEventListener('contextmenu',(e)=>openAdminMenu(e,card));
});

function rectFrom(a,b){return {left:Math.min(a.x,b.x),top:Math.min(a.y,b.y),width:Math.abs(a.x-b.x),height:Math.abs(a.y-b.y)}}
function hit(r1,r2){return !(r2.left>r1.left+r1.width || r2.left+r2.width<r1.left || r2.top>r1.top+r1.height || r2.top+r2.height<r1.top)}
adminSelectionSurface?.addEventListener('mousedown',(e)=>{
  if(e.button!==0) return;
  if(e.target.closest('.admin-file-card,.admin-ctx-menu,button,input,select,textarea,a,form')) return;
  const sr=adminSelectionSurface.getBoundingClientRect();
  adminDragState={start:{x:e.clientX,y:e.clientY},sr,dragged:false};
  adminDragSelectionBox?.classList.remove('hidden');
  if(adminDragSelectionBox){
    adminDragSelectionBox.style.left=(e.clientX-sr.left+adminSelectionSurface.scrollLeft)+'px';
    adminDragSelectionBox.style.top=(e.clientY-sr.top+adminSelectionSurface.scrollTop)+'px';
    adminDragSelectionBox.style.width='0px';
    adminDragSelectionBox.style.height='0px';
  }
  setAdminSelected([]);
  e.preventDefault();
});

document.addEventListener('mousemove',(e)=>{
  if(!adminDragState || !adminSelectionSurface || !adminDragSelectionBox) return;
  const r=rectFrom(adminDragState.start,{x:e.clientX,y:e.clientY});
  if(r.width>3||r.height>3) adminDragState.dragged=true;
  adminDragSelectionBox.style.left=(r.left-adminDragState.sr.left+adminSelectionSurface.scrollLeft)+'px';
  adminDragSelectionBox.style.top=(r.top-adminDragState.sr.top+adminSelectionSurface.scrollTop)+'px';
  adminDragSelectionBox.style.width=r.width+'px';
  adminDragSelectionBox.style.height=r.height+'px';
  const touched=[];
  adminCards.forEach(c=>{const rc=c.getBoundingClientRect(); if(hit(r,{left:rc.left,top:rc.top,width:rc.width,height:rc.height})) touched.push(c);});
  setAdminSelected(touched);
});

document.addEventListener('mouseup',()=>{
  if(!adminDragState || !adminDragSelectionBox) return;
  adminDragSelectionBox.classList.add('hidden');
  adminSuppressClear=!!adminDragState.dragged;
  adminDragState=null;
});

adminCtxMenu?.querySelectorAll('button').forEach(btn=>btn.addEventListener('click',async()=>{
  const cmd=btn.dataset.adminCmd;
  if(!adminSelected.length) return;
  const ids=adminSelected.map(c=>Number(c.dataset.id)).filter(Boolean);
  let target='';
  if(cmd==='move'){
    const answer=prompt('أدخل رقم المجلد الهدف (اتركه فارغاً للنقل إلى الجذر):','');
    if(answer===null) return;
    target=answer;
  }
  try{
    await adminBulkAction(cmd, ids, target.trim());
    if(cmd==='trash' || cmd==='delete' || cmd==='move') adminSelected.forEach(c=>c.remove());
    if(cmd==='unshare') adminSelected.forEach(c=>c.dataset.shared='0');
    setAdminSelected(adminSelected.filter(c=>document.body.contains(c)));
  }catch(err){
    alert(err.message||'فشلت العملية');
  }finally{
    adminCtxMenu.classList.add('hidden');
  }
}));

document.addEventListener('click',(e)=>{
  if(adminSuppressClear){adminSuppressClear=false;return;}
  if(!e.target.closest('.admin-file-card,.admin-ctx-menu')) setAdminSelected([]);
  if(!e.target.closest('.admin-ctx-menu')) adminCtxMenu?.classList.add('hidden');
});

if (window.Chart) {
  const ctx = document.getElementById('uploadsByMonthChart');
  if (ctx) new Chart(ctx, {
    type: 'bar',
    data: { labels: monthLabels, datasets: [{ label: 'عمليات الرفع', data: monthCounts, backgroundColor: '#1f7aec' }] },
    options: { responsive: true, plugins: { legend: { display: false } } }
  });
}

google.charts.load('current', {'packages':['geochart']});
google.charts.setOnLoadCallback(drawRegionsMap);
function drawRegionsMap() {
  const arr = [['الدولة', 'عدد الرافعين', 'عدد الملفات']].concat(countryRows);
  const data = google.visualization.arrayToDataTable(arr.length > 1 ? arr : [['الدولة','عدد الرافعين','عدد الملفات'], ['US',0,0]]);
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
    alert(`الدولة: ${code}\nإجمالي الرافعين: ${info.uploaders}\nإجمالي الملفات: ${info.files}`);
  });
}
</script>
<?php else: ?>
<header class="topbar">
  <div class="brand"><img src="/public/game-zone-logo.svg" alt="GAME ZONE"/><span>درايف</span></div>
  <form class="search" method="get" action="/search"><input name="q" placeholder="ابحث في درايف" value="<?= htmlspecialchars($search) ?>"/></form>
  <div class="profile"><img width="38" height="38" src="<?= htmlspecialchars($user['avatar'] ?: '/public/myimg.png') ?>" alt="avatar"/><span><?= htmlspecialchars($user['name']) ?></span><a class="header-logout" href="/logout">خروج</a></div>
</header>

<div class="layout">
  <aside class="sidebar modern-sidebar">
    <div class="new-wrap">
      <button id="newBtn" class="new-btn" type="button"><i class="fas fa-plus"></i> جديد</button>
      <div id="newMenu" class="new-menu hidden">
        <button type="button" data-open="uploadFiles"><i class="far fa-file"></i> تحميل ملف</button>
        <button type="button" data-open="uploadFolderModal"><i class="far fa-folder"></i> تحميل مجلد</button>
        <button type="button" data-open="folderModal"><i class="fas fa-folder-plus"></i> مجلد جديد</button>
      </div>
    </div>

    <nav class="sidebar-nav">
      <a href="/drive" class="<?= $route==='drive'?'active':'' ?>"><i class="far fa-folder-open"></i><span>ملفاتي</span></a>
      <a href="/trash" class="<?= $route==='trash'?'active':'' ?>"><i class="far fa-trash-alt"></i><span>سلة المحذوفات</span></a>
      <a href="#" onclick="return false;"><i class="fas fa-hdd"></i><span>التخزين</span></a>
    </nav>

    <div class="storage-card">
      <div class="storage-bar"><span style="width: <?= $usedPercent ?>%"></span></div>
      <p>تم استخدام <?= format_bytes($storage) ?> من إجمالي 1 تيرابايت</p>
    </div>

    <div id="uploadProgress" class="progress hidden"><div id="uploadProgressBar"></div><p id="uploadProgressText">0%</p><p id="uploadSpeedText">0 م.ب/ث</p></div>

    <div id="selectionBar" class="selection-bar hidden sidebar-selection-bar">
      <div class="selection-count"><span id="selectionCount">0</span> عنصر محدد</div>
      <div class="selection-actions">
        <button type="button" data-select-cmd="download"><i class="fas fa-download"></i><span>تنزيل</span></button>
        <button type="button" data-select-cmd="rename"><i class="fas fa-pen"></i><span>إعادة تسمية</span></button>
        <button type="button" data-select-cmd="share"><i class="fas fa-share-alt"></i><span>مشاركة</span></button>
        <button type="button" data-select-cmd="move"><i class="fas fa-folder-open"></i><span>نقل</span></button>
        <button type="button" data-select-cmd="copy"><i class="fas fa-link"></i><span>نسخ الرابط</span></button>
        <button type="button" data-select-cmd="delete"><i class="fas fa-trash-alt"></i><span>نقل للمهملات</span></button>
      </div>
      <div id="selectionMeta" class="selection-meta"></div>
    </div>


    <a class="logout" href="/logout"><i class="fas fa-sign-out-alt"></i> خروج</a>
  </aside>

  <main class="content">
    <?php if ($dbError): ?><div class="flash error">خطأ قاعدة البيانات: <?= htmlspecialchars($dbError) ?></div><?php endif; ?>
    <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>

    <input id="quickFileInput" type="file" multiple class="hidden" />
    <div id="dropUploadOverlay" class="drop-upload-overlay hidden"><div class="drop-upload-box">أفلت الملفات هنا لرفعها مباشرة</div></div>

    <div class="section-head"><h2><?= htmlspecialchars($pageTitle) ?></h2><?php if ($route==='trash'): ?><button type="button" id="emptyTrashBtn" class="danger-btn"><i class="fas fa-trash"></i> حذف نهائي لكل الملفات</button><?php endif; ?></div>

    <div id="selectionSurface" class="selection-surface">
    <div class="folders-grid">
      <?php foreach ($folders as $fd): ?>
      <div class="folder-card" data-type="folder" data-id="<?= (int)$fd['id'] ?>" data-name="<?= htmlspecialchars($fd['name']) ?>" data-href="/folders/<?= (int)$fd['id'] ?>">
        <?php if (!empty($fd['preview_image'])): ?><img src="/<?= htmlspecialchars($fd['preview_image']) ?>" alt="preview" />
        <?php else: ?><div class="folder-placeholder">📁</div><?php endif; ?>
        <strong><?= htmlspecialchars($fd['name']) ?></strong>
      </div>
      <?php endforeach; ?>

    </div>
    <div class="files-grid" id="filesGrid">
      <?php if (!$files): ?><div class="empty">لا توجد ملفات.</div><?php endif; ?>
      <?php foreach ($files as $f): ?>
      <div class="file-grid-card folder-card" data-type="file" data-id="<?= (int)$f['id'] ?>" data-name="<?= htmlspecialchars($f['filename']) ?>" data-file-url="<?= htmlspecialchars(file_url($f)) ?>" data-shared="<?= $f['shared_token'] ? '1':'0' ?>" data-share-url="<?= $f['shared_token'] ? htmlspecialchars(share_url($f['shared_token'], (string)$f['filename'])) : '' ?>">
        <div class="file-grid-thumb-link">
          <?php if (str_starts_with((string)$f['mime_type'], 'image/')): ?><img src="<?= htmlspecialchars(file_url($f)) ?>" alt="thumb" />
          <?php else: ?><div class="folder-placeholder">📄</div><?php endif; ?>
        </div>
        <strong><?= htmlspecialchars($f['filename']) ?></strong>
      </div>
      <?php endforeach; ?>
    </div>
    <div id="filesInfiniteLoader" class="files-infinite-loader hidden" aria-live="polite">
      <div class="files-spinner" role="progressbar" aria-label="circular progressbar, single color"></div>
      <span>جاري تحميل المزيد...</span>
    </div>
    <div id="dragSelectionBox" class="drag-selection-box hidden" aria-hidden="true"></div>
    </div>
  </main>
</div>


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


<div id="moveModal" class="modal hidden"><div class="modal-box move-modal-box"><button class="close" data-close>×</button>
  <h3 id="moveModalTitle"><i class="fas fa-folder-open"></i> نقل العناصر المحددة</h3>
  <p class="move-current">اختر المجلد الهدف:</p>
  <input id="moveSearchInput" placeholder="ابحث عن مجلد..." />
  <div id="moveFolderList" class="move-folder-list">
    <button type="button" class="move-folder-item" data-folder-id=""><i class="far fa-hdd"></i><span>ملفاتي (الجذر)</span></button>
    <?php foreach ($allFolders as $af): ?>
      <button type="button" class="move-folder-item" data-folder-id="<?= (int)$af['id'] ?>"><i class="far fa-folder"></i><span><?= htmlspecialchars($af['name']) ?></span></button>
    <?php endforeach; ?>
  </div>
  <div class="move-actions"><button type="button" id="moveCancelBtn"><i class="fas fa-times"></i> إلغاء</button><button type="button" id="moveConfirmBtn" disabled><i class="fas fa-check"></i> نقل</button></div>
</div></div>

<div id="renameModal" class="modal hidden"><div class="modal-box rename-modal-box"><button class="close" data-close>×</button>
  <h3><i class="far fa-edit"></i> إعادة تسمية</h3>
  <p class="rename-current" id="renameCurrentLabel">العنصر المحدد</p>
  <input id="renameInput" placeholder="الاسم الجديد" />
  <div class="rename-actions"><button type="button" id="renameCancelBtn"><i class="fas fa-times"></i> إلغاء</button><button type="button" id="renameSaveBtn"><i class="fas fa-check"></i> حفظ</button></div>
</div></div>

<div id="shareModal" class="modal hidden"><div class="modal-box ShareDialog"><button class="close" data-close>×</button>
  <h1 class="ShareDialog-title">مشاركة الملف</h1>
  <div class="ShareDialog-itemInfo"><b id="shareFileName">-</b> (<span id="shareFileSize">-</span>)</div>
  <div class="ShareDialog-copyrightMessage hidden"><b>مقيّد</b> - لا يمكن مشاركة هذا الملف لأنه محمي بحقوق النشر.</div>
  <div class="ShareDialog-dmcaMessage hidden"><b>مقيّد</b> - لا يمكن مشاركة هذا الملف بسبب مطالبة DMCA.</div>
  <div class="ShareDialog-virusMessage hidden"><b>مقيّد</b> - لا يمكن مشاركة هذا الملف لأنه يحتوي على فيروس.</div>
  <div class="ShareDialog-links">
    <div class="ShareDialog-inputGroup" role="group" aria-labelledby="share-link-label">
      <label for="share-link-input" id="share-link-label" class="hidden">رابط المشاركة</label>
      <input id="share-link-input" class="ShareDialog-linkInput" type="text" value="" readonly="readonly">
      <button type="button" class="copy-link ShareDialog-copyBtn" id="shareCopyBtn"><i class="fas fa-link" aria-hidden="true"></i>نسخ الرابط</button>
    </div>
    <div class="ShareDialog-socialLinks" role="group" aria-label="روابط اجتماعية">
      <a href="#" target="_blank" rel="noopener" id="shareFacebook" class="ShareDialog-social ShareDialog-facebook"><span class="ShareDialog-socialIcon"><i class="fab fa-facebook-f" aria-hidden="true"></i></span><span class="ShareDialog-socialLabel">فيسبوك</span></a>
      <a href="#" target="_blank" rel="noopener" id="shareX" class="ShareDialog-social ShareDialog-x"><span class="ShareDialog-socialIcon"><i class="fa-brands fa-x-twitter" aria-hidden="true"></i></span><span class="ShareDialog-socialLabel">X</span></a>
      <a href="#" target="_blank" rel="noopener" id="shareEmail" class="ShareDialog-social ShareDialog-email"><span class="ShareDialog-socialIcon"><i class="fas fa-envelope" aria-hidden="true"></i></span><span class="ShareDialog-socialLabel">البريد</span></a>
      <a href="#" target="_blank" rel="noopener" id="shareReddit" class="ShareDialog-social ShareDialog-reddit"><span class="ShareDialog-socialIcon"><i class="fab fa-reddit-alien" aria-hidden="true"></i></span><span class="ShareDialog-socialLabel">ريديت</span></a>
      <a href="#" target="_blank" rel="noopener" id="shareBlogger" class="ShareDialog-social ShareDialog-blogger"><span class="ShareDialog-socialIcon"><i class="fab fa-blogger-b" aria-hidden="true"></i></span><span class="ShareDialog-socialLabel">بلوجر</span></a>
      <a href="#" target="_blank" rel="noopener" id="shareLinkedin" class="ShareDialog-social ShareDialog-linkedin"><span class="ShareDialog-socialIcon"><i class="fab fa-linkedin-in" aria-hidden="true"></i></span><span class="ShareDialog-socialLabel">لينكدإن</span></a>
      <a href="#" target="_blank" rel="noopener" id="shareWhatsapp" class="ShareDialog-social ShareDialog-whatsapp"><span class="ShareDialog-socialIcon"><i class="fab fa-whatsapp" aria-hidden="true"></i></span><span class="ShareDialog-socialLabel">واتساب</span></a>
      <a href="#" target="_blank" rel="noopener" id="shareTelegram" class="ShareDialog-social ShareDialog-telegram"><span class="ShareDialog-socialIcon"><i class="fab fa-telegram-plane" aria-hidden="true"></i></span><span class="ShareDialog-socialLabel">تلغرام</span></a>
    </div>
  </div>
</div></div>

<div id="ctxMenu" class="ctx-menu hidden modern-left-menu">
  <button data-cmd="share"><i class="fas fa-share-alt" aria-hidden="true"></i><span>مشاركة</span></button>
  <button data-cmd="copy"><i class="fas fa-link" aria-hidden="true"></i><span>نسخ الرابط</span></button>
  <button data-cmd="download"><i class="fas fa-download" aria-hidden="true"></i><span>تنزيل</span></button>
  <hr>
  <button data-cmd="move"><i class="far fa-folder-open" aria-hidden="true"></i><span>نقل إلى...</span></button>
  <button data-cmd="rename"><i class="far fa-edit" aria-hidden="true"></i><span>إعادة تسمية</span></button>
  <button data-cmd="password"><i class="fas fa-lock" aria-hidden="true"></i><span>حماية بكلمة مرور</span></button>
  <hr>
  <button data-cmd="delete"><i class="far fa-trash-alt" aria-hidden="true"></i><span>نقل إلى سلة المهملات</span></button>
</div>

<form id="cmdForm" method="post" class="hidden">
  <input type="hidden" name="action" id="cmdAction"><input type="hidden" name="id" id="cmdId"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><input type="hidden" name="new_name" id="cmdName">
</form>

<div id="toastRoot" class="toast-root" aria-live="polite" aria-atomic="true"></div>

<script>
const MAX_FILE = 5 * 1024 * 1024 * 1024;
const newBtn=document.getElementById('newBtn');
const newMenu=document.getElementById('newMenu');
if(newBtn && newMenu){
  newBtn.addEventListener('click',(e)=>{e.stopPropagation();newMenu.classList.toggle('hidden');});
  document.querySelectorAll('[data-open]').forEach(el=>el.addEventListener('click',()=>{
    if(el.dataset.open==='uploadFiles'){
      quickFileInput?.click();
      newMenu.classList.add('hidden');
      return;
    }
    const target=document.getElementById(el.dataset.open);
    if(target) target.classList.remove('hidden');
    newMenu.classList.add('hidden');
  }));
  document.addEventListener('click',(e)=>{if(!newMenu.contains(e.target) && e.target!==newBtn)newMenu.classList.add('hidden');});
}
document.querySelectorAll('[data-close]').forEach(el=>el.addEventListener('click',()=>el.closest('.modal').classList.add('hidden')));
window.addEventListener('click',(e)=>{if(e.target.classList.contains('modal')) e.target.classList.add('hidden');});
window.addEventListener('keydown',(e)=>{if(e.key==='Escape'){document.querySelectorAll('.modal').forEach(m=>m.classList.add('hidden'));if(newMenu)newMenu.classList.add('hidden');ctxMenu.classList.add('hidden');}});

// منع قائمة المتصفح الافتراضية للنقر بالزر الأيمن لإظهار تجربة قائمة موحّدة داخل التطبيق
document.addEventListener('contextmenu',(e)=>{
  e.preventDefault();
});

window.addEventListener('keydown',(e)=>{
  const isSelectAll=(e.ctrlKey||e.metaKey) && (e.key==='a' || e.key==='A');
  if(!isSelectAll) return;
  const tag=(e.target?.tagName||'').toLowerCase();
  const editable=e.target?.isContentEditable || ['input','textarea','select'].includes(tag);
  if(editable) return;
  const visibleItems=[...document.querySelectorAll('#selectionSurface [data-type]')].filter(el=>!el.classList.contains('lazy-hidden'));
  if(!visibleItems.length) return;
  e.preventDefault();
  setSelected(visibleItems);
  showToast(`تم تحديد ${visibleItems.length} عنصراً في الصفحة الحالية`,'info');
});

window.addEventListener('keydown', async (e)=>{
  if(e.key!=='Delete') return;
  const tag=(e.target?.tagName||'').toLowerCase();
  const editable=e.target?.isContentEditable || ['input','textarea','select'].includes(tag);
  if(editable) return;
  if(!selectedItems.length) return;
  e.preventDefault();
  for(const el of [...selectedItems]){
    await submitCmd('delete', el);
  }
  showToast('تم نقل العناصر المحددة إلى سلة المهملات','success');
  setSelected([]);
});

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

const quickFileInput = document.getElementById('quickFileInput');
const dropUploadOverlay = document.getElementById('dropUploadOverlay');
const pWrap = document.getElementById('uploadProgress');
const pBar = document.getElementById('uploadProgressBar');
const pText = document.getElementById('uploadProgressText');
const pSpeed = document.getElementById('uploadSpeedText');
const activeFolderId = <?= $route==='folder' ? (int)$currentFolderId : 'null' ?>;

function buildUploadFormData(file){
  const fd=new FormData();
  fd.append('action','upload_ajax');
  fd.append('redirect', window.location.pathname);
  fd.append('folder_id', activeFolderId==null ? '' : String(activeFolderId));
  fd.append('file', file);
  return fd;
}

async function uploadSingleFile(file, idx, total){
  return new Promise((resolve,reject)=>{
    const xhr=new XMLHttpRequest();
    xhr.open('POST', window.location.pathname, true);
    const started=performance.now();

    xhr.upload.onprogress=(ev)=>{
      if(!ev.lengthComputable) return;
      const percent=Math.round((ev.loaded/ev.total)*100);
      pBar.style.width=percent+'%';
      pText.textContent=`${idx}/${total} • ${percent}%`;
      const elapsed=Math.max((performance.now()-started)/1000,0.001);
      const speedMB=(ev.loaded/elapsed)/(1024*1024);
      pSpeed.textContent=speedMB.toFixed(2)+' م.ب/ث';
    };

    xhr.onload=()=>{
      if(xhr.status>=200 && xhr.status<300) resolve();
      else {
        try{ const j=JSON.parse(xhr.responseText); reject(new Error(j.message||'فشل الرفع')); }
        catch(_){ reject(new Error('فشل الرفع')); }
      }
    };
    xhr.onerror=()=>reject(new Error('فشل الاتصال أثناء الرفع.'));
    xhr.send(buildUploadFormData(file));
  });
}

async function uploadFiles(files){
  const list=[...files];
  if(!list.length) return;
  const oversize=list.find(f=>f.size>MAX_FILE);
  if(oversize){ showToast('يوجد ملف أكبر من 5 جيجابايت.','warn'); return; }

  pWrap.classList.remove('hidden');
  pBar.style.width='0%';
  pText.textContent='0%';
  pSpeed.textContent='0 م.ب/ث';

  try {
    for(let i=0;i<list.length;i++) await uploadSingleFile(list[i], i+1, list.length);
    pBar.style.width='100%';
    pText.textContent='اكتمل الرفع';
    pSpeed.textContent=`تم رفع ${list.length} ملف`;
    setTimeout(()=>location.reload(), 400);
  } catch (e) {
    pWrap.classList.add('hidden');
    showToast(e.message,'warn');
  }
}

quickFileInput?.addEventListener('change', ()=>{
  if(!quickFileInput.files?.length) return;
  uploadFiles(quickFileInput.files);
  quickFileInput.value='';
});


function hasRealFiles(dt){
  if(!dt) return false;
  if(dt.items && dt.items.length){
    return [...dt.items].some(it=>it.kind==='file');
  }
  return !!(dt.files && dt.files.length);
}

document.querySelectorAll('.folder-card img, .file-grid-thumb-link').forEach(el=>{
  el.setAttribute('draggable','false');
  el.addEventListener('dragstart',(e)=>e.preventDefault());
});

let dragDepth=0;
window.addEventListener('dragenter',(e)=>{
  if(!hasRealFiles(e.dataTransfer)) return;
  dragDepth++;
  dropUploadOverlay?.classList.remove('hidden');
});
window.addEventListener('dragover',(e)=>{
  if(!hasRealFiles(e.dataTransfer)) return;
  e.preventDefault();
});
window.addEventListener('dragleave',()=>{
  dragDepth=Math.max(0, dragDepth-1);
  if(dragDepth===0) dropUploadOverlay?.classList.add('hidden');
});
window.addEventListener('drop',(e)=>{
  if(!hasRealFiles(e.dataTransfer)) return;
  e.preventDefault();
  dragDepth=0;
  dropUploadOverlay?.classList.add('hidden');
  uploadFiles(e.dataTransfer.files);
});

const ctxMenu=document.getElementById('ctxMenu');
const selectionBar=document.getElementById('selectionBar');
const selectionCount=document.getElementById('selectionCount');
const shareModal=document.getElementById('shareModal');
const shareFileName=document.getElementById('shareFileName');
const shareFileSize=document.getElementById('shareFileSize');
const shareLinkInput=document.getElementById('share-link-input');
const shareCopyBtn=document.getElementById('shareCopyBtn');
const shareFacebook=document.getElementById('shareFacebook');
const shareX=document.getElementById('shareX');
const shareEmail=document.getElementById('shareEmail');
const shareReddit=document.getElementById('shareReddit');
const shareBlogger=document.getElementById('shareBlogger');
const shareLinkedin=document.getElementById('shareLinkedin');
const shareWhatsapp=document.getElementById('shareWhatsapp');
const shareTelegram=document.getElementById('shareTelegram');
const selectionMeta=document.getElementById('selectionMeta');
const moveModal=document.getElementById('moveModal');
const moveModalTitle=document.getElementById('moveModalTitle');
const moveSearchInput=document.getElementById('moveSearchInput');
const moveFolderList=document.getElementById('moveFolderList');
const moveConfirmBtn=document.getElementById('moveConfirmBtn');
const moveCancelBtn=document.getElementById('moveCancelBtn');
const renameModal=document.getElementById('renameModal');
const renameInput=document.getElementById('renameInput');
const renameCurrentLabel=document.getElementById('renameCurrentLabel');
const renameSaveBtn=document.getElementById('renameSaveBtn');
const renameCancelBtn=document.getElementById('renameCancelBtn');
const emptyTrashBtn=document.getElementById('emptyTrashBtn');
const toastRoot=document.getElementById('toastRoot');
let currentTarget=null;
let selectedItems=[];
let dragMovePayload=null;

function buildMovePayload(items){
  const unique=[...new Set(items)].filter(Boolean);
  const files=unique.filter(el=>el.dataset.type==='file');
  const folders=unique.filter(el=>el.dataset.type==='folder');
  return {
    elements: unique,
    fileIds: files.map(el=>el.dataset.id).filter(Boolean),
    folderIds: folders.map(el=>el.dataset.id).filter(Boolean),
  };
}

function removeMovedItemsFromView(items, targetFolderId){
  const targetStr=(targetFolderId==null || targetFolderId==='') ? '' : String(targetFolderId);
  items.forEach(el=>{
    if(!el || !document.body.contains(el)) return;
    if(el.dataset.type==='folder' && String(el.dataset.id||'')===targetStr) return;
    el.remove();
  });
  setSelected(selectedItems.filter(el=>document.body.contains(el)));
}

async function moveElementsToFolder(items, targetFolderId){
  const payload=buildMovePayload(items);
  if(!payload.fileIds.length && !payload.folderIds.length){
    showToast('لا توجد عناصر صالحة للنقل.','warn');
    return;
  }
  const targetStr=(targetFolderId==null || targetFolderId==='') ? '' : String(targetFolderId);
  if(payload.folderIds.includes(targetStr)){
    showToast('لا يمكن نقل المجلد إلى نفسه.','warn');
    return;
  }
  await postAction('move_items',{target_folder_id:targetStr,file_ids:payload.fileIds,folder_ids:payload.folderIds});
  removeMovedItemsFromView(payload.elements, targetStr);
  showToast('تم نقل العناصر بنجاح','success');
}

function setSelected(items){
  document.querySelectorAll('.is-selected').forEach(el=>el.classList.remove('is-selected'));
  selectedItems=[...new Set(items)].filter(Boolean);
  selectedItems.forEach(el=>el.classList.add('is-selected'));
  selectionCount.textContent=String(selectedItems.length);
  if(selectionBar) selectionBar.classList.toggle('hidden', selectedItems.length<2);
  updateSelectionActions();
  updateSelectionMeta();
}
function pickOne(el){ setSelected([el]); currentTarget=el; }
function getPrimary(){ return currentTarget || selectedItems[0] || null; }

function showToast(message, tone='info'){
  if(!toastRoot) return;
  const el=document.createElement('div');
  el.className='toast toast-'+tone;
  el.textContent=message;
  toastRoot.appendChild(el);
  requestAnimationFrame(()=>el.classList.add('show'));
  setTimeout(()=>{ el.classList.remove('show'); setTimeout(()=>el.remove(),180); }, 2600);
}

function isShared(el){ return !!el?.dataset?.shareUrl; }
function updateSelectionMeta(){
  if(!selectionMeta){ return; }
  if(!selectedItems.length){ selectionMeta.textContent=''; return; }
  if(selectedItems.length>1){
    const fileCount=selectedItems.filter(x=>x.dataset.type==='file').length;
    selectionMeta.textContent=`التحديد الحالي: ${fileCount} ملف.`;
    return;
  }
  const el=selectedItems[0];
  if(el.dataset.type!=='file'){
    selectionMeta.textContent='العنصر المحدد مجلد.';
    return;
  }
  selectionMeta.textContent=`الحالة: ${isShared(el)?'مشترك':'غير مشترك'}`;
}

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

function buildShareLinks(url, name){
  const enc=encodeURIComponent(url);
  const text=encodeURIComponent('شارك هذا الملف: '+name);
  shareFacebook.href='https://www.facebook.com/sharer/sharer.php?u='+enc;
  shareX.href='https://twitter.com/intent/tweet?url='+enc+'&text='+text;
  shareEmail.href='mailto:?subject='+encodeURIComponent(name)+'&body='+enc;
  shareReddit.href='https://www.reddit.com/submit?url='+enc+'&title='+encodeURIComponent(name);
  shareBlogger.href='https://www.blogger.com/blog-this.g?u='+enc+'&n='+encodeURIComponent(name);
  shareLinkedin.href='https://www.linkedin.com/sharing/share-offsite/?url='+enc;
  shareWhatsapp.href='https://wa.me/?text='+text+'%20'+enc;
  shareTelegram.href='https://t.me/share/url?url='+enc+'&text='+text;
}

async function ensureShareUrl(el){
  if(el.dataset.shareUrl) return el.dataset.shareUrl;
  const res=await postAction('toggle_share_file',{id:el.dataset.id});
  el.dataset.shareUrl=res.share_url||'';
  el.dataset.shared=el.dataset.shareUrl?'1':'0';
  return el.dataset.shareUrl;
}

async function openShareDialog(el){
  if(!el || el.dataset.type!=='file'){ showToast('المشاركة متاحة للملفات فقط.','warn'); return; }
  shareFileName.textContent=(el.dataset.name||'ملف');
  const sizeText=el.querySelector('small')?.textContent?.split('•')[0]?.trim()||'-';
  shareFileSize.textContent=sizeText;
  const url=await ensureShareUrl(el);
  if(!url){ showToast('تعذر إنشاء رابط مشاركة.','warn'); return; }
  const full=window.location.origin+url;
  shareLinkInput.value=full;
  buildShareLinks(full, el.dataset.name||'ملف');
  shareModal.classList.remove('hidden');
}


async function postAction(action, payload={}){
  const fd=new FormData();
  fd.append('action', action);
  fd.append('redirect', window.location.pathname);
  Object.entries(payload).forEach(([k,v])=>{
    if(Array.isArray(v)){
      v.forEach(item=>fd.append(`${k}[]`, item==null?'':String(item)));
      return;
    }
    fd.append(k, v==null?'':String(v));
  });
  const r=await fetch(window.location.pathname,{method:'POST',headers:{'X-Requested-With':'XMLHttpRequest'},body:fd});
  const j=await r.json();
  if(!r.ok || !j.ok) throw new Error(j.message||'فشلت العملية');
  return j;
}


function getFileUrl(el){
  if(!el) return '';
  return el.dataset.fileUrl || el.querySelector('[data-file-url]')?.dataset.fileUrl || '';
}

async function submitCmd(cmd, el){
  if(!el) return;
  const type=el.dataset.type;
  const id=el.dataset.id;
    if(cmd==='download'){
    if(type!=='file') return;
    const fileUrl=getFileUrl(el);
    if(fileUrl) window.open(fileUrl + (fileUrl.includes('?')?'&':'?')+'download=1','_blank');
    return;
  }
  if(cmd==='info'){
    showToast(`الملف: ${el.dataset.name||'-'} • النوع: ${type}`,'info');
    return;
  }
  if(cmd==='rename'){
    openRenameModal(el);
    return;
  }
  if(cmd==='password'){ showToast('ميزة حماية كلمة المرور ستتوفر قريباً.','info'); return; }
  if(cmd==='move'){
    openMoveModal([el]);
    return;
  }
  if(cmd==='share' && type==='file'){ openShareDialog(el); return; }
  if(cmd==='copy' && type==='file'){
    const url=await ensureShareUrl(el);
    if(!url){ showToast('تعذر إنشاء رابط مشاركة.','warn'); return; }
    await navigator.clipboard.writeText(window.location.origin+url);
    showToast('تم إنشاء ونسخ رابط مشاركة عام مباشرة','success');
    updateSelectionMeta();
    return;
  }
  if(cmd==='delete'){
    await postAction((type==='file'?'trash':'delete_folder'), {id:id});
    el.remove();
  }
}

document.querySelectorAll('[data-type]').forEach(el=>{
  el.classList.add('selectable-item');
  el.setAttribute('draggable','true');

  el.addEventListener('click',(e)=>{
    if(e.target.closest('button,form,.star')) return;
    if(e.metaKey || e.ctrlKey){
      const next=selectedItems.includes(el)?selectedItems.filter(x=>x!==el):[...selectedItems, el];
      setSelected(next);
    } else {
      pickOne(el);
    }
    if(el.dataset.type==='folder' && !e.metaKey && !e.ctrlKey){
      const href=el.dataset.href||'';
      if(href){ window.location.href=href; return; }
    }
  });

  el.addEventListener('dragstart',(e)=>{
    const sourceItems=selectedItems.includes(el) ? selectedItems : [el];
    if(!selectedItems.includes(el)) pickOne(el);
    const payload=buildMovePayload(sourceItems);
    dragMovePayload=payload;
    e.dataTransfer.effectAllowed='move';
    e.dataTransfer.setData('text/plain', JSON.stringify({file_ids:payload.fileIds, folder_ids:payload.folderIds}));
    el.classList.add('is-dragging');
  });

  el.addEventListener('dragend',()=>{
    dragMovePayload=null;
    document.querySelectorAll('.drop-target-active').forEach(x=>x.classList.remove('drop-target-active'));
    document.querySelectorAll('.is-dragging').forEach(x=>x.classList.remove('is-dragging'));
  });

  if(el.dataset.type==='folder'){
    el.addEventListener('dragover',(e)=>{
      if(!dragMovePayload) return;
      e.preventDefault();
      e.dataTransfer.dropEffect='move';
    });

    el.addEventListener('dragenter',(e)=>{
      if(!dragMovePayload) return;
      e.preventDefault();
      el.classList.add('drop-target-active');
    });

    el.addEventListener('dragleave',()=>{
      el.classList.remove('drop-target-active');
    });

    el.addEventListener('drop', async (e)=>{
      if(!dragMovePayload) return;
      e.preventDefault();
      e.stopPropagation();
      el.classList.remove('drop-target-active');
      const targetFolderId=String(el.dataset.id||'');
      try{
        await moveElementsToFolder(dragMovePayload.elements, targetFolderId);
      }catch(err){
        showToast(err.message||'فشلت عملية النقل.','warn');
      } finally {
        dragMovePayload=null;
      }
    });
  }

  el.addEventListener('contextmenu',(e)=>openMenu(e, el));
});

const selectionSurface=document.getElementById('selectionSurface');
const dragSelectionBox=document.getElementById('dragSelectionBox');
let dragState=null;
let suppressClearOnce=false;

function getRectFromPoints(a,b){
  const left=Math.min(a.x,b.x);
  const top=Math.min(a.y,b.y);
  return {left, top, width:Math.abs(a.x-b.x), height:Math.abs(a.y-b.y)};
}

function intersects(r1,r2){
  return !(r2.left>r1.left+r1.width || r2.left+r2.width<r1.left || r2.top>r1.top+r1.height || r2.top+r2.height<r1.top);
}

selectionSurface?.addEventListener('mousedown',(e)=>{
  if(e.button!==0) return;
  if(e.target.closest('[data-type],button,a,input,select,textarea,form,#ctxMenu,.modal-box')) return;
  const surfaceRect=selectionSurface.getBoundingClientRect();
  dragState={start:{x:e.clientX,y:e.clientY},surfaceRect,dragged:false};
  dragSelectionBox.classList.remove('hidden');
  dragSelectionBox.style.left=(e.clientX-surfaceRect.left+selectionSurface.scrollLeft)+'px';
  dragSelectionBox.style.top=(e.clientY-surfaceRect.top+selectionSurface.scrollTop)+'px';
  dragSelectionBox.style.width='0px';
  dragSelectionBox.style.height='0px';
  setSelected([]);
  e.preventDefault();
});

document.addEventListener('mousemove',(e)=>{
  if(!dragState || !selectionSurface || !dragSelectionBox) return;
  const rect=getRectFromPoints(dragState.start,{x:e.clientX,y:e.clientY});
  if(rect.width>3 || rect.height>3) dragState.dragged=true;
  dragSelectionBox.style.left=(rect.left-dragState.surfaceRect.left+selectionSurface.scrollLeft)+'px';
  dragSelectionBox.style.top=(rect.top-dragState.surfaceRect.top+selectionSurface.scrollTop)+'px';
  dragSelectionBox.style.width=rect.width+'px';
  dragSelectionBox.style.height=rect.height+'px';

  const touched=[];
  selectionSurface.querySelectorAll('[data-type]').forEach(el=>{
    const r=el.getBoundingClientRect();
    if(intersects(rect,{left:r.left,top:r.top,width:r.width,height:r.height})) touched.push(el);
  });
  setSelected(touched);
});

document.addEventListener('mouseup',()=>{
  if(!dragState || !dragSelectionBox) return;
  dragSelectionBox.classList.add('hidden');
  suppressClearOnce=!!dragState.dragged;
  dragState=null;
});

document.addEventListener('click',(e)=>{
  if(suppressClearOnce){ suppressClearOnce=false; return; }
  if(!e.target.closest('[data-type], #ctxMenu, #selectionBar, #shareModal .modal-box, #moveModal .modal-box')){
    setSelected([]);
  }
  if(!e.target.closest('#ctxMenu')) ctxMenu.classList.add('hidden');
});

document.querySelectorAll('[data-select-cmd]').forEach(btn=>btn.addEventListener('click',async ()=>{
  const cmd=btn.dataset.selectCmd;
  if(selectedItems.length<2){ showToast('حدد ملفين فأكثر لإظهار شريط الإجراءات.','warn'); return; }

  const filesOnly=selectedItems.filter(el=>el.dataset.type==='file');
  const primary=selectedItems[0];

  if(cmd==='download'){
    if(!filesOnly.length){ showToast('التنزيل متاح للملفات فقط.','warn'); return; }
    for(const el of filesOnly){
      const fileUrl=getFileUrl(el);
      if(fileUrl) window.open(fileUrl + (fileUrl.includes('?')?'&':'?')+'download=1','_blank');
    }
    showToast(`بدأ تنزيل ${filesOnly.length} ملف`,'success');
    return;
  }

  if(cmd==='move'){ openMoveModal(selectedItems); return; }

  if(cmd==='delete'){
    for(const el of selectedItems){ await submitCmd('delete', el); }
    showToast('تم تنفيذ النقل إلى المهملات للعناصر المحددة','success');
    setSelected([]);
    return;
  }

  if(cmd==='share' || cmd==='copy' || cmd==='rename'){
    showToast('هذه العملية لا تدعم التحديد المتعدد في هذا المشروع حالياً.','warn');
    return;
  }

  submitCmd(cmd, primary).catch(e=>showToast(e.message,'warn'));
}));


let pendingMoveItems=[];
let moveTargetFolder='';
let renameTarget=null;

function openRenameModal(el){
  renameTarget=el||null;
  if(!renameTarget) return;
  if(renameCurrentLabel) renameCurrentLabel.textContent=`العنصر الحالي: ${renameTarget.dataset.name||''}`;
  if(renameInput) renameInput.value=renameTarget.dataset.name||'';
  renameModal?.classList.remove('hidden');
  setTimeout(()=>renameInput?.focus(), 50);
}


function updateSelectionActions(){
  if(!selectionBar) return;
  const count=selectedItems.length;
  const filesOnly=selectedItems.filter(el=>el.dataset.type==='file').length;
  const hasFolder=selectedItems.some(el=>el.dataset.type==='folder');
  const btn=(cmd)=>selectionBar.querySelector(`[data-select-cmd="${cmd}"]`);

  if(btn('download')) btn('download').classList.toggle('hidden', !(count>=2 && filesOnly>0));
  if(btn('move')) btn('move').classList.toggle('hidden', count<2);
  if(btn('delete')) btn('delete').classList.toggle('hidden', count<2);
  if(btn('rename')) btn('rename').classList.add('hidden');
  if(btn('share')) btn('share').classList.add('hidden');
  if(btn('copy')) btn('copy').classList.add('hidden');
}

function openMoveModal(items){
  pendingMoveItems=[...items];
  moveTargetFolder='';
  if(moveModalTitle) moveModalTitle.textContent=`نقل ${items.length} عنصر`;
  moveConfirmBtn.disabled=true;
  moveModal.classList.remove('hidden');
}

moveFolderList?.addEventListener('click',(e)=>{
  const btn=e.target.closest('.move-folder-item');
  if(!btn) return;
  moveTargetFolder=btn.dataset.folderId||'';
  moveFolderList.querySelectorAll('.move-folder-item').forEach(x=>x.classList.remove('active'));
  btn.classList.add('active');
  moveConfirmBtn.disabled=false;
});

moveSearchInput?.addEventListener('input',()=>{
  const q=moveSearchInput.value.trim().toLowerCase();
  moveFolderList.querySelectorAll('.move-folder-item').forEach(btn=>{
    const t=btn.textContent.toLowerCase();
    btn.classList.toggle('hidden', q && !t.includes(q));
  });
});

moveCancelBtn?.addEventListener('click',()=>moveModal.classList.add('hidden'));
moveConfirmBtn?.addEventListener('click', async ()=>{
  if(!pendingMoveItems.length) return;
  try{
    await moveElementsToFolder(pendingMoveItems, moveTargetFolder);
    moveModal.classList.add('hidden');
  }catch(err){
    showToast(err.message||'فشلت عملية النقل.','warn');
  }
});

renameCancelBtn?.addEventListener('click',()=>renameModal?.classList.add('hidden'));
renameSaveBtn?.addEventListener('click', async ()=>{
  if(!renameTarget) return;
  const n=(renameInput?.value||'').trim();
  if(!n){ showToast('أدخل اسماً جديداً.','warn'); return; }
  await postAction((renameTarget.dataset.type==='file'?'rename_file':'rename_folder'), {id:renameTarget.dataset.id,new_name:n});
  renameTarget.dataset.name=n;
  const lbl=renameTarget.querySelector('strong'); if(lbl) lbl.textContent=n;
  renameModal?.classList.add('hidden');
  showToast('تمت إعادة التسمية بنجاح','success');
});
renameInput?.addEventListener('keydown',(e)=>{ if(e.key==='Enter'){ e.preventDefault(); renameSaveBtn?.click(); }});

emptyTrashBtn?.addEventListener('click', async ()=>{
  if(!confirm('هل تريد حذف كل الملفات من سلة المهملات نهائياً؟')) return;
  await postAction('empty_trash',{});
  showToast('تم حذف كل ملفات سلة المهملات نهائياً','success');
  setTimeout(()=>location.reload(), 300);
});

shareCopyBtn?.addEventListener('click', async ()=>{
  const primary=getPrimary();
  if(!primary || primary.dataset.type!=='file'){ showToast('اختر ملفاً أولاً.','warn'); return; }
  const url=await ensureShareUrl(primary);
  if(!url){ showToast('تعذر إنشاء رابط مشاركة.','warn'); return; }
  const full=window.location.origin + url;
  shareLinkInput.value=full;
  buildShareLinks(full, primary.dataset.name||'ملف');
  await navigator.clipboard.writeText(full);
  showToast('تم نسخ الرابط','success');
  updateSelectionMeta();
});

ctxMenu?.querySelectorAll('button').forEach(btn=>btn.addEventListener('click',(e)=>{
  e.stopPropagation();
  ctxMenu.classList.add('hidden');
  const primary=getPrimary();
  if(!primary) return;
  submitCmd(btn.dataset.cmd, primary).catch(e=>showToast(e.message,'warn'));
}));

(function setupInfiniteFilesLoading(){
  const content=document.querySelector('main.content');
  const filesGrid=document.getElementById('filesGrid');
  const loader=document.getElementById('filesInfiniteLoader');
  if(!content || !filesGrid || !loader) return;

  const cards=Array.from(filesGrid.querySelectorAll('.file-grid-card[data-type="file"]'));
  const pageSize=24;
  if(cards.length<=pageSize){
    loader.classList.add('hidden');
    return;
  }

  let visibleCount=pageSize;
  let loading=false;

  function render(){
    cards.forEach((card,idx)=>card.classList.toggle('lazy-hidden', idx>=visibleCount));
    loader.classList.toggle('hidden', visibleCount>=cards.length);
  }

  async function loadMore(){
    if(loading || visibleCount>=cards.length) return;
    loading=true;
    loader.classList.add('is-loading');
    await new Promise(r=>setTimeout(r, 320));
    visibleCount=Math.min(visibleCount+pageSize, cards.length);
    render();
    loader.classList.remove('is-loading');
    loading=false;
  }

  content.addEventListener('scroll',()=>{
    const nearBottom=content.scrollTop + content.clientHeight >= content.scrollHeight - 160;
    if(nearBottom) loadMore();
  },{passive:true});

  render();
})();
</script>
<?php endif; ?>
</body>
</html>
