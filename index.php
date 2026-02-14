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
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uq_file_token (shared_token),
      INDEX idx_user_status (user_id, is_trashed, is_starred),
      INDEX idx_user_created (user_id, created_at),
      INDEX idx_user_folder (user_id, folder_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $cols = $pdo->query("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='files'")->fetchAll(PDO::FETCH_COLUMN);
    if (!in_array('folder_id', $cols, true)) $pdo->exec("ALTER TABLE files ADD COLUMN folder_id BIGINT UNSIGNED NULL, ADD INDEX idx_user_folder (user_id, folder_id)");
    if (!in_array('shared_token', $cols, true)) $pdo->exec("ALTER TABLE files ADD COLUMN shared_token VARCHAR(64) NULL, ADD UNIQUE KEY uq_file_token (shared_token)");

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
function share_url(string $token): string { return '/s/' . $token; }
function token(): string { return bin2hex(random_bytes(16)); }

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
    $q = $pdo->prepare('SELECT * FROM files WHERE shared_token=? LIMIT 1');
    $q->execute([$segments[1]]);
    $file = $q->fetch();
    if (!$file) { http_response_code(404); exit('Shared file not found'); }
    $abs = __DIR__ . '/' . $file['relative_path'];
    if (!is_file($abs)) { http_response_code(404); exit('Missing file'); }
    header('Content-Type: ' . ($file['mime_type'] ?: 'application/octet-stream'));
    header('Content-Length: ' . filesize($abs));
    header("Content-Disposition: inline; filename*=UTF-8''" . rawurlencode($file['filename']));
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
    $abs = __DIR__ . '/' . $file['relative_path'];
    if (!is_file($abs)) { http_response_code(404); exit('Missing'); }
    header('Content-Type: ' . ($file['mime_type'] ?: 'application/octet-stream'));
    header('Content-Length: ' . filesize($abs));
    header("Content-Disposition: inline; filename*=UTF-8''" . rawurlencode($file['filename']));
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
                $tokenValue = $row['shared_token'] ? null : token();
                $st = $pdo->prepare('UPDATE files SET shared_token=? WHERE id=? AND user_id=?');
                $st->execute([$tokenValue, $id, $user['id']]);
            }
        }

        if ($action === 'upload' || $action === 'upload_ajax' || $action === 'upload_folder') {
            if (empty($_FILES['file']['name']) && empty($_FILES['files']['name'])) throw new RuntimeException('اختر ملفاً أو مجلداً أولاً.');
            $currentStorage = get_user_storage($pdo, $user['id']);

            $processSingle = function(array $one, ?int $folderId, ?string $displayName=null) use (&$currentStorage, $config, $pdo, $user) {
                if ($one['error'] !== UPLOAD_ERR_OK) throw new RuntimeException('فشل رفع ملف.');
                if ((int)$one['size'] > (int)$config['max_upload_size']) throw new RuntimeException('الملف أكبر من 5 جيجابايت.');
                if (($currentStorage + (int)$one['size']) > USER_STORAGE_LIMIT) throw new RuntimeException('تم تجاوز سعة المستخدم 1 تيرابايت.');
                $name = $displayName ?: (string)$one['name'];
                $ext = pathinfo($name, PATHINFO_EXTENSION);
                $stored = bin2hex(random_bytes(20)) . ($ext ? '.' . $ext : '');
                $dest = $config['upload_dir'] . '/' . $stored;
                if (!move_uploaded_file($one['tmp_name'], $dest)) throw new RuntimeException('تعذر حفظ الملف.');
                $mime = mime_content_type($dest) ?: 'application/octet-stream';
                $st = $pdo->prepare('INSERT INTO files (user_id,user_name,folder_id,filename,stored_name,mime_type,size_bytes,relative_path) VALUES (?,?,?,?,?,?,?,?)');
                $st->execute([$user['id'], $user['name'], $folderId, $name, $stored, $mime, (int)$one['size'], 'uploads/' . $stored]);
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

$files = [];
$folders = [];
$allFolders = [];
$storage = 0;
$search = trim((string)($_GET['q'] ?? ''));
$pageTitle = 'My Drive';

if ($user && $route !== 'login' && $pdo) {
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

    <div id="uploadProgress" class="progress hidden"><div id="uploadProgressBar"></div><p id="uploadProgressText">0%</p></div>

    <div class="section-head"><h2><?= htmlspecialchars($pageTitle) ?></h2><div>☰ ⓘ</div></div>
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
      <a href="<?= htmlspecialchars(file_url($f)) ?>" target="_blank" class="folder-card" data-type="file" data-id="<?= (int)$f['id'] ?>" data-name="<?= htmlspecialchars($f['filename']) ?>" data-shared="<?= $f['shared_token'] ? '1':'0' ?>" data-share-url="<?= $f['shared_token'] ? htmlspecialchars(share_url($f['shared_token'])) : '' ?>">
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
      <div class="row" data-type="file" data-id="<?= (int)$f['id'] ?>" data-name="<?= htmlspecialchars($f['filename']) ?>" data-shared="<?= $f['shared_token'] ? '1':'0' ?>" data-share-url="<?= $f['shared_token'] ? htmlspecialchars(share_url($f['shared_token'])) : '' ?>">
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

<div id="ctxMenu" class="ctx-menu hidden">
  <button data-cmd="rename">إعادة تسمية</button>
  <button data-cmd="move">نقل</button>
  <button data-cmd="share">مشاركة / إلغاء المشاركة</button>
  <button data-cmd="copy">نسخ رابط المشاركة</button>
  <button data-cmd="delete">حذف</button>
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
uploadForm?.addEventListener('submit',(e)=>{
  e.preventDefault();
  if(!singleFile.files.length) return;
  const f=singleFile.files[0];
  if(f.size>MAX_FILE){ alert('الملف أكبر من 5 جيجابايت.'); return; }
  const fd=new FormData(uploadForm);
  const xhr=new XMLHttpRequest();
  xhr.open('POST', window.location.pathname, true);
  pWrap.classList.remove('hidden');
  xhr.upload.onprogress=(ev)=>{
    if(ev.lengthComputable){
      const percent=Math.round((ev.loaded/ev.total)*100);
      pBar.style.width=percent+'%';
      pText.textContent=percent+'%';
    }
  };
  xhr.onload=()=>{
    if(xhr.status>=200 && xhr.status<300){ location.reload(); }
    else { try{const j=JSON.parse(xhr.responseText); alert(j.message||'فشل الرفع');}catch(_){alert('فشل الرفع');} }
  };
  xhr.onerror=()=>alert('فشل الاتصال أثناء الرفع.');
  xhr.send(fd);
});

const ctxMenu=document.getElementById('ctxMenu');
let currentTarget=null;
function openMenu(ev, el){
  ev.preventDefault();
  currentTarget=el;
  ctxMenu.style.left=ev.clientX+'px';
  ctxMenu.style.top=ev.clientY+'px';
  ctxMenu.classList.remove('hidden');
}
document.querySelectorAll('[data-type]').forEach(el=>{
  el.addEventListener('contextmenu',(e)=>openMenu(e, el));
});
document.addEventListener('click',()=>ctxMenu.classList.add('hidden'));

const cmdForm=document.getElementById('cmdForm');
const cmdAction=document.getElementById('cmdAction');
const cmdId=document.getElementById('cmdId');
const cmdName=document.getElementById('cmdName');
ctxMenu?.querySelectorAll('button').forEach(btn=>btn.addEventListener('click',(e)=>{
  e.stopPropagation();
  if(!currentTarget) return;
  const type=currentTarget.dataset.type;
  const id=currentTarget.dataset.id;
  const cmd=btn.dataset.cmd;

  if(cmd==='rename'){
    const n=prompt('الاسم الجديد:', currentTarget.dataset.name||'');
    if(!n) return;
    cmdAction.value=(type==='file'?'rename_file':'rename_folder'); cmdId.value=id; cmdName.value=n; cmdForm.submit();
  }
  if(cmd==='move' && type==='file'){
    const to=prompt('أدخل رقم المجلد الهدف (فارغ = الجذر):','');
    const form=document.createElement('form'); form.method='post'; form.className='hidden';
    form.innerHTML=`<input name="action" value="move_file"><input name="id" value="${id}"><input name="target_folder_id" value="${to}"><input name="redirect" value="${window.location.pathname}">`;
    document.body.appendChild(form); form.submit();
  }
  if(cmd==='share' && type==='file'){
    cmdAction.value='toggle_share_file'; cmdId.value=id; cmdName.value=''; cmdForm.submit();
  }
  if(cmd==='copy' && type==='file'){
    const url=currentTarget.dataset.shareUrl;
    if(!url){ alert('الملف غير مشارك. فعّل المشاركة أولاً.'); return; }
    navigator.clipboard.writeText(window.location.origin+url); alert('تم نسخ رابط المشاركة');
  }
  if(cmd==='delete'){
    cmdAction.value=(type==='file'?'trash':'delete_folder'); cmdId.value=id; cmdName.value=''; cmdForm.submit();
  }
}));
</script>
<?php endif; ?>
</body>
</html>
