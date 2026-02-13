<?php
session_start();
$config = require __DIR__ . '/config.php';

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
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
      is_starred TINYINT(1) NOT NULL DEFAULT 0,
      is_trashed TINYINT(1) NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_user_status (user_id, is_trashed, is_starred),
      INDEX idx_user_created (user_id, created_at),
      INDEX idx_user_folder (user_id, folder_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

    $check = $pdo->query("SELECT COUNT(*) c FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='files' AND COLUMN_NAME='folder_id'")->fetch();
    if ((int)$check['c'] === 0) {
        $pdo->exec("ALTER TABLE files ADD COLUMN folder_id BIGINT UNSIGNED NULL, ADD INDEX idx_user_folder (user_id, folder_id)");
    }
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
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return round($bytes, 2) . ' ' . $units[$i];
}

function file_url(array $f): string {
    return '/d/' . (int)$f['id'] . '/' . rawurlencode((string)$f['filename']);
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
    header('X-Content-Type-Options: nosniff');
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
if (empty($segments)) {
    $route = empty($_SESSION['user']) ? 'login' : 'drive';
} elseif ($segments[0] === 'login') {
    $route = 'login';
} elseif ($segments[0] === 'drive') {
    $route = 'drive';
} elseif ($segments[0] === 'recent') {
    $route = 'recent';
} elseif ($segments[0] === 'starred') {
    $route = 'starred';
} elseif ($segments[0] === 'trash') {
    $route = 'trash';
} elseif ($segments[0] === 'search') {
    $route = 'search';
} elseif ($segments[0] === 'folders' && isset($segments[1])) {
    $route = 'folder';
    $currentFolderId = (int)$segments[1];
}

$flash = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    try {
        if ($action === 'login') {
            $xf = xf_auth($config, trim($_POST['username'] ?? ''), (string)($_POST['password'] ?? ''));
            if (!$xf) throw new RuntimeException('فشل تسجيل الدخول عبر XenForo API.');
            $_SESSION['user'] = $xf;
            header('Location: /drive');
            exit;
        }

        require_login();
        if (!$pdo) throw new RuntimeException('قاعدة البيانات غير متاحة حالياً.');
        $user = $_SESSION['user'];
        $redirect = $_POST['redirect'] ?? '/drive';

        if ($action === 'create_folder') {
            $name = trim((string)($_POST['folder_name'] ?? ''));
            if ($name === '') throw new RuntimeException('اكتب اسم المجلد.');
            $parent = $_POST['folder_id'] ?? null;
            $parentId = ($parent === '' || $parent === null) ? null : (int)$parent;
            $st = $pdo->prepare('INSERT INTO folders (user_id,name,parent_id) VALUES (?,?,?)');
            $st->execute([$user['id'], $name, $parentId]);
        }

        if ($action === 'upload') {
            if (empty($_FILES['file']['name'])) throw new RuntimeException('اختر ملفاً أولاً.');
            $upload = $_FILES['file'];
            if ($upload['error'] !== UPLOAD_ERR_OK) throw new RuntimeException('فشل الرفع.');
            if ($upload['size'] > $config['max_upload_size']) throw new RuntimeException('حجم الملف أكبر من المسموح.');
            $original = (string)$upload['name'];
            $ext = pathinfo($original, PATHINFO_EXTENSION);
            $stored = bin2hex(random_bytes(20)) . ($ext ? '.' . $ext : '');
            $dest = $config['upload_dir'] . '/' . $stored;
            if (!move_uploaded_file($upload['tmp_name'], $dest)) throw new RuntimeException('تعذر حفظ الملف.');
            $mime = mime_content_type($dest) ?: 'application/octet-stream';
            $folderRaw = $_POST['folder_id'] ?? null;
            $folderId = ($folderRaw === '' || $folderRaw === null) ? null : (int)$folderRaw;
            $st = $pdo->prepare('INSERT INTO files (user_id,user_name,folder_id,filename,stored_name,mime_type,size_bytes,relative_path) VALUES (?,?,?,?,?,?,?,?)');
            $st->execute([$user['id'], $user['name'], $folderId, $original, $stored, $mime, (int)$upload['size'], 'uploads/' . $stored]);
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
$pageTitle = 'ملفاتي';

if ($user && $route !== 'login' && $pdo) {
    $sum = $pdo->prepare('SELECT COALESCE(SUM(size_bytes),0) FROM files WHERE user_id=? AND is_trashed=0');
    $sum->execute([$user['id']]);
    $storage = (int)$sum->fetchColumn();

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
    if ($route === 'trash') $where .= ' AND is_trashed=1';
    else $where .= ' AND is_trashed=0';
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

    $map = ['drive'=>'ملفاتي','recent'=>'الأحدث','starred'=>'المميّز بنجمة','trash'=>'سلة المهملات','search'=>'نتائج البحث','folder'=>'المجلد'];
    $pageTitle = $map[$route] ?? 'ملفاتي';
}

?>
<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Safe Drive</title>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0" />
  <link rel="stylesheet" href="/public/assets/style.css" />
</head>
<body>
<?php if ($route === 'login'): ?>
<main class="login-wrap">
  <section class="login-card">
    <img src="/public/google-logo.png" class="logo" alt="logo" />
    <h1>سيف درايف</h1>
    <p>سجّل الدخول بحساب المنتدى</p>
    <form method="post" class="login-form">
      <input type="hidden" name="action" value="login" />
      <input name="username" placeholder="اسم المستخدم أو البريد" required />
      <input name="password" type="password" placeholder="كلمة المرور" required />
      <button type="submit">بدء الاستخدام</button>
    </form>
    <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>
  </section>
  <img src="/public/login.gif" class="hero" alt="login" />
</main>
<?php else: ?>
<header class="topbar">
  <div class="brand"><span class="material-symbols-outlined">menu</span><img src="/public/google-logo.png" alt="" /><span>Drive</span></div>
  <form class="search" method="get" action="/search">
    <span class="material-symbols-outlined">search</span>
    <input name="q" value="<?= htmlspecialchars($search) ?>" placeholder="ابحث في ملفاتك" />
  </form>
  <div class="profile"><span><?= htmlspecialchars($user['name']) ?></span><img src="<?= htmlspecialchars($user['avatar'] ?: '/public/myimg.png') ?>" alt="avatar" /><a href="/logout" class="logout">خروج</a></div>
</header>

<div class="layout">
  <aside class="sidebar">
    <form method="post" enctype="multipart/form-data" class="upload-box">
      <input type="hidden" name="action" value="upload" />
      <input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>" />
      <input type="hidden" name="folder_id" value="<?= $route==='folder'?(int)$currentFolderId:'' ?>" />
      <input type="file" name="file" required />
      <button type="submit">رفع ملف</button>
    </form>

    <form method="post" class="folder-create">
      <input type="hidden" name="action" value="create_folder" />
      <input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>" />
      <input type="hidden" name="folder_id" value="<?= $route==='folder'?(int)$currentFolderId:'' ?>" />
      <input name="folder_name" placeholder="اسم مجلد جديد" required />
      <button type="submit">إنشاء مجلد</button>
    </form>

    <nav>
      <a href="/drive" class="<?= $route==='drive'?'active':'' ?>"><span class="material-symbols-outlined">home</span> ملفاتي</a>
      <a href="/recent" class="<?= $route==='recent'?'active':'' ?>"><span class="material-symbols-outlined">history</span> الأحدث</a>
      <a href="/starred" class="<?= $route==='starred'?'active':'' ?>"><span class="material-symbols-outlined">star</span> المميّز بنجمة</a>
      <a href="/trash" class="<?= $route==='trash'?'active':'' ?>"><span class="material-symbols-outlined">delete</span> سلة المهملات</a>
    </nav>
    <div class="storage">المساحة المستخدمة: <?= format_bytes($storage) ?> / 5 GB</div>
  </aside>

  <main class="content">
    <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>
    <h2><?= htmlspecialchars($pageTitle) ?></h2>

    <?php if ($route === 'folder'): ?><a class="back" href="/drive">⬅ الرجوع إلى ملفاتي</a><?php endif; ?>

    <?php if (in_array($route, ['drive','folder'], true) && $folders): ?>
      <div class="folders-grid">
        <?php foreach ($folders as $fd): ?>
          <a href="/folders/<?= (int)$fd['id'] ?>" class="folder-card">
            <?php if (!empty($fd['preview_image'])): ?>
              <img src="/<?= htmlspecialchars($fd['preview_image']) ?>" alt="preview" />
            <?php else: ?>
              <div class="folder-placeholder"><span class="material-symbols-outlined">folder</span></div>
            <?php endif; ?>
            <strong><?= htmlspecialchars($fd['name']) ?></strong>
            <small><?= (int)$fd['items_count'] ?> عنصر</small>
          </a>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>

    <div class="table">
      <div class="row head"><div>الاسم</div><div>الحجم</div><div>آخر تعديل</div><div>الخيارات</div></div>
      <?php if (!$files): ?>
        <div class="empty">لا توجد ملفات.</div>
      <?php else: foreach ($files as $f): ?>
        <div class="row">
          <div class="name-cell">
            <form method="post" class="inline-form"><input type="hidden" name="action" value="toggle_star"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><button class="star <?= (int)$f['is_starred']?'on':'' ?>">★</button></form>
            <a href="<?= htmlspecialchars(file_url($f)) ?>" target="_blank">
              <?php if (str_starts_with((string)$f['mime_type'], 'image/')): ?><img src="<?= htmlspecialchars(file_url($f)) ?>" class="thumb-mini" alt="thumb"><?php else: ?><span class="material-symbols-outlined">description</span><?php endif; ?>
              <?= htmlspecialchars($f['filename']) ?>
            </a>
          </div>
          <div><?= format_bytes((int)$f['size_bytes']) ?></div>
          <div><?= htmlspecialchars($f['created_at']) ?></div>
          <div class="actions">
            <?php if ($route === 'trash'): ?>
              <form method="post" class="inline-form"><input type="hidden" name="action" value="restore"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><button>استعادة</button></form>
              <form method="post" class="inline-form"><input type="hidden" name="action" value="delete"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><button>حذف نهائي</button></form>
            <?php else: ?>
              <form method="post" class="inline-form"><input type="hidden" name="action" value="trash"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><button>إلى السلة</button></form>
              <form method="post" class="inline-form move-form"><input type="hidden" name="action" value="move_file"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"><input type="hidden" name="redirect" value="<?= htmlspecialchars($uri ?: '/drive') ?>"><select name="target_folder_id"><option value="">الجذر</option><?php foreach ($allFolders as $op): ?><option value="<?= (int)$op['id'] ?>" <?= ((int)$f['folder_id']===(int)$op['id'])?'selected':'' ?>><?= htmlspecialchars($op['name']) ?></option><?php endforeach; ?></select><button>نقل</button></form>
            <?php endif; ?>
          </div>
        </div>
      <?php endforeach; endif; ?>
    </div>
  </main>
</div>
<?php endif; ?>
</body>
</html>
