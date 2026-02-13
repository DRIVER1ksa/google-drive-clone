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

function xf_auth(array $config, string $login, string $password): ?array {
    $endpoint = $config['xf']['base_url'] . '/api/auth';
    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POSTFIELDS => http_build_query(['login' => $login, 'password' => $password]),
        CURLOPT_HTTPHEADER => ['XF-Api-Key: ' . $config['xf']['api_key']],
        CURLOPT_TIMEOUT => 20,
    ]);
    $response = curl_exec($ch);
    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if (!$response || $http >= 400) return null;
    $decoded = json_decode($response, true);
    if (!empty($decoded['success']) && !empty($decoded['user'])) return $decoded['user'];
    return null;
}

function require_login(): void {
    if (empty($_SESSION['user'])) {
        header('Location: /?page=login');
        exit;
    }
}

function format_bytes(int $bytes): string {
    $units = ['B','KB','MB','GB','TB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($units)-1) { $bytes /= 1024; $i++; }
    return round($bytes, 2) . ' ' . $units[$i];
}

$flash = null;

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: /?page=login');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    try {
        if ($action === 'login') {
            $u = trim($_POST['username'] ?? '');
            $p = (string)($_POST['password'] ?? '');
            $xfUser = xf_auth($config, $u, $p);
            if (!$xfUser) throw new RuntimeException('فشل تسجيل الدخول عبر XenForo API.');
            $_SESSION['user'] = [
                'id' => (string)($xfUser['user_id'] ?? $xfUser['id'] ?? $u),
                'name' => $xfUser['username'] ?? $u,
            ];
            header('Location: /?page=home');
            exit;
        }

        require_login();
        $pdo = db($config);
        $user = $_SESSION['user'];

        if ($action === 'upload') {
            if (empty($_FILES['file']['name'])) throw new RuntimeException('اختر ملفاً للرفع أولاً.');
            $f = $_FILES['file'];
            if ($f['error'] !== UPLOAD_ERR_OK) throw new RuntimeException('فشل رفع الملف.');
            if ($f['size'] > $config['max_upload_size']) throw new RuntimeException('حجم الملف أكبر من الحد المسموح.');

            $stored = bin2hex(random_bytes(16)) . '-' . preg_replace('/[^A-Za-z0-9._-]/', '_', basename($f['name']));
            $dest = $config['upload_dir'] . '/' . $stored;
            if (!move_uploaded_file($f['tmp_name'], $dest)) throw new RuntimeException('تعذر حفظ الملف.');
            $mime = mime_content_type($dest) ?: 'application/octet-stream';

            $st = $pdo->prepare('INSERT INTO files (user_id,user_name,filename,stored_name,mime_type,size_bytes,relative_path) VALUES (?,?,?,?,?,?,?)');
            $st->execute([$user['id'], $user['name'], $f['name'], $stored, $mime, $f['size'], 'uploads/' . $stored]);
            $flash = ['type'=>'success','msg'=>'تم رفع الملف بنجاح'];
        }

        if (in_array($action, ['toggle_star','trash','restore','delete'], true)) {
            $id = (int)($_POST['id'] ?? 0);
            if ($action === 'toggle_star') {
                $st = $pdo->prepare('UPDATE files SET is_starred = 1 - is_starred WHERE id = ? AND user_id = ?');
                $st->execute([$id, $user['id']]);
            } elseif ($action === 'trash') {
                $st = $pdo->prepare('UPDATE files SET is_trashed = 1 WHERE id = ? AND user_id = ?');
                $st->execute([$id, $user['id']]);
            } elseif ($action === 'restore') {
                $st = $pdo->prepare('UPDATE files SET is_trashed = 0 WHERE id = ? AND user_id = ?');
                $st->execute([$id, $user['id']]);
            } else {
                $q = $pdo->prepare('SELECT relative_path FROM files WHERE id = ? AND user_id = ?');
                $q->execute([$id, $user['id']]);
                $row = $q->fetch();
                if ($row && is_file(__DIR__ . '/' . $row['relative_path'])) unlink(__DIR__ . '/' . $row['relative_path']);
                $st = $pdo->prepare('DELETE FROM files WHERE id = ? AND user_id = ?');
                $st->execute([$id, $user['id']]);
            }
            $flash = ['type'=>'success','msg'=>'تم تنفيذ العملية'];
        }
    } catch (Throwable $e) {
        $flash = ['type'=>'error','msg'=>$e->getMessage()];
    }
}

$page = $_GET['page'] ?? (empty($_SESSION['user']) ? 'login' : 'home');
$user = $_SESSION['user'] ?? null;
$files = [];
$storage = 0;
if ($user && $page !== 'login') {
    $pdo = db($config);
    $where = 'user_id = :uid';
    if ($page === 'home') $where .= ' AND is_trashed = 0';
    if ($page === 'recent') $where .= ' AND is_trashed = 0';
    if ($page === 'starred') $where .= ' AND is_trashed = 0 AND is_starred = 1';
    if ($page === 'trash') $where .= ' AND is_trashed = 1';
    if ($page === 'search') {
        $where .= ' AND is_trashed = 0 AND filename LIKE :search';
    }
    $sql = "SELECT * FROM files WHERE $where ORDER BY created_at DESC";
    $st = $pdo->prepare($sql);
    $st->bindValue(':uid', $user['id']);
    if ($page === 'search') $st->bindValue(':search', '%' . ($_GET['q'] ?? '') . '%');
    $st->execute();
    $files = $st->fetchAll();

    $sum = $pdo->prepare('SELECT COALESCE(SUM(size_bytes),0) FROM files WHERE user_id = ? AND is_trashed = 0');
    $sum->execute([$user['id']]);
    $storage = (int)$sum->fetchColumn();
}
?>
<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Safe Drive PHP</title>
  <link rel="stylesheet" href="/public/assets/style.css" />
</head>
<body>
<?php if ($page === 'login'): ?>
  <main class="login-wrap">
    <section class="login-card">
      <img src="/public/drive.svg" class="logo" alt="logo"/>
      <h1>Safe Drive</h1>
      <p>تسجيل دخول عبر XenForo API</p>
      <form method="post" class="login-form">
        <input type="hidden" name="action" value="login"/>
        <input name="username" placeholder="اسم المستخدم" required/>
        <input name="password" type="password" placeholder="كلمة المرور" required/>
        <button type="submit">تسجيل الدخول</button>
      </form>
      <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>
    </section>
    <img src="/public/login.gif" class="hero" alt="hero"/>
  </main>
<?php else: ?>
<header class="topbar">
  <div class="brand"><img src="/public/drive.svg" alt=""/><strong>Safe Drive</strong></div>
  <form class="search" method="get">
    <input type="hidden" name="page" value="search"/>
    <input name="q" placeholder="ابحث في ملفاتك..." value="<?= htmlspecialchars($_GET['q'] ?? '') ?>"/>
  </form>
  <a class="logout" href="/?logout=1">خروج</a>
</header>
<div class="app">
  <aside class="sidebar">
    <form method="post" enctype="multipart/form-data" class="upload-box">
      <input type="hidden" name="action" value="upload"/>
      <input type="file" name="file" required/>
      <button>رفع ملف</button>
    </form>
    <nav>
      <a href="/?page=home" class="<?= $page==='home'?'active':'' ?>">ملفاتي</a>
      <a href="/?page=recent" class="<?= $page==='recent'?'active':'' ?>">الأحدث</a>
      <a href="/?page=starred" class="<?= $page==='starred'?'active':'' ?>">المميزة</a>
      <a href="/?page=trash" class="<?= $page==='trash'?'active':'' ?>">سلة المحذوفات</a>
    </nav>
    <div class="storage">المساحة المستخدمة: <?= format_bytes($storage) ?> / 5 GB</div>
  </aside>
  <main class="content">
    <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>
    <h2>
      <?php
      echo match($page){
        'home'=>'My Drive', 'recent'=>'Recent', 'starred'=>'Starred', 'trash'=>'Trash', 'search'=>'نتائج البحث', default=>'My Drive'
      };
      ?>
    </h2>
    <div class="grid">
      <?php if (!$files): ?>
        <div class="empty">لا توجد ملفات حالياً.</div>
      <?php else: foreach ($files as $f): ?>
      <article class="card">
        <a href="/<?= htmlspecialchars($f['relative_path']) ?>" target="_blank" class="file-link">
          <img src="/public/recent.svg" alt=""/>
          <strong title="<?= htmlspecialchars($f['filename']) ?>"><?= htmlspecialchars($f['filename']) ?></strong>
          <small><?= format_bytes((int)$f['size_bytes']) ?></small>
          <small><?= htmlspecialchars($f['created_at']) ?></small>
        </a>
        <div class="actions">
          <form method="post"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"/><input type="hidden" name="action" value="toggle_star"/><button>⭐</button></form>
          <?php if ($page === 'trash'): ?>
            <form method="post"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"/><input type="hidden" name="action" value="restore"/><button>استعادة</button></form>
            <form method="post"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"/><input type="hidden" name="action" value="delete"/><button>حذف نهائي</button></form>
          <?php else: ?>
            <form method="post"><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"/><input type="hidden" name="action" value="trash"/><button>🗑</button></form>
          <?php endif; ?>
        </div>
      </article>
      <?php endforeach; endif; ?>
    </div>
  </main>
</div>
<?php endif; ?>
</body>
</html>
