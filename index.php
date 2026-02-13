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
    $ch = curl_init($config['xf']['base_url'] . '/api/auth');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POSTFIELDS => http_build_query(['login' => $login, 'password' => $password]),
        CURLOPT_HTTPHEADER => ['XF-Api-Key: ' . $config['xf']['api_key']],
        CURLOPT_TIMEOUT => 20,
    ]);
    $response = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if (!$response || $code >= 400) return null;
    $decoded = json_decode($response, true);
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
        header('Location: /?page=login');
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

function file_url(array $file): string {
    return '/file.php?id=' . (int)$file['id'] . '&name=' . rawurlencode((string)$file['filename']);
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
            $xf = xf_auth($config, trim($_POST['username'] ?? ''), (string)($_POST['password'] ?? ''));
            if (!$xf) throw new RuntimeException('Login failed via XenForo API.');
            $_SESSION['user'] = $xf;
            header('Location: /?page=home');
            exit;
        }

        require_login();
        $pdo = db($config);
        $user = $_SESSION['user'];

        if ($action === 'upload') {
            if (empty($_FILES['file']['name'])) throw new RuntimeException('Please select a file first.');
            $upload = $_FILES['file'];
            if ($upload['error'] !== UPLOAD_ERR_OK) throw new RuntimeException('Upload failed.');
            if ($upload['size'] > $config['max_upload_size']) throw new RuntimeException('File exceeds max allowed size.');

            $original = (string)$upload['name'];
            $ext = pathinfo($original, PATHINFO_EXTENSION);
            $stored = bin2hex(random_bytes(20)) . ($ext ? '.' . $ext : '');
            $dest = $config['upload_dir'] . '/' . $stored;
            if (!move_uploaded_file($upload['tmp_name'], $dest)) throw new RuntimeException('Could not save uploaded file.');

            $mime = mime_content_type($dest) ?: 'application/octet-stream';
            $st = $pdo->prepare('INSERT INTO files (user_id,user_name,filename,stored_name,mime_type,size_bytes,relative_path) VALUES (?,?,?,?,?,?,?)');
            $st->execute([$user['id'], $user['name'], $original, $stored, $mime, (int)$upload['size'], 'uploads/' . $stored]);
            $flash = ['type' => 'success', 'msg' => 'File uploaded successfully.'];
        }

        if (in_array($action, ['toggle_star', 'trash', 'restore', 'delete'], true)) {
            $id = (int)($_POST['id'] ?? 0);
            if ($action === 'toggle_star') {
                $st = $pdo->prepare('UPDATE files SET is_starred = 1-is_starred WHERE id=? AND user_id=?');
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
            $flash = ['type' => 'success', 'msg' => 'Action completed.'];
        }
    } catch (Throwable $e) {
        $flash = ['type' => 'error', 'msg' => $e->getMessage()];
    }
}

$page = $_GET['page'] ?? (empty($_SESSION['user']) ? 'login' : 'home');
$user = $_SESSION['user'] ?? null;
$files = [];
$storage = 0;

if ($user && $page !== 'login') {
    $pdo = db($config);
    $where = 'user_id=:uid';
    if (in_array($page, ['home', 'recent'], true)) $where .= ' AND is_trashed=0';
    if ($page === 'starred') $where .= ' AND is_trashed=0 AND is_starred=1';
    if ($page === 'trash') $where .= ' AND is_trashed=1';
    if ($page === 'search') $where .= ' AND is_trashed=0 AND filename LIKE :search';

    $st = $pdo->prepare("SELECT * FROM files WHERE $where ORDER BY created_at DESC");
    $st->bindValue(':uid', $user['id']);
    if ($page === 'search') $st->bindValue(':search', '%' . ($_GET['q'] ?? '') . '%');
    $st->execute();
    $files = $st->fetchAll();

    $sum = $pdo->prepare('SELECT COALESCE(SUM(size_bytes),0) FROM files WHERE user_id=? AND is_trashed=0');
    $sum->execute([$user['id']]);
    $storage = (int)$sum->fetchColumn();
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Safe Drive</title>
  <link rel="stylesheet" href="/public/assets/style.css" />
</head>
<body>
<?php if ($page === 'login'): ?>
<main class="login-wrap">
  <section class="login-card">
    <img src="/public/google-logo.png" class="logo" alt="Drive" />
    <h1>Safe Drive</h1>
    <p>Sign in with your XenForo account</p>
    <form method="post" class="login-form">
      <input type="hidden" name="action" value="login" />
      <input name="username" placeholder="Username / Email" required />
      <input name="password" type="password" placeholder="Password" required />
      <button type="submit">Get Started</button>
    </form>
    <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>
  </section>
  <img src="/public/login.gif" class="hero" alt="Login" />
</main>
<?php else: ?>
<header class="topbar">
  <div class="brand">
    <span class="menu">☰</span>
    <img src="/public/google-logo.png" alt="Drive" />
    <span>Drive</span>
  </div>
  <form class="search" method="get">
    <input type="hidden" name="page" value="search" />
    <img src="/public/search.svg" alt="search" />
    <input name="q" placeholder="Search in Drive" value="<?= htmlspecialchars($_GET['q'] ?? '') ?>" />
  </form>
  <div class="profile">
    <span class="username"><?= htmlspecialchars($user['name']) ?></span>
    <img src="<?= htmlspecialchars($user['avatar'] ?: '/public/myimg.png') ?>" alt="avatar" />
    <a href="/?logout=1" class="logout">Logout</a>
  </div>
</header>

<div class="layout">
  <aside class="sidebar">
    <form method="post" enctype="multipart/form-data" class="upload-box">
      <input type="hidden" name="action" value="upload" />
      <input type="file" name="file" required />
      <button>+ New Upload</button>
    </form>

    <nav>
      <a href="/?page=home" class="<?= $page==='home'?'active':'' ?>"><img src="/public/home.svg" alt="" />My Drive</a>
      <a href="/?page=recent" class="<?= $page==='recent'?'active':'' ?>"><img src="/public/recent.svg" alt="" />Recent</a>
      <a href="/?page=starred" class="<?= $page==='starred'?'active':'' ?>"><img src="/public/starred.svg" alt="" />Starred</a>
      <a href="/?page=trash" class="<?= $page==='trash'?'active':'' ?>"><img src="/public/trash.svg" alt="" />Trash</a>
    </nav>

    <div class="storage">Storage: <?= format_bytes($storage) ?> / 5 GB</div>
  </aside>

  <main class="content">
    <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>
    <h2>My Drive</h2>

    <div class="thumbs">
      <?php foreach (array_slice($files, 0, 4) as $f): ?>
        <a href="<?= htmlspecialchars(file_url($f)) ?>" class="thumb" target="_blank">
          <img src="/public/recent.svg" alt="file" />
          <span><?= htmlspecialchars($f['filename']) ?></span>
        </a>
      <?php endforeach; ?>
    </div>

    <div class="table">
      <div class="row head"><div>Name</div><div>File Size</div><div>Last Modified</div><div>Options</div></div>
      <?php if (!$files): ?>
        <div class="empty">No files found.</div>
      <?php else: foreach ($files as $f): ?>
        <div class="row">
          <div class="name-cell">
            <form method="post" class="inline-form"><input type="hidden" name="action" value="toggle_star"/><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"/><button class="star <?= (int)$f['is_starred']?'on':'' ?>">★</button></form>
            <a href="<?= htmlspecialchars(file_url($f)) ?>" target="_blank"><?= htmlspecialchars($f['filename']) ?></a>
          </div>
          <div><?= format_bytes((int)$f['size_bytes']) ?></div>
          <div><?= htmlspecialchars($f['created_at']) ?></div>
          <div class="actions">
            <?php if ($page === 'trash'): ?>
              <form method="post" class="inline-form"><input type="hidden" name="action" value="restore"/><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"/><button>Restore</button></form>
              <form method="post" class="inline-form"><input type="hidden" name="action" value="delete"/><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"/><button>Delete</button></form>
            <?php else: ?>
              <form method="post" class="inline-form"><input type="hidden" name="action" value="trash"/><input type="hidden" name="id" value="<?= (int)$f['id'] ?>"/><button>Move to trash</button></form>
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
