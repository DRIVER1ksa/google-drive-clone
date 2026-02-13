<?php
session_start();
$config = require __DIR__ . '/config.php';

if (!is_dir($config['upload_dir'])) {
    mkdir($config['upload_dir'], 0775, true);
}

function db(array $config): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=%s',
        $config['db']['host'],
        $config['db']['name'],
        $config['db']['charset']
    );

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
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if (!$response || $httpCode >= 400) {
        return null;
    }

    $decoded = json_decode($response, true);
    if (empty($decoded['success']) || empty($decoded['user'])) {
        return null;
    }

    $user = $decoded['user'];
    $avatar = $user['avatar_urls']['o'] ?? $user['avatar_urls']['h'] ?? $user['avatar_urls']['l'] ?? null;

    return [
        'id' => (string)($user['user_id'] ?? $user['id'] ?? $login),
        'name' => $user['username'] ?? $login,
        'avatar' => $avatar,
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
    $index = 0;
    while ($bytes >= 1024 && $index < count($units) - 1) {
        $bytes /= 1024;
        $index++;
    }
    return round($bytes, 2) . ' ' . $units[$index];
}

function file_url(array $file): string {
    return '/d/' . (int)$file['id'] . '/' . rawurlencode($file['filename']);
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
            $username = trim($_POST['username'] ?? '');
            $password = (string)($_POST['password'] ?? '');
            $xfUser = xf_auth($config, $username, $password);

            if (!$xfUser) {
                throw new RuntimeException('Login failed via XenForo API.');
            }

            $_SESSION['user'] = $xfUser;
            header('Location: /?page=home');
            exit;
        }

        require_login();
        $pdo = db($config);
        $user = $_SESSION['user'];

        if ($action === 'upload') {
            if (empty($_FILES['file']['name'])) {
                throw new RuntimeException('Please select a file first.');
            }

            $upload = $_FILES['file'];
            if ($upload['error'] !== UPLOAD_ERR_OK) {
                throw new RuntimeException('Upload failed.');
            }
            if ($upload['size'] > $config['max_upload_size']) {
                throw new RuntimeException('File exceeds max allowed size.');
            }

            $original = (string)$upload['name'];
            $ext = pathinfo($original, PATHINFO_EXTENSION);
            $storedName = bin2hex(random_bytes(20)) . ($ext ? '.' . $ext : '');
            $destination = $config['upload_dir'] . '/' . $storedName;

            if (!move_uploaded_file($upload['tmp_name'], $destination)) {
                throw new RuntimeException('Could not save uploaded file.');
            }

            $mimeType = mime_content_type($destination) ?: 'application/octet-stream';

            $stmt = $pdo->prepare('INSERT INTO files (user_id, user_name, filename, stored_name, mime_type, size_bytes, relative_path) VALUES (?, ?, ?, ?, ?, ?, ?)');
            $stmt->execute([
                $user['id'],
                $user['name'],
                $original,
                $storedName,
                $mimeType,
                (int)$upload['size'],
                'uploads/' . $storedName,
            ]);

            $flash = ['type' => 'success', 'msg' => 'File uploaded successfully.'];
        }

        if (in_array($action, ['toggle_star', 'trash', 'restore', 'delete'], true)) {
            $id = (int)($_POST['id'] ?? 0);

            if ($action === 'toggle_star') {
                $stmt = $pdo->prepare('UPDATE files SET is_starred = 1 - is_starred WHERE id = ? AND user_id = ?');
                $stmt->execute([$id, $user['id']]);
            } elseif ($action === 'trash') {
                $stmt = $pdo->prepare('UPDATE files SET is_trashed = 1 WHERE id = ? AND user_id = ?');
                $stmt->execute([$id, $user['id']]);
            } elseif ($action === 'restore') {
                $stmt = $pdo->prepare('UPDATE files SET is_trashed = 0 WHERE id = ? AND user_id = ?');
                $stmt->execute([$id, $user['id']]);
            } elseif ($action === 'delete') {
                $query = $pdo->prepare('SELECT relative_path FROM files WHERE id = ? AND user_id = ?');
                $query->execute([$id, $user['id']]);
                $row = $query->fetch();

                if ($row && is_file(__DIR__ . '/' . $row['relative_path'])) {
                    unlink(__DIR__ . '/' . $row['relative_path']);
                }

                $stmt = $pdo->prepare('DELETE FROM files WHERE id = ? AND user_id = ?');
                $stmt->execute([$id, $user['id']]);
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
$totalStorage = 0;

if ($user && $page !== 'login') {
    $pdo = db($config);

    $where = 'user_id = :uid';
    if ($page === 'home' || $page === 'recent') {
        $where .= ' AND is_trashed = 0';
    } elseif ($page === 'starred') {
        $where .= ' AND is_trashed = 0 AND is_starred = 1';
    } elseif ($page === 'trash') {
        $where .= ' AND is_trashed = 1';
    } elseif ($page === 'search') {
        $where .= ' AND is_trashed = 0 AND filename LIKE :search';
    }

    $sql = "SELECT * FROM files WHERE $where ORDER BY created_at DESC";
    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':uid', $user['id']);

    if ($page === 'search') {
        $stmt->bindValue(':search', '%' . ($_GET['q'] ?? '') . '%');
    }

    $stmt->execute();
    $files = $stmt->fetchAll();

    $sumStmt = $pdo->prepare('SELECT COALESCE(SUM(size_bytes), 0) FROM files WHERE user_id = ? AND is_trashed = 0');
    $sumStmt->execute([$user['id']]);
    $totalStorage = (int)$sumStmt->fetchColumn();
}

$pageTitle = match ($page) {
    'home' => 'My Drive',
    'recent' => 'Recent',
    'starred' => 'Starred',
    'trash' => 'Trash',
    'search' => 'Search Results',
    default => 'Safe Drive',
};
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
      <img src="/public/drive.svg" class="logo" alt="Drive" />
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
    <div class="left-head">
      <img src="/public/drive.svg" alt="Drive" />
      <span>Drive</span>
    </div>

    <form class="search" method="get">
      <input type="hidden" name="page" value="search" />
      <input name="q" placeholder="Search in Drive" value="<?= htmlspecialchars($_GET['q'] ?? '') ?>" />
      <button type="submit">⌕</button>
    </form>

    <div class="right-head">
      <a href="/?page=home" title="Home">⌂</a>
      <a href="/?logout=1" class="logout">Logout</a>
      <div class="profile" title="<?= htmlspecialchars($user['name']) ?>">
        <?php if (!empty($user['avatar'])): ?>
          <img src="<?= htmlspecialchars($user['avatar']) ?>" alt="avatar" />
        <?php else: ?>
          <img src="/public/myimg.png" alt="avatar" />
        <?php endif; ?>
        <span><?= htmlspecialchars($user['name']) ?></span>
      </div>
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
        <a href="/?page=home" class="<?= $page === 'home' ? 'active' : '' ?>">My Drive</a>
        <a href="/?page=recent" class="<?= $page === 'recent' ? 'active' : '' ?>">Recent</a>
        <a href="/?page=starred" class="<?= $page === 'starred' ? 'active' : '' ?>">Starred</a>
        <a href="/?page=trash" class="<?= $page === 'trash' ? 'active' : '' ?>">Trash</a>
      </nav>

      <div class="storage">Storage: <?= format_bytes($totalStorage) ?> / 5 GB</div>
    </aside>

    <main class="content">
      <?php if ($flash): ?><div class="flash <?= $flash['type'] ?>"><?= htmlspecialchars($flash['msg']) ?></div><?php endif; ?>

      <h2><?= htmlspecialchars($pageTitle) ?></h2>

      <div class="recent-grid">
        <?php foreach (array_slice($files, 0, 4) as $f): ?>
          <a href="<?= htmlspecialchars(file_url($f)) ?>" class="thumb-card" target="_blank">
            <img src="/public/recent.svg" alt="file" />
            <span><?= htmlspecialchars($f['filename']) ?></span>
          </a>
        <?php endforeach; ?>
      </div>

      <div class="table-wrap">
        <div class="table-head row">
          <div>Name</div>
          <div>File Size</div>
          <div>Last Modified</div>
          <div>Options</div>
        </div>

        <?php if (!$files): ?>
          <div class="empty">No files found.</div>
        <?php else: ?>
          <?php foreach ($files as $f): ?>
            <div class="row">
              <div class="name-cell">
                <form method="post" class="inline-form">
                  <input type="hidden" name="action" value="toggle_star" />
                  <input type="hidden" name="id" value="<?= (int)$f['id'] ?>" />
                  <button class="icon-btn <?= (int)$f['is_starred'] ? 'starred' : '' ?>">★</button>
                </form>
                <a href="<?= htmlspecialchars(file_url($f)) ?>" target="_blank"><?= htmlspecialchars($f['filename']) ?></a>
              </div>

              <div><?= format_bytes((int)$f['size_bytes']) ?></div>
              <div><?= htmlspecialchars($f['created_at']) ?></div>

              <div class="actions">
                <?php if ($page === 'trash'): ?>
                  <form method="post" class="inline-form"><input type="hidden" name="action" value="restore" /><input type="hidden" name="id" value="<?= (int)$f['id'] ?>" /><button>Restore</button></form>
                  <form method="post" class="inline-form"><input type="hidden" name="action" value="delete" /><input type="hidden" name="id" value="<?= (int)$f['id'] ?>" /><button>Delete</button></form>
                <?php else: ?>
                  <form method="post" class="inline-form"><input type="hidden" name="action" value="trash" /><input type="hidden" name="id" value="<?= (int)$f['id'] ?>" /><button>Move to trash</button></form>
                <?php endif; ?>
              </div>
            </div>
          <?php endforeach; ?>
        <?php endif; ?>
      </div>
    </main>
  </div>
<?php endif; ?>
</body>
</html>
