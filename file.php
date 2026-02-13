<?php
session_start();
$config = require __DIR__ . '/config.php';

if (empty($_SESSION['user'])) {
    http_response_code(403);
    exit('Unauthorized');
}

$id = (int)($_GET['id'] ?? 0);
if ($id <= 0) {
    http_response_code(404);
    exit('Not found');
}

$dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s', $config['db']['host'], $config['db']['name'], $config['db']['charset']);
$pdo = new PDO($dsn, $config['db']['user'], $config['db']['pass'], [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

$stmt = $pdo->prepare('SELECT * FROM files WHERE id = ? AND user_id = ? LIMIT 1');
$stmt->execute([$id, $_SESSION['user']['id']]);
$file = $stmt->fetch();

if (!$file) {
    http_response_code(404);
    exit('Not found');
}

$absolute = __DIR__ . '/' . $file['relative_path'];
if (!is_file($absolute)) {
    http_response_code(404);
    exit('Missing file');
}

$mime = $file['mime_type'] ?: 'application/octet-stream';
$size = filesize($absolute);
$encodedName = rawurlencode($file['filename']);

header('Content-Type: ' . $mime);
header('Content-Length: ' . $size);
header('Content-Disposition: inline; filename*=UTF-8\'\'' . $encodedName);
header('X-Content-Type-Options: nosniff');

readfile($absolute);
