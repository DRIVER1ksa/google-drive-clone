<?php
return [
  'db' => [
    'host' => getenv('DB_HOST') ?: '127.0.0.1',
    'name' => getenv('DB_NAME') ?: 'drive',
    'user' => getenv('DB_USER') ?: 'drive',
    'pass' => getenv('DB_PASS') ?: 'peCH29Dnfqcjuqy6jRgB',
    'charset' => 'utf8mb4',
  ],
  'xf' => [
    'base_url' => rtrim(getenv('XF_BASE_URL') ?: 'https://gamezone.to', '/'),
    'api_key' => getenv('XF_API_KEY') ?: 'C9dRzxibqXuQ61RYQUJwzKEh6VkjY9PR',
  ],
  'upload_dir' => __DIR__ . '/uploads',
  'max_upload_size' => 5 * 1024 * 1024 * 1024,
  'admin_user_ids' => array_values(array_filter(array_map('trim', explode(',', getenv('ADMIN_USER_IDS') ?: '1')))),
];
