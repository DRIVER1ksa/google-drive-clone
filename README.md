# Safe Drive PHP Edition

نسخة PHP/MySQL مع تسجيل XenForo API.

## المتطلبات
- PHP 8.1+
- MySQL / phpMyAdmin
- `curl`, `pdo_mysql`
- خادم Nginx أو Apache

## الإعداد
1. أنشئ قاعدة بيانات `drive`.
2. استورد `schema.sql`.
3. عدّل `config.php` أو ENV (`DB_*`, `XF_*`).
4. ارفع الملفات.
5. تأكد أن `uploads/` قابلة للكتابة.

## Nginx (مهم)
استخدم إعدادات `nginx.conf.example` داخل server block لديك.

## ملاحظات
- الواجهة الآن تستخدم أيقونات المشروع الأصلية من `public/` (home/recent/starred/trash/google-logo/search).
- الروابط تعمل على Nginx بدون `.htaccess` لأن التطبيق يستخدم `file.php?id=...` بشكل مباشر.
- أسماء الملفات العربية محفوظة كما هي في العرض والتنزيل.
