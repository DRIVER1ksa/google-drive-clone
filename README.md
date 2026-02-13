# Safe Drive PHP Edition

تم تحويل المشروع إلى نسخة PHP + MySQL مع واجهة مطابقة لفكرة Google Drive Clone وتسجيل دخول عبر XenForo API.

## المتطلبات
- PHP 8.1+
- MySQL / phpMyAdmin (CloudPanel)
- امتداد cURL و PDO_MYSQL

## الإعداد السريع
1. أنشئ قاعدة بيانات باسم `drive`.
2. نفذ ملف `schema.sql` داخل phpMyAdmin.
3. عدّل بيانات الاتصال في `config.php` (أو عبر متغيرات البيئة).
4. ارفع كل الملفات إلى موقعك.
5. تأكد من صلاحية الكتابة على مجلد `uploads/`.

## التشغيل المحلي
```bash
php -S 0.0.0.0:8000
```
ثم افتح:
`http://localhost:8000/?page=login`

## الميزات
- تسجيل دخول XenForo API.
- رفع الملفات.
- عرض الملفات (My Drive / Recent / Starred / Trash / Search).
- نقل إلى سلة المهملات، استعادة، حذف نهائي.
- تخزين كل بيانات الملفات في MySQL.
