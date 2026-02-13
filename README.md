# Safe Drive PHP Edition

نسخة PHP + MySQL مع تسجيل XenForo API ودعم RTL عربي.

## المتطلبات
- PHP 8.1+
- MySQL / phpMyAdmin
- curl + pdo_mysql
- Nginx أو Apache

## الإعداد
1. أنشئ قاعدة البيانات `drive`.
2. استورد `schema.sql`.
3. عدّل `config.php` (أو ENV).
4. ارفع الملفات مع صلاحية كتابة لمجلد `uploads/`.
5. في Nginx استخدم `nginx.conf.example`.

## المسارات
- `/login` تسجيل الدخول
- `/drive` الملف الرئيسي
- `/recent` الأحدث
- `/starred` المميزة
- `/trash` المحذوفات
- `/folders/{id}` فتح مجلد
- `/d/{id}/{filename}` رابط الملف (بدون `file.php`)

## الميزات الحالية
- واجهة عربية RTL.
- اسم المستخدم + الصورة بعد تسجيل XenForo.
- إنشاء مجلدات.
- نقل الملفات بين المجلدات.
- عرض Thumbnail للصور داخل قائمة الملفات.
- عرض Thumbnail للمجلد عند توفر صورة داخله.
