# Safe Drive PHP Edition

نسخة PHP + MySQL تعمل على Nginx وتدعم تسجيل XenForo.

## المسارات
- `/login`
- `/drive` (أو `/home`)
- `/recent`
- `/starred`
- `/trash`
- `/search?q=...`
- `/folders/{id}`
- `/d/{id}/{filename}` (ملف خاص بالمستخدم)
- `/s/{token}/{filename.ext}` (رابط مشاركة عام مختصر مع الامتداد)

## الميزات
- واجهة RTL عربية بتخطيط قريب من Google Drive.
- زر **+ جديد** مع قائمة: (تحميل ملف / تحميل مجلد / مجلد جديد).
- نوافذ منبثقة (Modal) لرفع الملفات والمجلدات وإنشاء المجلدات.
- شريط تقدم رفع + نسبة الرفع + سرعة الرفع (MB/s) أثناء التحميل.
- قائمة يمين (Right Click) للملفات/المجلدات: إعادة تسمية، نقل، حذف، مشاركة/إلغاء مشاركة، نسخ رابط المشاركة.
- سعة كل مستخدم: **1 TB**.
- الحد الأقصى للملف الواحد: **5 GB**.
- كارت تخزين جانبي مشابه Google Drive.

## الإعداد السريع
1. استورد `schema.sql`.
2. عدّل `config.php`.
3. اجعل `uploads/` قابلًا للكتابة.
4. ضع إعداد Nginx من `nginx.conf.example`.
5. تأكد أن PHP (`upload_max_filesize`, `post_max_size`) تسمح بـ 5GB أو أعلى.

## إصلاح 404 لروابط `/d/...` على CloudPanel/Nginx
ضع `location ^~ /d/` قبل location الملفات الثابتة regex.
