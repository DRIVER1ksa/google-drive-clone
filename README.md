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
- `/d/{id}/{filename}`

## الميزات
- واجهة RTL عربية بتخطيط قريب من المشروع الأصلي.
- زر **جديد** واحد مع قائمة (رفع ملف / إنشاء مجلد) ونوافذ منبثقة.
- إنشاء مجلدات + نقل الملفات بينها.
- صور مصغرة للصور داخل القائمة وبطاقات المجلدات.
- اسم المستخدم وصورته من XenForo بعد تسجيل الدخول.

## الإعداد السريع
1. استورد `schema.sql`.
2. عدّل `config.php`.
3. اجعل `uploads/` قابلًا للكتابة.
4. ضع إعداد Nginx من `nginx.conf.example`.


## إصلاح 404 لروابط الملفات `/d/.../*.png` على CloudPanel/Nginx
إذا كان لديك location للملفات الثابتة مثل:
`location ~* \.(css|js|png|...)$`
فهذا قد يلتقط رابط `/d/1/file.png` ويُرجع 404.

الحل: أضف هذا **قبل** location الملفات الثابتة في server 80/443:
```nginx
location ^~ /d/ {
    {{varnish_proxy_pass}}
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

وفي server الداخلي (8080) اجعل:
```nginx
location / {
    try_files $uri $uri/ /index.php?$query_string;
}
```
