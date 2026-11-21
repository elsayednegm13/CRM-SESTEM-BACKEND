# سجل محاولات SECURITY-F06-API-ADMIN-COMPACT-01

- W0: HEADs الخمسة وبصمات المصدر مطابقة؛ نقطة A5 الخارجية manifest وpayload `122/122` سليمة. موارد الجولات السابقة متوقفة ولم تُلمس. PHP CLI يحوي `pdo_pgsql/curl/openssl` وDocker Server متاح، مع عدم إنشاء Sandbox بعد.
- G1: قُفلت مصفوفة العقد والـallowlist. G4-D مشروطة بقرار provisioning لأن عضوًا جديدًا لا يملك mapping Actor SQL تحت ON. لا تشغيل SQL أو HTTP حتى الآن.
- G2a: تعديل 5 ملفات مصدر ضمن القائمة وقاعدة تصنيف typed؛ نجح `php -l` 6/6، وفاحص المصدر، و`git diff --check`.
- G3: حاوية جديدة `daleel-f06-compact01-44e1ef49-pg` على `127.0.0.1:55481`، system ID `7701014410365292590`، SCRAM ورفض كلمة خاطئة، migrations `38/38`، fixtures، ثم SQL scope `31/31` مع بصمة Leads ثابتة.
- G2b محاولة مرفوضة قبل HTTP: فشل استعلام البصمة لأن harness استخدم اسمَي جدولين غير موجودين `tenant_staff_roles/tenant_staff_role_permissions`. صُحح إلى `roles/role_permissions` قبل إرسال الطلب؛ لا mutation.
- G2b: HTTPS حقيقي أعاد `503/ACTOR_SQL_UNAVAILABLE` لـ E1 A5 وE2 A4 وE4 direct function مع بصمة authority+Leads ثابتة واستجابة عامة وفاحص تسرب. أنشئت نسخة DB `daleel_f06compact01_e4clone` داخل نفس الحاوية؛ غياب assign function أعاد 503، ثم حُوّل mapping A5 فيها إلى role مجهول فأعاد 503. بقيت القاعدة الأصلية بعقودها.
- حادث بيئي: توقف Docker Desktop بعد اختبارات G2b؛ فشل `deploy_050.py` قبل الوصول إلى DB. أُعيد تشغيل Docker Desktop ثم الحاوية المملوكة فقط؛ تحقق system ID و38 migrations وغياب 050 قبل نشرها. لم تُلمس حاويات الجولات الأخرى.
- G2b/G4-A محاولة HTTP مرفوضة: مهلة startup 10 ثوانٍ انتهت قبل جاهزية Laravel؛ أوقفت عمليتَي PHP/TLS المملوكتين، وزيدت مهلة الجاهزية. محاولة ثانية وصلت GET roles تحت OFF لكن فاحص body افترض `data` قائمة، والعقد الفعلي `data.roles`؛ صُحح الفاحص. لم تتغير بصمة authority.
- G4-A: نشر overlay 050 في الحاوية المملوكة. HTTP OFF/ON للـGET roles/staff والمنح/السحب الضيق والرفض والضيف/CSRF/Host؛ 38 حالة مسجلة مع نجاح مستقل A1 وقت غياب اعتماد A5، ثم استعادة بصمة grant/membership/audit. دالة 050 Sandbox فقط.
- G5: `g5_sql_gate.py` إيجابي grant/revoke تحت rollback و6/6 رفض SQLSTATE 42501؛ `negative_mutation_gate.py` كشف تسرب الصف بعد حذف policy وتكوين grant بعد ACL mutation، واستعاد policy/ACL داخل rollback. `final_catalog.py` أثبت بصمة authority+Leads النهائية مطابقة للبداية، 9 policies و3 triggers مفعلة وSET FALSE لكل Actor وغياب DML مباشر على جداول authority.
- G5 إعادة التحقق بعد negative mutations: شُغلت الحاوية المملوكة بعد فحص label/port؛ تحقق system ID، ثم أعيد `sql_scope_gate.py` بنتيجة 31/31 و`g5_sql_gate.py` بنتيجة 6/6 و`final_catalog.py` ببصمة مستعادة. أُوقفت الحاوية مجددًا؛ لم تُحذف الشبكة أو volume.
- G4-B/C/D: لم تبدأ؛ تتطلب دوال SQL جديدة ذات عقود مستقلة للـroles وmembership lifecycle، وD يحتاج provisioning للـActor الجديد. حُفظ حد التنفيذ الجزئي المصرح بدل توسيع سلطة خدمة عامة.
