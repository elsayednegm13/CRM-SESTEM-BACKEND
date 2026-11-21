# SECURITY-F06-TEAM-ROLE-ADMIN-UNBLOCK-01 — سجل المحاولات

## W0 / G1 / G2

- تطابقت HEADs الخمسة وبصمات CLAUDE وLeadService وconfig قبل التعديل وmanifest90 مع المرجع. لم يكن شيء staged، ولم تُلمس الموارد القديمة.
- أضيف سطر mapping واحد لـ A5 في `config/f06_actor_sql.php`. نجح `php -l`، وأثبت `config_preflight.php` أن A5 بلا اعتماد وactor المجهول يعيدان null، وأن A1 مستقل.
- اختيرت دالتا direct grant/revoke في `TenantStaffRoleMutationService` لمنح `leads.view:SELF` إلى A4. أبقيت صلاحيات A1/A2/A4/B1. أضيف A0 صناعي بلا LOGIN كمرساة invariant، وA5 RBAC محدود بلا `company.administer`.
- قرار G2: `G2_PASS_SOURCE_SCOPE` لهذا الزوج فقط قبل أي DB أو تعديل خدمة. الدالة ON مطالبة بهوية `session_user` والتحقق LIVE وmutation/version/audit الذرية. دالة `f06scope_effective_scopes` لا تُمثل member.manage غير القابل للنطاق بقيمة موجبة؛ فحصت الدالة الجديدة وجوده مستقلًا.

## G3 / G4 / G5

- أُنشئت حاوية PostgreSQL16 جديدة عند `127.0.0.1:55480`، system identifier `7700986034630172718`، SCRAM وprovision مرتين وmigrations 38/38 وfixtures صناعية. ورث A5 المجموعة الضيقة مع `SET FALSE` فقط.
- نجح G4 الموجب و11/11 سلبية مباشرة بـ`42501` وبصمة ثابتة.
- أول harness لـG5 نجح استدعاء الدالة ثم حاول قراءة عمود `id` غير الممنوح لـactor؛ أعاد `42501` وتراجعت المعاملة. هذا خطأ فحص لا فشل grant. بعد تصحيح القراءة نجح grant/revoke و6/6 سلبية داخل rollback وبصمة ثابتة.
- فشل توليد شهادة TLS عبر PHP CLI قبل كتابة شهادة. وُلّدت لاحقًا بـOpenSSL داخل الحاوية المملوكة ونُسخت إلى runtime خارجي؛ حُذفت النسخ المؤقتة داخل الحاوية.

## G6 / G7 وإعادة fixture

- أول HTTP OFF نجح grant 201/revoke 200 وversion/audit. فشلت إعادة fixture لأن تريغر grant يمنع DELETE؛ تراجعت المعاملة. أُعيدت صفوف هذه الجولة الصناعية فقط داخل معاملة إدارية على Sandbox المملوكة، مع تعطيل تريغري USER المحددين مؤقتًا ثم تفعيلهما وفحص البصمة الأصلية `d1ea25751eff723bc3c2bfe7f6dbd6a1`. صُحح harness.
- محاولة فحص audit الأولى استخدمت `created_at` بدل `occurred_at`؛ فشلت بعد OFF. أُعيدت fixture بالطريقة نفسها مع التحقق من البصمة والتريغرات، ثم صُحح الاستعلام.
- نجح OFF/ON بعد ذلك في المنح والسحب والسلبيات الأولى، وعادت البصمة. نجح G7 الحالي 31/31 SQL مع بصمة Leads ثابتة؛ كشف تحكمان عكسيان داخل rollback ضعف policy أو ACL وعادت السياسة والامتياز والبصمة.
- كشفت المراجعة الأخيرة نقص B1 وguest وCSRF وcross Host من G6. أُعيد تشغيل الحاوية المملوكة فقط بعد فحص هويتها. أعاد طلب guest الأول 405 لأن harness استخدم GET على route POST/DELETE؛ صُحح إلى GET staff بعد إعادة fixture إلى بصمتها. نجحت جولة OFF/ON النهائية: grant 201، duplicate grant 403، revoke 200، repeat revoke 403، B1 403، guest 401، CSRF missing 419، cross Host 401، وسلبيات الإدارة الأخرى 403 بلا mutation. غياب اعتماد A5 منع mutation مع HTTP 500؛ ظل A1 يقرأ Leads بـ200. عادت بصمة authority بين الوضعين وبعدهما.
- بعد فحص الاسم وlabel وsystem identifier، أُوقفت حاوية هذه الجولة وحدها؛ بقي volume/network، وأُوقفت خوادم Laravel/TLS المؤقتة.
- أضيف فحص مستقل لحقول audit وgrant provenance (actor/target/tenant/outcome/request_id/metadata/granted_by/revoked_by). نجحت إعادة G6 الكاملة OFF/ON والفحوص السلبية وفقدان اعتماد A5 واستقلال A1؛ عادت البصمة. أُوقفت الحاوية نفسها بعد مطابقة الهوية مرة أخرى.
