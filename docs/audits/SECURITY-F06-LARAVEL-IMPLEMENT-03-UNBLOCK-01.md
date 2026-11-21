<div dir="rtl">

# SECURITY-F06-LARAVEL-IMPLEMENT-03-UNBLOCK-01 — سجل تنفيذ

**الصفة:** Backend/PostgreSQL/Security/QA مع مراجعة أثر DevOps. **التاريخ المحلي:** 2026-10-26. هذا سجل الجولة الجديدة؛ تقرير توقف IMPLEMENT-03 السابق باقٍ دون تعديل.

## W0

- الفروع وHEADs الخمسة مطابقة للتكليف: ROOT `c2ee5a3a3e128f86147e06d39cd50ca7ff2cf7d9`، API `e8cee07c2c39df5a1531cbd63168695347202371`، WEB `6fb01b8838de52de621dab4691a5cdd5710c29f6`، ADMIN `9fa43befadaaa5d4583f8de6bf7a06c60e891bef`، SUPER `a802e44b8a269071bcb46fcaa675aafb43b12a87`. لا staged. WEB/ADMIN/SUPER نظيفة. في API ثلاثة ملفات tracked M مسبقة و61 ملفًا غير متتبعًا بينها تقرير التوقف؛ كلها محفوظة كحالة قبل الجولة.
- ROOT فيه أربعة tracked M: الثلاثة المتوقعة و`CLAUDE.md`. أكد المالك صراحةً أن الفرق في `CLAUDE.md` مقصود ومن عمله؛ فُحص الفرق قراءةً فقط فوجدت إضافة إرشادات العمل العامة دون تغيير حدود الحماية. تصنيفه `OWNER_APPROVED_PRE_EXISTING_CHANGE`. بصمته قبل التنفيذ `a972f9ef6f3e9959bb86687d7ffa9eae096ce9d78c1d3d515cc66e2191e8487a`. لا تعديله أو Git write له.
- checkpoint المحددة: manifest SHA-256 `08f4a8b841330b97e626ff409d2a1ef2b99193d3ab70b179b29d8362630adb7d`، payload `25/25`، ملفات المصدر الحي `25/25` قبل إضافة A4. `000_provision_roles.sql` ‏`4c80758ae7ce2b7e5849196aa8f7ae90ecfa8b0e72da5df3d05030acb18db57f`، و`002_actor_sql_fixture.sql` ‏`33942af36e8eb734ed9558a2fc038991d6153632d9dc91ecd9b4771b9c9fea22`. لم تُلمس نقطة الاسترجاع. بصمة `config/f06_actor_sql.php` قبل الإضافة `59f9044e50c622cf6f67391b92bb6b12a48096b63b6e8071f15a6d4d669280a7`.
- فُحص Docker metadata والمنافذ قراءةً فقط لتجنب التصادم؛ لم تُستخدم حاوية قديمة. تعليمات الجذر وAPI وتقارير I01/I02/SETROLE وتقرير التوقف وcheckpoint قُرئت. الـ39 غير موجودة ولا تدخل الجولة.

## G0 — فك مانع A4

أُضيف **سطر مصدر واحد** فقط في `config/f06_actor_sql.php`: `daleel_f06i03_actor_a4 → env('F06_ACTOR_PW_A4')`. بقيت المفاتيح السابقة والعلم وallow_env وresolver دون تعديل. SHA بعد الإضافة `4212c1e811a3105a047836fda22d8cfb2d4f4aed9d54728e8e67fd9c9e5fb2c8`. أظهر diff مع preimage في checkpoint هذا السطر وحده. `php -l` للملف و`g0_preflight.php` نجح؛ preflight أعاد أربع حالات PASS: default OFF، اعتماد A4 مفقود يرد `null` ويرفضه `ActorConnectionFactory` قبل DB، متغير A4 الصناعي يربط الدور الصحيح، والدور غير المعروف يبقى دون اعتماد. لا اختبارات HTTP/DB في G0. قيد `APP_ENV=testing` قائم من `TenantStaffRequestContext::f06Enabled()`؛ هذا فحص مصدر لا إثبات runtime بعد.

## خطة التنفيذ قبل sandbox

1. بناء PostgreSQL 16 جديد بملكية I03 فقط وSCRAM من initdb، والتحقق من label/volume/network/system_identifier وHBA ومصادقة موجبة/سالبة قبل أي migration.
2. تشغيل provisioner I03 المشتق من I02 المصحح مع actor A4 بعضوية `ADMIN FALSE, INHERIT TRUE, SET FALSE`، ثم 38 migration على قاعدة I03 المحددة؛ إعادة اختبار provisioner حيث تسمح العقود.
3. إدخال بيانات A1/A2/B1/A3/A4 عبر provider operation وقيود العضوية، ثم سياسة `RESTRICTIVE TO` تضم A4 صراحة. فصل Leads بحسب `created_by_membership_id` و`assigned_membership_id`.
4. اختبار SQL موجب وسالب مع rc/SQLSTATE وبصمة before/after؛ ثم HTTP socket حقيقي تحت FLAG OFF/ON مع CSRF وHost والجلسة وLeadService وLD03؛ فحص التاريخية بعد إثبات عزلها.
5. تثبيت hashes ودلتا Git/الموارد، وقف موارد الجولة فقط، وقرار محدود لا يغلق F06.

عقد المصدر: `GET /api/v1/company/leads` عبر ResolveTenantHost → TenantStaffRequestContext → `auth:tenant_staff` → ValidateTenantStaffSession → LeadController/LeadService. `ASSIGNED` يعتمد `assigned_membership_id`، و`SELF` يعتمد `created_by_membership_id`، و`ALL_TENANT` نطاق الشركة؛ `assignLead` يتطلب `leads.manage=ALL_TENANT`. دور A4 المقترح مستقل واسمه 24 بايت دون حد PostgreSQL ‏63 بايت.

## G2 — صندوق الاختبار الفعلي

**VERIFIED_RUNTIME [E-G2]:** حاوية جديدة فقط `daleel-f06-laravel-i03-49ec7da0-pg` بعلامة `control=SECURITY-F06-LARAVEL-IMPLEMENT-03-UNBLOCK-01`، وشبكة `daleel-f06-laravel-i03-49ec7da0-net` وحجم `daleel_f06_laravel_i03_49ec7da0_pg_data`. PostgreSQL 16.15، قاعدة `daleel_f06i03`، ربط `127.0.0.1:55472` فقط؛ `system_identifier=7700716788417429547`. كل أسطر HBA الفعالة لـhost تستخدم `scram-sha-256`. اتصال بكلمة مرور خاطئة أعاد rc=2، والصحيحة نجح. أسرار الاختبار وملفات الجلسة والشهادات وسجل الخادم الخام في `C:\Users\NEGM\AppData\Local\Temp\f06-i03-49ec7da0-d0v83ggz` خارج المستودع؛ cache Laravel المؤقت في `I:\WORK\DALEEL-CRM-I03-RUNTIME` خارج المستودع. لا اتصال بقاعدة قديمة.

**VERIFIED_RUNTIME [E-MIG]:** تجهيز الأدوار I03 اجتاز تكرارين على الحاوية نفسها؛ 38/38 migration حقيقية اكتملت ثم أُدخلت fixtures. `migrate-retry.redacted.log` دليل الإعادة الأخيرة؛ سجل المحاولات غير الناجحة في `ATTEMPT-LEDGER.md`. كانت أدوار NOLOGIN للمجموعات والكتابة المقيدة، وأدوار LOGIN منفصلة لـA1/A2/B1/A4 وhost/auth/bootstrap/provider auth/provider control. أنشئت قبل migrations لأن 026 و028–030 و036–038 تتطلبها. هذا overlay داخل sandbox فقط، وليس provisioning منتجًا. 039 غائبة وغير مشغلة. `002_actor_sql_fixture.sql` أضاف A4 إلى خريطة bootstrap ودالة `f06i02_actor_tenant_id` ومنح `EXECUTE`، مع `REVOKE ... FROM PUBLIC`، وإلى سياسة leads ‏`RESTRICTIVE` المقترنة بـ`AND` بالسياسات `PERMISSIVE` الموجودة. جدول leads ‏`FORCE RLS`، ومجموعة `daleel_tenant_runtime` لا تملك كائنات؛ العضويات الأربع `ADMIN FALSE, INHERIT TRUE, SET FALSE`. تحقق ذلك من catalog في [E-SQL].

## G3 — اتصال SQL عدائي

**VERIFIED_RUNTIME [E-SQL]:** [sql_gate_evidence.json](../../tools/security/f06-laravel-i03/sql_gate_evidence.json) يضم 21/21 سيناريو متوقعًا بعد آخر إعادة. اتصالات TCP/SCRAM بأسماء `session_user` مستقلة. `SET ROLE daleel_tenant_runtime` أو دور actor آخر رُفض لكل A1/A2/B1/A4 مع rc=3 وSQLSTATE `42501`. B1 رأى صف B ضابطًا موجبًا؛ A1 وA4 رأيا صفوف A. تحت GUC spoof نحو B، SELECT أعاد صفرًا، UPDATE لم يُرجع صفًا، INSERT فشل rc=3/`42501`. SELECT وUPDATE وINSERT الشرعية داخل A نجحت لكل من A1 وA4، والكتابات العدائية والموجبة داخل معاملات `BEGIN/ROLLBACK` مع نجاح rollback. بصمة leads قبل/بعد آخر بوابة متطابقة. هذا يثبت حد tenant في sandbox فقط؛ SQL الحر قد يصل إلى صف actor آخر داخل tenant A، لذلك `ACTOR_SCOPE_ARBITRARY_SQL=OPEN`.

## G4 — HTTP وLD03

**VERIFIED_RUNTIME [E-HTTP]:** خادم Laravel `artisan serve --no-reload` على `127.0.0.1:18081`، وTLS loopback على `127.0.0.1:18082` للحفاظ على cookie ‏Secure في `APP_ENV=testing`. curl استخدم Host اصطناعيًا وOrigin وcookie jar وCSRF حقيقيين؛ المسار مر عبر Host resolver وauth/session و`LeadController`/`LeadService` الفعليين. [الدليل النهائي](../../tools/security/f06-laravel-i03/http_gate_evidence_20261026T055016.json): 23/23 OFF و23/23 ON، status وbody keysets وLead IDs والحقول المقارنة متطابقة لكل السيناريوهات، مع استعادة بصمة البيانات بعد كل flag. المقارنة طبّعت فقط حقول الصف المحددة بالمصدر وتجنبت UUID/time المتغيرين. Host خاطئ 404، guest 401، login دون CSRF ‏419، كلمة مرور خاطئة 401، A1/A2/B1/A4 logins ‏200، جلسة B1 على Host A ‏401، وA3 المعلق ‏401. قوائم A1=5 وA2=1 وB1=1 وA4=1. العلم OFF لا يعني إغلاق F06؛ ON طبق مفتاح A4 الجديد.

**LD03 [E-HTTP]:** (01) A4 قرأ lead أنشأه A1 وأسند إليه ‏200؛ (02) lead آخر في A ظاهر لـA1 وخارج إسناد A4 أعاد 403 لـA4؛ (03) lead أنشأه A4 وأسند إلى A1 أعاد 403 لـA4، فيفصل ASSIGNED عن SELF؛ (04) تحديث المسند ‏200، وغير المسند ‏403؛ (05) assign لـA4 وA2 أعاد 403 بسبب عقد `leads.manage=ALL_TENANT`، وA1 أعاد 200 ثم ظهر lead لـA4 (2 صفوف) مع تحقق DB restoration؛ (06) B غير ظاهر بقائمة A4 وبضوابط SQL/GUC؛ (07) A4 موجود في ACL/RLS/bootstrap، وغياب الاعتماد رُفض. رفض إعادة الإسناد لـA4/A2 هنا رفض capability؛ رفض تحديث صف A4 غير المسند يختبر نطاق الصف. أُعيدت البيانات إلى fixture baseline بعد كل flag.

**VERIFIED_RUNTIME [E-A4-NEG]:** [اختبار غياب الاعتماد](../../tools/security/f06-laravel-i03/http_gate_evidence_20261026T054602.json): عند إزالة `F06_ACTOR_PW_A4` من بيئة خادم ON فقط، تسجيل دخول A4 نجح لكن GET leads أعاد 500 مغلقًا، بينما A1 login وGET بقيا 200/5؛ لا fallback إلى اعتماد A1/A2/B1. استجابة 500 ليست UX مقبولًا للإنتاج؛ هي دليل رفض ضيق في testing. **VERIFIED_RUNTIME [E-A4-CONN]:** [سجل اتصال منقح](../../tools/security/f06-laravel-i03/a4_pg_connections.redacted.log) يبين اتصال SCRAM مصادقًا ومصرحًا بـ`user=daleel_f06i03_actor_a4` وقت طلبات ON. الرابط الزمني مع HTTP قوي، ولم نسجل request ID مشتركًا داخل SQL، فلا ندعي إثبات اقتران كل طلب بمعرف معاملة بعينها. `HTTP_SAME_WORKER_REUSE=NOT_VERIFIED`؛ خادم artisan لا يثبت بقاء worker واحد، ودليل process-local السابق يبقى منفصلًا.

## G5 — التاريخية وحدود التشغيل

**VERIFIED_SOURCE [E-HIST]:** فُحص `phpunit.xml` وملفات اختبارات Identity/Tenancy/Provider/ProviderControl. بعض الاختبارات مثبتة لقاعدة/منفذ acceptance ‏55437، وبعضها يتطلب ENG06 host أو port 5432، وبعضها يستخدم `RefreshDatabase`، وهو دورة حياة غير آمنة لقاعدة fixture هذه. لا يصح إجبارها على 55472 أو اعتبار skip نجاحًا. تشغيل host `php artisan test` لوحدتين بلا DB ظل صامتًا لأكثر من 30 ثانية ثم قوطع؛ لا counts مقبولة منه. لذلك 51 HTTP و11 Kernel و29 PHPUnit التاريخية `BLOCKED_UNSAFE_OR_UNMAPPED_TARGET` ولم تُعَد؛ أرقامها القديمة `DOCUMENTED_PRIOR` فقط. الاختبارات البديلة لهذه الجولة: G0 أربع حالات، SQL ‏21، HTTP ‏46 وغياب A4 أربع حالات. لا ترقية لهذه الأعداد إلى نجاح suite تاريخية.

## المحاولات والدلتا والموارد

**VERIFIED_RUNTIME [E-ATTEMPT]:** [سجل المحاولات](../../tools/security/f06-laravel-i03/ATTEMPT-LEDGER.md) يذكر فشل `.pgpass` على Windows، cache path، اختيار PHP بلا `pdo_pgsql`، تعارض دور provider عند migration 028، تصحيح parser SQL، إعادة تحميل `artisan serve` للبيئة، TLS/CSRF، وفشل harness بسبب `TIME_WAIT` ثم cache معدل الدخول. فشل `TIME_WAIT` ترك تعديلين صناعيين بلا استعادة؛ كُشف ذلك من اختلاف قائمة A4، ثم أعيدت **دلالة** صفّي fixture فقط داخل sandbox. بصمة DB الأولية قبل الحادث لا يمكن مساواتها بعد إعادة timestamps؛ البوابة النهائية تستخدم baseline جديدة متطابقة قبل/بعد. لا يُخفى هذا الاختلاف، ولا يعد انجرافًا في بيانات عملاء.

**VERIFIED_SOURCE [E-DELTA]:** إضافة مصدر منتج واحدة في `config/f06_actor_sql.php`، هي المفتاح الصناعي A4 فقط. بقية الملفات الجديدة في `tools/security/f06-laravel-i03/` والتقرير الحالي فقط. لا تغيير في I01/I02/SETROLE/POC أو واجهات الويب أو migrations 001–038 أو root docs. checkpoint manifest ما زال `08f4a8…2630adb7d`؛ الملفات الحية 24/25 تطابقه بعد التنفيذ، والوحيد المختلف `config/f06_actor_sql.php` بسبب السطر المصرح به. root `CLAUDE.md` بقي SHA ‏`a972f9ef…e8487a` كما أقره المالك قبل التنفيذ: `OWNER_APPROVED_PRE_EXISTING_CHANGE`، ولم يُعدل أو يُضف لـGit. ملف تقرير التوقف السابق SHA ‏`7678773135f4f42ae27b2201943941989989fcb2360076bb57efedd637fdcef5` ولم يُمس. [دلتا البصمات](../../tools/security/f06-laravel-i03/DELTA-SHA256.tsv) تسرد الملفات الجديدة والمعدلة دون أسرار. نقطة الاسترجاع القديمة محفوظة؛ لا checkpoint جديدة لهذه الجولة.

**VERIFIED_RUNTIME [E-STOP]:** بعد التحقق من اسم الحاوية والعلامة والمنفذ أُوقفَت حاوية I03 فقط. خادم Laravel وTLS الخاصان بالجولة أوقفتهما أداة HTTP، ولا listener على 18081/18082. container/network/volume باقية دون حذف؛ حالة الحاوية النهائية `exited`، ومصدرها `system_identifier` أعلاه. لم تُمس الموارد القديمة. لم يُجرَ Git add/commit/push. محاولة إزالة `__pycache__` الخاص بالأداة آليًا رُفضت بمراجعة التنفيذ؛ تُرك المجلد كما هو ولا يؤثر على الشفرة أو الأدلة.

## الأعلام الختامية

| العلم | القرار | الدليل/الحد |
|---|---|---|
| W0_PRECHECK | PASS_WITH_OWNER_EXCEPTION | E-W0؛ `CLAUDE.md` معتمد مسبقًا |
| RECOVERY_CHECKPOINT_25_HASH_MATCH | PASS_PREIMAGE; 24/25_LIVE_AFTER_EXPECTED | E-W0/E-DELTA |
| FIVE_REPO_GIT_BASELINE | PASS_WITH_OWNER_EXCEPTION | E-W0/E-DELTA؛ لا staged |
| A4_CREDENTIAL_MAPPING_SOURCE_CHANGE | PASS | E-G0؛ سطر واحد |
| A4_MISSING_CREDENTIAL_FAIL_CLOSED | PASS_SCOPED | E-G0/E-A4-NEG؛ HTTP 500 |
| FEATURE_FLAG_DEFAULT_OFF_TESTING_ONLY | PASS_SOURCE_AND_RUNTIME | E-G0/E-HTTP |
| NEW_SANDBOX_IDENTITY_AND_HBA | PASS | E-G2 |
| REAL_MIGRATIONS_APPLIED | PASS_38_OF_38 | E-MIG |
| A4_ASSIGNED_FIXTURE_AND_ACTOR_ROLE | PASS | E-MIG/E-HTTP |
| A4_RESTRICTIVE_RLS_APPLIES | PASS_SCOPED | E-MIG/E-SQL |
| ACTOR_SET_FALSE_ALL_ROLES | PASS | E-MIG/E-SQL |
| SET_ROLE_SQLSTATE_AND_RC | PASS_42501_RC3 | E-SQL |
| GUC_CROSS_TENANT_NEGATIVE_CONTROLS | PASS_SCOPED | E-SQL |
| HTTP_CSRF_AUTH_HOST_SESSION_WIRE | PASS | E-HTTP |
| LEADCONTROLLER_LEADSERVICE_REAL | PASS | E-HTTP |
| FLAG_OFF_ON_COMPARISON | PASS_23_VS_23 | E-HTTP |
| LD03_ASSIGNED_READ_AND_WRITE | PASS_SCOPED | E-HTTP |
| LD03_LEAD_REASSIGNMENT_CONTRACT | PASS_SCOPED | E-HTTP |
| HTTP_SAME_WORKER_REUSE | NOT_VERIFIED | لا worker ثابت مثبت |
| ROLE_PROVISIONING_SANDBOX_REPRODUCIBLE | PASS_SCOPED | E-MIG؛ تكراران على sandbox واحدة |
| ROLE_PROVISIONING_PRODUCT | NOT_IMPLEMENTED | لا provisioning منتج |
| HISTORICAL_51_HTTP | BLOCKED_UNSAFE_OR_UNMAPPED_TARGET | E-HIST؛ DOCUMENTED_PRIOR فقط |
| HISTORICAL_11_KERNEL | BLOCKED_UNSAFE_OR_UNMAPPED_TARGET | E-HIST؛ DOCUMENTED_PRIOR فقط |
| HISTORICAL_29_PHPUNIT | BLOCKED_UNSAFE_OR_UNMAPPED_TARGET | E-HIST؛ DOCUMENTED_PRIOR فقط |
| TENANT_SQL_BOUNDARY_AFTER_SETROLE | PASS_SCOPED_SANDBOX | E-SQL |
| ACTOR_SCOPE_ARBITRARY_SQL | OPEN | داخل tenant لا يزال مفتوحًا |
| PHP_MULTI_CREDENTIAL_COMPROMISE_RISK | OPEN | متعدد الاعتمادات في PHP |
| T4B_REMEDIATION | NOT_EXECUTED | خارج التفويض |
| F16_REMEDIATION | NOT_EXECUTED | خارج التفويض |
| MIGRATION_039 | NOT_EXECUTED | غير مصرّح بها |
| ROOT_PROTECTED_DOCS | UNCHANGED_WITH_OWNER_EXCEPTION | E-W0/E-DELTA |
| GIT_COMMIT | NOT_EXECUTED | ممنوع في الجولة |
| CURRENT_DELTA_RECOVERY_POINT | NOT_CREATED | يحتاج تفويضًا مستقلًا |
| CUSTOMERS | NOT_TOUCHED | sandbox اصطناعي فقط |
| PRODUCTION | NOT_TOUCHED | لا نشر |
| EXECUTIVE_VERDICT | PASS_SCOPED_FOR_I03_SANDBOX; F06_OPEN | البوابات الأساسية لهذه الجولة نجحت ضمن الحدود |
| NEXT_GATE | INDEPENDENT_DELTA_REVIEW_AND_NEW_RECOVERY_AUTH | مراجعة مستقلة ثم حفظ بتكليف منفصل |

## القرار

**PASS_SCOPED** لفك مانع A4 والاختبارات G0/G2/G3/HTTP/LD03 في sandbox الجديدة. لا يُحوَّل هذا إلى GO للمنتج أو العملاء أو الإنتاج؛ F06 وT4b وF16 وSQL actor-scope داخل الشركة وإدارة الاعتمادات تبقى مفتوحة. الخطوة التالية المحددة: مراجعة مستقلة للدلتا والأدلة ثم تفويض صريح منفصل لإنشاء نقطة استرجاع جديدة، قبل أي شريحة تنفيذ لاحقة.

</div>
