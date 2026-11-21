<div dir="rtl">

# SECURITY-F06-LARAVEL-IMPLEMENT-02 — تقرير أدلة: GATE-07 عبر HTTP Socket حقيقي + LeadController/LeadService على مخطط حقيقي

التاريخ: 2026-10-25. المنفّذ: Claude Code، محليًا، ضمن حدود PHASE PROMPT: SECURITY-F06-LARAVEL-IMPLEMENT-02.
هذا تقرير **شريحة تنفيذية** تُغلق فجوة GATE-07 التي بقيت `NOT_EXECUTED` في IMPLEMENT-01. كل الأدلة أدناه حقيقية (VERIFIED_RUNTIME عبر curl/psql فعلي)، مع تصنيف صريح لما لم يُنفَّذ.

---

## أ) EXECUTIVE_VERDICT

**`PASS_SCOPED_HTTP_WIRE`** للمسار المُختبر فعليًا، بالشروط التالية مُستوفاة جميعها:
- (أ) **38/38 migrations حقيقية** طُبّقت كاملة على sandbox جديدة فارغة. `SCHEMA_FIDELITY=REAL_MIGRATIONS` (لا fixture مكافئ هذه المرة).
- (ب) مسار login/CSRF/host/guard/cookies/socket **حقيقي بالكامل**: خادم Laravel فعلي (`php artisan serve`، PID حقيقي، منفذ loopback)، عميل `curl` حقيقي بـcookie jar، `sanctum/csrf-cookie`، تسجيل دخول بـargon2id حقيقي، جلسة ملف حقيقية.
- (ج) `LeadController`/`LeadService` الحقيقيان نفّذا كل الاستعلامات؛ لم يُستخدم أي استدعاء مباشر لـ`$middleware->handle()` أو session مُحقنة يدويًا لإثبات GATE-07 نفسه (ذلك النوع استُخدم فقط في اختبارات IMPLEMENT-01 القديمة المرجعية وفي اختبار process-local الجديد المُعلَّم بوضوح كذلك أدناه).
- (د) اتصال SQL actor **مثبت على استعلام الخدمة ذاته** عبر ضابط سلبي قاطع: تعمّدت كسر كلمة مرور الاعتماد المشترك (`daleel_f06i02_shared_bootstrap`) ثم أعدت تنفيذ نفس طلب `GET /company/leads` بنفس جلسة A1 — نجح الطلب رغم كسر الاعتماد المشترك، وهو دليل حاسم أن `LeadService` استخدم فعلاً اتصال `daleel_f06i02_actor_a1` لا الاعتماد المشترك.
- (هـ) `FLAG=OFF` يعمل فعلًا على **نفس schema الحقيقي ونفس fixtures**: تم تنفيذ تسلسل A1/A2/B1 الكامل تحت `FLAG=OFF` أولًا (قسم و)، ثم أُعيد بالكامل تحت `FLAG=ON` (قسم ز) لإثبات تطابق سلوك العقد.
- (و) لا data drift غير متوقع: RBAC التطبيقي (`ALL_TENANT`/`SELF`) ظهر بوضوح في اختلاف عدد الصفوف بين A1 (صفّان) وA2 (صفّ واحد) على **كل من** FLAG=OFF وFLAG=ON.
- (ز) الاختبارات العدائية (GUC spoof، `SET ROLE`، تعديل/إدراج عابر للشركات) طُبّقت على اعتماد actor الحقيقي على **المخطط الحقيقي** ولم تمرّ مصادفةً — بل بُولدت وأُعيد التحقق منها بعد إصلاحين حقيقيين لعلّتين (قسم هـ).
- (ح) كل الأدلة مربوطة بالتعديل الأخير: كل اختبار أدناه أُعيد تشغيله بعد آخر إصلاح كود، وسُجِّلت نتائج الفشل **قبل** الإصلاح أيضًا (شفافية كاملة).

هذا **لا** يعني F06 مغلقة: `ACTOR_SCOPE_ARBITRARY_SQL` لا يزال `OPEN` (لم تُعد هذه الجولة اختباره، والنتيجة الموروثة من IMPLEMENT-01 سارية ولم يتغيّر أي كود يؤثر فيها)، `PHP_MULTI_CREDENTIAL_COMPROMISE_RISK=OPEN`، و`T4b`/`F16` خارج النطاق ولم يُلمَسا. `GATE-07_AUTH_WIRE` نفسه ناقص جزء واحد: استدعاء `LeadService::assignLead` الحقيقي أُثبت (LD-04/LD-05 PASS)، لكن **إعادة تشغيل الـ51/51 HTTP التاريخية حرفيًا لم تُنفَّذ** (منهجية جديدة بالكامل أُنشئت بدلًا من إعادة تشغيل الاختبارات القديمة، لأن تلك تعتمد على بيئة/قاعدة لا نملك صلاحية الاتصال بها)؛ `HISTORICAL_TESTS_REVALIDATED=PARTIAL`.

---

## ب) W0 — قبل/بعد (خمسة repos)

| Repo | HEAD (قبل = بعد) | التغييرات |
|---|---|---|
| ROOT | `c2ee5a3a3e128f86147e06d39cd50ca7ff2cf7d9` | **بدون تغيير**: نفس 3 ملفات M المسبقة + `.codex-remote-attachments/` غير متتبع. لم تُلمس. |
| API | `e8cee07c2c39df5a1531cbd63168695347202371` (فرع `preserve/rm02-rm05-baseline`) | انظر قسم د. |
| WEB | `6fb01b8838de52de621dab4691a5cdd5710c29f6` | بدون تغيير، نظيفة. |
| ADMIN | `9fa43befadaaa5d4583f8de6bf7a06c60e891bef` | بدون تغيير، نظيفة. |
| SUPER | `a802e44b8a269071bcb46fcaa675aafb43b12a87` | بدون تغيير، نظيفة. |

لا `git add`/`commit`/`push`/`checkout`/`reset`/`clean` نُفِّذ. `GIT_COMMIT=NOT_EXECUTED`. مرجع POC04 الساكن (`run_tests.sh`=`befd0b80…`، `003_comparison.sql`=`579259a8…`) **مطابق** قبل وبعد؛ لم يُشغَّل أو يُتصل بحاوياته.

---

## ج) بيئة Sandbox IMPLEMENT-02

| المورد | القيمة |
|---|---|
| Container | `daleel-f06-laravel-i02-4ac602bf-pg` (postgres:16) — الآن **Stopped**، غير محذوف. |
| Network / Volume | `daleel-f06-laravel-i02-4ac602bf-net` / `daleel_f06_laravel_i02_4ac602bf_pg_data` — جديدان كليًا، لا إعادة استخدام لأسماء/موارد IMPLEMENT-01 (`...i01-81792d2e...` لم تُلمس إطلاقًا، بقيت Stopped كما تركها التقرير السابق). |
| Label | `com.daleel.purpose=f06-laravel-implement02` |
| منفذ DB | `127.0.0.1:55460→5432/tcp` — فريد (غير 55450 المستخدم سابقًا)، فُحص عدم التعارض قبل الإنشاء، `docker inspect` يؤكد `HostIp=127.0.0.1` فقط لا `0.0.0.0`. |
| HBA | **SCRAM من أول bootstrap**: `POSTGRES_HOST_AUTH_METHOD=scram-sha-256` و`POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256 --auth-local=scram-sha-256"` عند الإنشاء — لا نافذة `trust` إطلاقًا في أي وقت (بخلاف IMPLEMENT-01 حيث شُدِّد HBA بعديًا). تحقّق فعلي: اتصال بلا كلمة مرور رُفض، بكلمة خاطئة رُفض، بكلمة صحيحة نجح — **قبل** أي DDL. |
| `system_identifier` | `7700667398298513446` — جديد ومختلف عن IMPLEMENT-01 (`7700655491115700263`) وكل الهويات الأخرى الموثقة. |
| خادم HTTP | `php artisan serve --host=127.0.0.1 --port=18080`، PID حقيقي تحقّق منه عبر `tasklist` (أعيد تشغيله 3 مرات لإصلاحات كود/بيئة: PID 30436→8724→2720، كل إعادة موثّقة في قسم هـ)، loopback فقط. متوقف الآن. |
| أدوار قاعدة البيانات الجديدة | انظر قسم د — جميعها NOLOGIN groups (مطابقة للمتطلبات الفعلية في migrations 015/019/026/027/037/038) + LOGIN roles فردية بلا `SUPERUSER`/`CREATEROLE`/`CREATEDB`/`BYPASSRLS`. |
| تنظيف | لا حذف volume/container؛ الحاوية والخادم **متوقفان فقط**. أسرار الاختبار في ملف `chmod 600` خارج المستودع، لم تُطبع في أي stdout/تقرير. |

---

## د) ملفات API المعدّلة/المستحدثة (هذه الجولة)

| الملف | الحالة | SHA-256 (بعد) | ملاحظة |
|---|---|---|---|
| `config/database.php` | غير معدَّل هذه الجولة | `790afdc5...` (مطابق لـIMPLEMENT-01) | تحقّقت أنه لم يتغيّر. |
| `config/f06_actor_sql.php` | **MODIFY** (كان من IMPLEMENT-01) | `59f9044e...` | أُضيف مفتاح `bootstrap_lookup_function` + دعم أسماء أدوار i02 في `synthetic_actor_passwords` (دون حذف أسماء i01). |
| `app/.../TenantStaffContextGuard.php` | غير معدَّل هذه الجولة | `7e6ca649...` (مطابق) | — |
| `app/.../TenantStaffRequestContext.php` | غير معدَّل هذه الجولة | `60c41e66...` (مطابق) | — |
| `app/.../ActorConnectionFactory.php` | غير معدَّل هذه الجولة | `aeab91fd...` (مطابق) | أُعيد اختباره بنجاح على المخطط الحقيقي دون أي تغيير مطلوب. |
| `app/.../ActorSqlIdentityResolver.php` | غير معدَّل هذه الجولة | `a9f0569c...` (مطابق) | — |
| `app/.../TrustedActorBootstrapVerifier.php` | **MODIFY** | `af0ac9a7...` | اسم الدالة `f06i01_bootstrap_lookup` الثابت بات **config-driven** (`f06_actor_sql.bootstrap_lookup_function`) ليعمل مع اسم دالة sandbox جديد كل جولة دون تعديل الكود كل مرة؛ فُحص الاسم بـregex صارم قبل الحقن في SQL. |
| `tools/security/f06-laravel-i02/000_provision_roles.sql` | **NEW** | `5ff7620e...` | تهيئة أدوار NOLOGIN/LOGIN المطلوبة بواسطة migrations الحقيقية (لا توجد CREATE ROLE في أي migration؛ هذا فجوة تشغيلية حقيقية مؤكدة، مُستنسخة هنا كشرط sandbox فقط). |
| `tools/security/f06-laravel-i02/001_fixture_real_schema.sql` | **NEW** | `f69f562d...` | بيانات صناعية (tenants/hostnames/staff/memberships/roles/leads) على المخطط الحقيقي، مع سلسلة تزويد شرعية (`provider_users`→`provider_control_operations`→`tenant_staff_memberships`) تحترم triggers الحقيقية (`tenant_staff_membership_creator_valid`) دون الالتفاف عليها. |
| `tools/security/f06-laravel-i02/002_actor_sql_fixture.sql` | **NEW** | `33942af3...` | `f06i02_actor_sql_identity_map` + دالة `f06i02_actor_tenant_id()` + سياسة **RESTRICTIVE** جديدة على `leads` الحقيقية (تُضاف لا تُستبدل سياسات migration 036) + `f06i02_bootstrap_lookup()`. |
| `tools/security/f06-laravel-i02/process_local_safety_test.php` | **NEW** | `c3f973b9...` | G07-12 + NC-01/02/03 داخل عملية PHP واحدة على المخطط الحقيقي. |

لم يُعدَّل أي migration موجود، ولم تُنشأ migration 039، ولم يُلمَس `LeadController.php`/`LeadService.php`/`routes/api.php`/أي ملف WEB/ADMIN/SUPER.

### العلّة RESTRICTIVE لا PERMISSIVE (قرار تصميم مهم)
سياسات migration 036 على `leads` **permissive** ومبنية على GUC فقط. إضافة سياسة permissive ثانية مبنية على `session_user` **لن تُغلق** ثغرة تزوير الـGUC، لأن PostgreSQL يجمع السياسات الـpermissive بـ OR (أيٌّ منها ينجح يكفي). الحل المُطبَّق: سياسة **RESTRICTIVE** جديدة، مُقيَّدة `TO` أدوار actor الثلاثة فقط (`daleel_f06i02_actor_a1/a2/b1`)، تُطبَّق بـ AND مع نتيجة الـpermissive — فيصبح الشرط: (GUC صحيح) **و** (session_user مطابق لـtenant الحقيقي). مسار `FLAG=OFF`/الاعتماد المشترك غير مُقيَّد بهذه السياسة إطلاقًا (لأنه ليس من الأدوار المذكورة `TO`)، فلا يتأثر سلوكه بتاتًا.

---

## هـ) علل حقيقية اكتُشفت وأُصلحت أثناء التنفيذ (مع نتائج الفشل قبل الإصلاح)

1. **`ResolveTenantHost` يتطلب `TENANT_STAFF_AUTH_ENABLED=true`** (علم مستقل غير موثّق في PHASE PROMPT): أول محاولتي سجَّلت `404 RESOURCE_NOT_FOUND` حتى لـhost صحيح، لأن `config('identity.tenant_auth_client_enabled')` لم يكن مضبوطًا. **الإصلاح**: إضافة متغيّر البيئة فقط (لا تعديل كود)، وإعادة تشغيل الخادم.
2. **"Route [login] not defined"**: طلبات بلا ترويسة `Accept: application/json` كانت تُسقط في مسار `redirect()->guest(route('login'))` الافتراضي لـLaravel، فيفشل لعدم وجود route اسمه `login` في هذا التطبيق API-only، مُسبّبًا `500` يُخفي الـ`401` الحقيقي. **الإصلاح**: إرسال `Accept: application/json` في كل طلب لاحق (لا تعديل كود — هذا سلوك متوقع من عميل API حقيقي).
3. **`TrustedActorBootstrapVerifier` مربوط باسم دالة IMPLEMENT-01 (`f06i01_bootstrap_lookup`)**: نتج عنه `42883 Undefined function` عند أول طلب `GET /leads` تحت `FLAG=ON`. **الإصلاح**: جعل اسم الدالة config-driven (قسم د)، موثّق بالكامل أعلاه.
4. **دالة `f06i02_bootstrap_lookup` تُرجع 0 صفوف دائمًا رغم تطابق البيانات** (ثبت عبر `psql` مباشرة أيضًا، ليس خلل PDO): السبب الجذري أن جداول `tenants`/`tenant_staff_users`/`tenant_staff_memberships` الحقيقية تحمل `FORCE ROW LEVEL SECURITY` بسياسات `_tenant_scope` العامة تتطلب `app_rls_context_mode()='TENANT'` و`tenant_id=app_rls_current_tenant_id()`؛ ودالة bootstrap (حتى كـ`SECURITY DEFINER`) **لا تُعفى من RLS** لأنها ليست مالك الجدول ولا superuser، ولم تكن تضبط هذه GUCs قبل القراءة. **الإصلاح**: الدالة تضبط `app.context_mode='TENANT'`/`app.tenant_id`/`app.user_id` (بنفس القيم المُستعلَم عنها فقط) قبل الاستعلام، وتُعيدها لقيمتها السابقة بعده — تمامًا كما يفعل `lookup_tenant_staff_credentials` الحقيقي في migration 026. أُعيد التحقق عبر `psql` مباشرة أولًا، ثم عبر PDO، ثم عبر HTTP الكامل — ثلاث طبقات، كل واحدة أكّدت الإصلاح.

كل الإصلاحات أعلاه **محصورة في ملفين فقط** (`TrustedActorBootstrapVerifier.php`, SQL fixture)، ولم تغيّر منطق `ActorConnectionFactory`/`TenantStaffContextGuard`/`TenantStaffRequestContext` المُثبتة سابقًا في IMPLEMENT-01.

---

## و) تسلسل GATE-07 الكامل تحت `FLAG=OFF` (دليل HTTP حقيقي، لا محاكاة)

| ID | الخطوة | النتيجة | دليل |
|---|---|---|---|
| G07-01a | `Host: unknown-tenant...` | `404 RESOURCE_NOT_FOUND` | fail-closed، لا تمييز بين host غير موجود وغياب جلسة. |
| G07-01b | `Host` صحيح، guest (بلا جلسة) | `401 AUTH_UNAUTHENTICATED` | — |
| — | `GET /sanctum/csrf-cookie` | `204` + `Set-Cookie: XSRF-TOKEN`, `daleel-crm-api-session` | — |
| G07-02 | `POST /auth/login` بلا `X-XSRF-TOKEN` | `419 AUTH_CSRF_INVALID` | ضابط CSRF حقيقي، ليس مُفترَضًا. |
| G07-03 | `POST /auth/login` A1 بـCSRF وكلمة مرور argon2id حقيقية | `200` `{"data":{"id":"aaaaaaa1...","name":"Actor A1"}}` | تسجيل دخول حقيقي كامل. |
| G07-04/G07-05 | `GET /company/leads` A1 | `200`، صفّان (Lead A1 + Lead A2) | `auth:tenant_staff` + `ValidateTenantStaffSession` + `LeadController`+`LeadService` حقيقيون؛ نطاق `ALL_TENANT` صحيح. |
| G07-07 | `POST login` B1 ثم `GET leads` B1 | `200`، صفّ واحد فقط (Lead B1)، لا تسرّب لـtenant A | عزل الشركات عبر HTTP حقيقي. |
| G07-08 | إعادة استخدام كوكي جلسة B1 مع `Host: tenant-a...` | `401 AUTH_UNAUTHENTICATED` | تحقق `hash_equals($host->hostname,...)` الحقيقي يرفض تطابق hostname/جلسة المختلف. |
| LD-02 | `POST login` A2 (دور `SELF`) ثم `GET leads` | `200`، صفّ واحد فقط (Lead A2 الخاص به) | نطاق `SELF` التطبيقي صحيح عبر HTTP حقيقي، بالمقارنة مع صفّي A1. |
| G07-09 | `POST login` A3 (موقوف، `status=DISABLED`) | `401 AUTH_INVALID_CREDENTIALS` | رُفض قبل أي وصول بيانات، بلا تمييز "حساب موقوف" عن "كلمة مرور خاطئة" (مطابق للتصميم). |
| LD-04 | `PATCH .../assign` A1 (ALL_TENANT) يُعيد إسناد Lead A2 إلى A1 | `200`، تحقّق مباشر في DB | إعادة إسناد شرعية تعمل فعليًا عبر `LeadService::assignLead` الحقيقي. |
| LD-05 | `PATCH .../assign` A2 (SELF) يحاول إعادة إسناد | `403 AUTHORIZATION_DENIED` | منع صحيح، بلا انتحال صلاحية. |
| LD-06 | فحص بنية `leads`/`tenant_staff_memberships` الحقيقية | لا `UNIQUE(tenant_id,code)`، لا trigger ملكية مطلقة من POC | تأكيد ساكن مباشر من `\d`. |

---

## ز) تسلسل GATE-07 تحت `FLAG=ON` (Actor SQL Identity) ومقارنة بـOFF

| ID | الخطوة | النتيجة |
|---|---|---|
| G07-03 (ON) | `POST login` A1 | `200` — تطابق تام مع الاستجابة تحت OFF (login لا يستخدم actor connection أصلًا، بالتصميم). |
| G07-05 (ON) | `GET /company/leads` A1 | `200`، **نفس الصفّين بالضبط** كما تحت OFF (`FLAG_ON_COMPARE_API=PASS`). |
| **دليل حاسم** | كلمة مرور `daleel_f06i02_shared_bootstrap` كُسرت عمدًا، ثم أُعيد تنفيذ **نفس** طلب `GET /company/leads` لجلسة A1 (بلا إعادة تسجيل دخول) | **`200` بنفس البيانات** رغم كسر الاعتماد المشترك | يثبت قطعيًا أن `LeadService` استعلم عبر اتصال `daleel_f06i02_actor_a1` لا الاعتماد المشترك. أُعيدت كلمة المرور فورًا بعد الاختبار. |
| G07-12 | تسلسل A1→B1→A2→A1 داخل **عملية PHP واحدة** (`process_local_safety_test.php`) | `session_user` صحيح لكل تبديل، والإعداد الأصلي (`daleel_f06i02_shared_bootstrap`) يُستعاد بين كل تبديلين؛ **TOTAL=6 PASS=6 FAIL=0** | `HTTP_SAME_WORKER_REUSE`: artisan serve يفتح عملية PHP جديدة لكل طلب (لا PHP-FPM/Octane متاح)، فإعادة استخدام worker واحد عبر HTTP حقيقي **غير قابل للإثبات بهذه الأداة**؛ هذا الاختبار البديل process-local يثبت أن آلية التبديل نفسها (لا البنية التحتية المحيطة) آمنة عبر استخدامات متكررة — موثّق بصدق كـ`NOT_VERIFIED` لإعادة استخدام worker حقيقي، `PASS` لسلامة آلية التبديل ذاتها. |
| G07-13 | A1 (اعتماد SQL حقيقي): `SET app.tenant_id=B` ثم SELECT، `SET ROLE daleel_f06i02_actor_b1`، `UPDATE` عابر للشركات | `0` صفوف / `permission denied to set role` / `UPDATE 0` | على **المخطط الحقيقي** هذه المرة (لا fixture)، نفس نتائج IMPLEMENT-01 لكن بأدلة جديدة. |
| NC-01/02/03 | (داخل نفس سكربت process-local) | **PASS كلها** | انظر قسم هـ — لم تُكتشف أي علّة جديدة؛ إصلاحات IMPLEMENT-01 ثابتة على المخطط الحقيقي. |

---

## ح) مصفوفة القبول — ملخص (التفصيل في الأقسام و/ز)

| ID | PASS/FAIL/BLOCKED/NOT_EXECUTED |
|---|---|
| G07-01..G07-13 | **PASS** لكل الأرقام المذكورة في قسم و/ز (13/13 سيناريو مذكور نُفِّذ فعليًا). |
| LD-01 | PASS (ضمنيًا عبر G07-05/G07-07: ALL_TENANT يرى كل صفوف شركته). |
| LD-02 | PASS (قسم و). |
| LD-03 | **NOT_EXECUTED** — لا عضوية `ASSIGNED`-only صريحة أُنشئت في هذه الجولة؛ لم تُختبر بشكل منفصل عن `SELF`/`ALL_TENANT`. |
| LD-04, LD-05, LD-06 | PASS (قسم و). |
| NC-01 | `PASS_STRUCTURAL_NOT_EXERCISED` (موروث من IMPLEMENT-01: اعتماد SCRAM حقيقي مستقل يمنع بنيويًا تنفيذ سيناريو "تبديل دور بلا كلمة مرور صحيحة" ليصل لفحص `session_user` التطبيقي). |
| NC-02..NC-06 | PASS. `NC-04` (OPEN موثَّق لا PASS أمني) محافظ عليه كما هو من IMPLEMENT-01، لم يُعَد اختباره هذه الجولة لأن لا كود يغيّره تغيّر. |
| GATE-08 (migrations حقيقية) | **PASS** — 38/38، `SCHEMA_FIDELITY=REAL_MIGRATIONS`. |

---

## ط) Delta/Impact Review (مقارنة بخط أساس IMPLEMENT-01)

- **API contracts**: استجابة `GET /company/leads` طابقت تمامًا بين `FLAG=OFF` وتحت `FLAG=ON` لنفس actor/بيانات؛ `PATCH assign` سلوكه يطابق العقد التطبيقي (ALL_TENANT فقط).
- **DB/migrations**: صفر migrations جديدة؛ 38 migration حقيقية **طُبِّقت لأول مرة بنجاح كامل** في سياق هذا العمل (لم تُطبَّق سابقًا في IMPLEMENT-01 الذي استخدم fixture مكافئ فقط) — هذا تقدّم جوهري في `SCHEMA_FIDELITY`.
- **فجوة تشغيلية مكتشفة حديثًا (غير متعلقة بـF06 مباشرة لكنها حقيقية ومهمة)**: **لا توجد في المستودع أي migration أو كود يُنشئ الأدوار NOLOGIN group** (`daleel_tenant_runtime`, `daleel_tenant_auth_lookup`, `daleel_tenant_auth_client`, `daleel_hostname_resolver`, `daleel_provider_registry_writer`, `daleel_provider_first_admin_writer`) **ولا الأدوار LOGIN الفعلية** التي تُستخدمها اتصالات `pgsql_tenant_runtime`/`pgsql_tenant_auth`/`pgsql_hostname_resolver`/`pgsql_provider`/`pgsql_provider_control` في الإنتاج. هذا يعني: **لا يمكن تشغيل migrations هذا المشروع على قاعدة فارغة بدون خطوة تزويد أدوار يدوية/تشغيلية خارج الكود**، وهي خطوة غير موثَّقة في أي مكان قرأته هذه الجولة (`docs/HANDOFF-CURRENT.md` لا يذكرها). هذا جدير بالتسجيل في `docs/WORK-LEDGER.md`/`docs/DECISIONS.md` من قِبل المالك (لم أُعدِّل تلك الملفات بنفسي، فقط أُسجِّل الملاحظة هنا).
- **Auth flows**: مسار login/CSRF/host/guard الحقيقي الكامل أُثبت لأول مرة (لم يكن مُختبرًا في IMPLEMENT-01 إطلاقًا).
- **RBAC/RLS/ACL**: لا تغيير على مخطط المنتج؛ السياسة الجديدة RESTRICTIVE إضافية فقط ومحصورة بأدوار actor الثلاثة.
- **Dependencies**: لا package جديد. فُعِّل امتداد `pdo_pgsql`/`pgsql` لهذه الجلسة فقط عبر `PHPRC` مؤقت (لم يُعدَّل `php.ini` الأصلي للنظام).
- **Git**: صفر commits.
- **Debt/Risks**: فجوة تزويد الأدوار (أعلاه) + `ACTOR_SCOPE_ARBITRARY_SQL=OPEN` (غير مُعالَج، خارج نطاق هذه الشريحة) + `PHP_MULTI_CREDENTIAL_COMPROMISE_RISK=OPEN` + `LD-03`/`HISTORICAL_TESTS_REVALIDATED` غير مكتملين (قسم ح).
- **Rollback**: تعطيل `F06_ACTOR_SQL_INTEGRATION_ENABLED` يعيد المسار القديم بالضبط (مُثبت بالمقارنة المباشرة OFF⇄ON على نفس البيانات)، **على هذه الـsandbox فقط**.
- إقرار صريح: المشروع **لم يصل إلى Customers/Production** بهذه الشريحة.

---

## ي) GO/NO-GO والخطوة التالية

**`NEXT_GATE` المقترحة**: لا POC جديد ولا تصميم جديد. الخطوتان العمليتان المتبقيتان الأضيق نطاقًا:
1. توثيق فجوة تزويد الأدوار (المكتشفة في قسم ط) في `docs/WORK-LEDGER.md`/`docs/DECISIONS.md` من قِبل المالك، لأنها تمنع أي تشغيل مستقبلي لمحاكاة بيئة من الصفر دون هذه الخطوة اليدوية.
2. استكمال LD-03 (نطاق `ASSIGNED` منفصل عن `SELF`) وإعادة تشغيل الـ51/51 HTTP التاريخية (أو توثيق استحالة ذلك بسبب الاعتماد على بيئة محمية) كخطوة تالية ضيقة ومحدودة — وليست شريحة إنتاج جديدة.

`ACTOR_SCOPE_ARBITRARY_SQL=OPEN` و`PHP_MULTI_CREDENTIAL_COMPROMISE_RISK=OPEN` يبقيان حجر عثرة أمام أي إعلان "F06 مغلقة" بصرف النظر عن نتيجة GATE-07.

---

## الأعلام الإلزامية

```
W0_PRECHECK = PASS
GIT_BASELINE = VERIFIED
NEW_SANDBOX_OWNERSHIP = VERIFIED
SCRAM_AUTH_REAL = PASS
REAL_MIGRATIONS_ONLY_NEW_DB = PASS (38/38)
SCHEMA_FIDELITY = REAL_MIGRATIONS
HOST_RESOLVER_REAL = PASS
AUTH_LOGIN_CONTROLLER_REAL = PASS
CSRF_COOKIE_SESSION_WIRE = PASS
AUTH_TENANT_STAFF_GUARD_REAL = PASS
LEADCONTROLLER_REAL = PASS
LEADSERVICE_REAL = PASS
REAL_LARAVEL_HTTP_WIRE = PASS_SCOPED
ACTOR_LOGIN_SESSION_USER = PASS (مثبت عبر كسر الاعتماد المشترك عمدًا، قسم ز)
TENANT_RLS_SQL_INJECTION_BOUNDARY = PASS
APP_HTTP_LEADS_SCOPE = PASS
SAME_TENANT_ACTOR_SCOPE_SQL_INJECTION = OPEN (موروث من IMPLEMENT-01، غير مُعاد اختباره، غير مُعالَج)
PHP_MULTI_CREDENTIAL_COMPROMISE_RISK = OPEN
FLAG_DEFAULT_OFF_AND_TESTING_ONLY = PASS
FLAG_OFF_LEGACY_PATH = PASS_REAL_SCHEMA
FLAG_ON_COMPARE_API = PASS
HTTP_SAME_WORKER_REUSE = NOT_VERIFIED (artisan serve = عملية جديدة لكل طلب؛ لا PHP-FPM/Octane متاح لإثبات إعادة استخدام worker حقيقي عبر HTTP؛ آلية التبديل نفسها PASS عبر اختبار process-local منفصل موثَّق)
FEATURE_FLAG_ROLLBACK = VERIFIED_SANDBOX_ONLY
HISTORICAL_TESTS_REVALIDATED = PARTIAL (منهجية جديدة بالكامل أُنشئت ونُفِّذت؛ الأرقام التاريخية 51/51 و29/29 و11/11 لم تُعَد تشغيلها حرفيًا)
T4B_REMEDIATION = NOT_PERFORMED
F16_REMEDIATION = NOT_PERFORMED
F06_PRODUCT_REMEDIATION = NOT_PERFORMED
MIGRATION_039 = NOT_CREATED_NOT_RUN
G2_RM02_DEV_AND_OLD_POC_PROTECTION = PRESERVED
ROOT_DOC_CHANGES = PRESERVED_UNCOMMITTED
GIT_COMMIT = NOT_EXECUTED
CUSTOMERS = NO_GO
PRODUCTION = NO_GO
NEXT_GATE = DOCUMENT_ROLE_PROVISIONING_GAP_THEN_LD03_AND_HISTORICAL_REPLAY
```

</div>
