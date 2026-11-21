<div dir="rtl">

# SECURITY-F06-LARAVEL-IMPLEMENT-01 — تقرير أدلة: أول تكامل Laravel HTTP ↔ SQL actor login (sandbox معزولة)

التاريخ: 2026-10-25. المنفّذ: Claude Code، محليًا، ضمن حدود PHASE PROMPT: SECURITY-F06-LARAVEL-IMPLEMENT-01.
هذا تقرير **شريحة تنفيذية أولى محدودة النطاق**، لا يُغلق F06، ولا T4b، ولا F16. كل الأدلة أدناه حقيقية (VERIFIED_RUNTIME/VERIFIED_SOURCE) أو موثّقة صراحة كـ DOCUMENTED_PRIOR/STATIC_INFERENCE/NOT_EXECUTED. لا يوجد ادّعاء نجاح غير مدعوم بسجل تنفيذ فعلي.

---

## أ) EXECUTIVE_VERDICT

**`PARTIAL`** — ليس `PASS_SCOPED_HTTP_SQL` الكامل، لأن:
- طبقة SQL العدائية (GATE-02، GATE-04، GATE-05، NC-02..NC-05) أُثبتت بالكامل بأدلة حقيقية (SCRAM فعلي، psql مباشر، RLS حقيقية).
- طبقة HTTP أُثبتت فقط عبر **استدعاء مباشر للـ middleware الحقيقي** (`TenantStaffRequestContext::handle()`) بطلب `Illuminate\Http\Request` حقيقي وجلسة حقيقية وقاعدة PostgreSQL حقيقية جديدة — **وليس** عبر HTTP socket كامل (`artisan serve` + cookie jar + مسار `auth:tenant_staff`/`ValidateTenantStaffSession` الحقيقي). لذلك `REAL_LARAVEL_HTTP_WIRE=PARTIAL`.
- GATE-07 (AUTH_WIRE: تسجيل الدخول الحقيقي، `dl_tauth`، CSRF) **لم يُنفَّذ** في هذه الجولة؛ الأرقام التاريخية (51/51 HTTP ×3, 11/11 Kernel, 29/29 PHPUnit) تبقى `DOCUMENTED_PRIOR` فقط ولم تُعَد.
- `SCHEMA_FIDELITY=SCOPED_EQUIVALENT`: الـsandbox تستخدم جدولًا مكافئًا صناعيًا (18 عمودًا لـleads مطابقة لـmigration 036، وFKs مركّبة) وليس إعادة تشغيل migrations 001–038 الحقيقية.
- تم اكتشاف وإصلاح علة حقيقية في الكود أثناء الاختبار (قسم هـ) قبل الإعلان عن أي PASS.

النتيجة العملية: **الطبقة الأمنية الجوهرية (حدود tenant عبر SQL حر تحت actor login حقيقي) مُثبتة بأدلة قوية**، بينما **طبقة "الربط الكامل بسلك HTTP الحقيقي" لا تزال جزئية** وتحتاج شريحة لاحقة لإثبات المسار الكامل (تسجيل الدخول → الجلسة → CSRF → auth guard) على نفس البنية.

---

## ب) W0 — قبل/بعد (خمسة repos)

| Repo | الفرع | HEAD (قبل = بعد) | dirty/staged/untracked |
|---|---|---|---|
| ROOT | master | `c2ee5a3a3e128f86147e06d39cd50ca7ff2cf7d9` | **بدون تغيير**: نفس 3 ملفات M مسبقًا (`docs/EVIDENCE-REGISTER.md`, `docs/HANDOFF-CURRENT.md`, `docs/WORK-LEDGER.md`) + `.codex-remote-attachments/` غير متتبع — لم تُلمس. |
| API | preserve/rm02-rm05-baseline | `e8cee07c2c39df5a1531cbd63168695347202371` | **بعد**: 3 ملفات M جديدة (`config/database.php`, `app/.../TenantStaffContextGuard.php`, `app/.../TenantStaffRequestContext.php`) + ملفات جديدة (قسم د) + `tools/` (كانت موجودة جزئيًا، أُضيف إليها `f06-laravel-i01/` فقط) + تقرير التصميم السابق (لم يُلمس) + هذا التقرير. |
| WEB | master | `6fb01b8838de52de621dab4691a5cdd5710c29f6` | **بدون تغيير**، نظيفة. |
| ADMIN | master | `9fa43befadaaa5d4583f8de6bf7a06c60e891bef` | **بدون تغيير**، نظيفة. |
| SUPER | master | `a802e44b8a269071bcb46fcaa675aafb43b12a87` | **بدون تغيير**، نظيفة. |

لا `git add`/`commit`/`push`/`checkout`/`reset`/`clean` نُفّذ في أي مستودع. `GIT_COMMIT=NOT_EXECUTED`.

مرجع POC04 الساكن: `run_tests.sh` SHA-256 `befd0b8066569479351ad38c88272ba2b8af26fcd3a61055e6029f3954d7a2ba` و`003_comparison.sql` SHA-256 `579259a851c8763b2da0038434bfc3805f8d8017e2badff47ff302bf0d7cf20b` — **مطابقان** قبل وبعد. لم يُشغَّل أي POC قديم ولم يُتصل بحاوياته (`daleel-pg-security-g2`, `daleel-pg-acceptance`, `daleel-pg-scratch`, `f06-poc01..04`, `*-closeout`, `*-gate`, `*-lastfix`).

---

## ج) الموارد الجديدة فقط (sandbox)

| المورد | القيمة |
|---|---|
| Container | `daleel-f06-laravel-i01-81792d2e-pg` (postgres:16)، الآن **Stopped** (ليس محذوفًا) |
| Network | `daleel-f06-laravel-i01-81792d2e-net` (bridge جديدة، خاصة بهذه الحاوية) |
| Volume | `daleel_f06_laravel_i01_81792d2e_pg_data` |
| Label | `com.daleel.purpose=f06-laravel-implement01` |
| منفذ منشور | `127.0.0.1:55450→5432/tcp` فقط (لا نشر عمومي؛ تم فحص عدم التعارض قبل الإنشاء) — مطلوب لأن اختبار HTTP نُفّذ من PHP على المضيف (Windows) لا من حاوية PHP داخل الشبكة؛ موثّق صراحة كاستثناء W1 المسموح. |
| `system_identifier` | `7700655491115700263` — جديد ومختلف عن كل الهويات الموثقة سابقًا (G2/acceptance/scratch/POC01-04). |
| HBA | تم **تشديده يدويًا** بعد الإنشاء: صورة postgres:16 الافتراضية تحتوي `host all all 127.0.0.1/32 trust` و`local all all trust`؛ استُبدلت بالكامل بـ`scram-sha-256` على كل الأسطر (local/host/replication)، ثم `pg_reload_conf()`. **لا trust نشط في الـsandbox.** |
| تنظيف | لا حذف لـvolume/container (يتطلب تفويضًا مستقلًا)؛ الحاوية متوقفة فقط لتقليل سطح التعرض عبر المنفذ. أسرار الاختبار (كلمات مرور الأدوار) محفوظة في ملف مؤقت ضيق الصلاحيات (`chmod 600`) خارج المستودع، لم تُطبع في أي stdout/تقرير. |

---

## د) ملفات API المعدّلة/المستحدثة

| الملف | الحالة | SHA-256 | الغرض |
|---|---|---|---|
| `config/database.php` | **MODIFY** | `790afdc57c8c0c628d1b2235dedc9892fa8a7c8649ff32c6a2f7f8dbdaae0fca` | إضافة اتصال `pgsql_f06_bootstrap` فقط (host/user/password كلها `env()` بلا قيمة افتراضية → fail-closed خارج sandbox مُهيّأة). لم يُعدَّل `pgsql_tenant_runtime` ولا أي اتصال آخر. |
| `config/f06_actor_sql.php` | **NEW** | `25ac450f0a2c3a177dd507efdef052c8abdd22e628552eb2e4963b9e31607217` | علم `enabled` (افتراضي false) + `allow_env` (افتراضي `testing` فقط) + خريطة كلمات مرور صناعية للاختبار. |
| `app/Modules/Identity/Http/Middleware/TenantStaffRequestContext.php` | **MODIFY** | `60c41e662cd71f02271674839b765a0f0cc7db462fa8a4807d2c27727d220fa0` | فرع `if ($this->f06Enabled())`؛ عند false يمر المسار القديم **دون أي تعديل في سلوكه**؛ عند true يستخدم `handleWithActorSqlIdentity()` الجديد. |
| `app/Modules/Identity/Application/TenantStaffContextGuard.php` | **MODIFY** | `7e6ca649a212563221c99fd310e851d72be99923ea12a9a9ce10255d209ac3ef` | استخراج `validateStoredShape()` (بدون SQL) من `activateFromSession()` القديمة، لإعادة استخدام نفس قاعدة التحقق في المسارين دون ازدواج منطق. `bindAndRevalidate()` و`activateFromSession()` القديمتان **لم يتغيّر سلوكهما**. |
| `app/Modules/Identity/Application/ActorConnectionFactory.php` | **NEW** | `aeab91fd914131cb83ac48381f7c4ef0291e7a2c8d1622d7d839cbea6a915d95` | التبديل الآمن لـ`pgsql_tenant_runtime` إلى دخول SQL خاص بالعضوية، مع رفض fail-closed عند `transactionLevel()>0`، تحقق `session_user` بعد كل تبديل، واستعادة غير مشروطة (`finally`). |
| `app/Modules/Identity/Application/ActorSqlIdentityResolver.php` | **NEW** | `a9f0569ce35d757210d7d036604655dc4c6e79cb18514d9f517d56cac1819baa` | مزوّد اعتماد اختبار فقط؛ يرفض العمل إن كان العلم OFF؛ لا fallback لأي اعتماد مشترك. |
| `app/Modules/Identity/Application/TrustedActorBootstrapVerifier.php` | **NEW** | `aee85465a2f818d431327442730e069b06ddd9d40f2672bd76eb4c1ed7d35903` | اتصال bootstrap مستقل (`pgsql_f06_bootstrap`) يستدعي دالة SECURITY DEFINER ضيقة في الـsandbox لإعادة التحقق من tenant/staff/membership دون لمس `pgsql_tenant_runtime`. |
| `tools/security/f06-laravel-i01/001_sandbox_fixture.sql` | **NEW** | `517f65a9dbb2e2b5c55cc4fcd2558bc98b254b2611a7f7e22eabc97118ec237e` | fixture SQL صناعية (SCOPED_EQUIVALENT)، ليست migration منتج. |
| `tools/security/f06-laravel-i01/middleware_wire_test.php` | **NEW** | `bf6566895d80d421ebba052525e6bd8f49e1969f4893954cc2d0037efc5352d2` | سكربت اختبار "سلك" مباشر للـmiddleware الحقيقي. |
| `tools/security/f06-laravel-i01/negative_controls_test.php` | **NEW** | `25d9444e4c94fbae9204ac2ef93f6fe56cadc13c1365d69b8809753370445add` | NC-01/02/03 على `ActorConnectionFactory`. |

**قيمة العلم الافتراضية: `F06_ACTOR_SQL_INTEGRATION_ENABLED` غير معرّف → `false`**. `FEATURE_FLAG_DEFAULT_OFF=true`.

أي ملف آخر (`LeadService.php`, `LeadController.php`, `routes/api.php`, migrations 001–038، أي ملف WEB/ADMIN/SUPER) — **لم يُعدَّل**؛ تم التحقق بـ`git diff --stat` بعد التنفيذ (لم يظهر في القائمة).

ملاحظة مسار حقيقية غير متوقعة: المسار الفعلي في المصدر هو `GET /api/v1/company/leads` (اسم الـroute: `api.v1.company.leads.index`)، **لا** `GET /api/v1/leads` كما ورد حرفيًا في نص PHASE PROMPT. تم التحقق من `routes/api.php:90` واستُخدم المسار الحقيقي في كل الاختبارات؛ هذا تصحيح واقعي لا اجتهاد.

---

## هـ) أدلة الاختبارات (IDs، النتائج، rc/SQLSTATE، ما أُعيد تشغيله بعد إصلاح)

### طبقة SQL (psql مباشر عبر منفذ TCP الجديد، SCRAM فعلي، لا `docker exec` محلي بعد تشديد HBA)

| ID | النتيجة | دليل |
|---|---|---|
| GATE-00-ENV | PASS | `system_identifier` جديد، شبكة/حاوية جديدتان، لا نشر عمومي، HBA بلا trust. |
| GATE-02-LOGIN-A1 | PASS | `SELECT session_user` = `daleel_f06i01_actor_a1` بعد SCRAM فعلي. |
| GATE-02-LOGIN-A2 | PASS | `session_user` = `daleel_f06i01_actor_a2`. |
| GATE-02-LOGIN-B1 | PASS | `session_user` = `daleel_f06i01_actor_b1`. |
| GATE-02-BOOTSTRAP-FN-ACTIVE | PASS | `f06i01_bootstrap_lookup(A1,...)` → 1 صف `daleel_f06i01_actor_a1` (session_user لا current_user، بعد تصحيح — انظر أدناه). |
| GATE-02-BOOTSTRAP-FN-SUSPENDED-A3 | PASS | نفس الاستدعاء لـA3 (موقوف + غير مُعرَّف في الخريطة) → 0 صفوف. |
| GATE-02-BOOTSTRAP-FN-VERSION-MISMATCH | PASS | `auth_version` خاطئ → 0 صفوف. |
| NC-05-CROSS-TENANT-LOOKUP | PASS | `tenant_id` خاطئ مع بيانات A1 → 0 صفوف. |
| GATE-04-BASELINE-A1 | PASS | A1 يرى صفّين من tenant A فقط. |
| GATE-04-BASELINE-B1 | PASS | B1 يرى صفًا واحدًا من tenant B فقط. |
| GATE-04-GUC-SPOOF-SELECT | PASS | A1 يضبط `app.tenant_id=B` ثم `SELECT` → لا يزال يرى صفّي tenant A فقط (RLS تتجاهل الـGUC). |
| GATE-04-CROSS-TENANT-UPDATE | PASS | `UPDATE ... WHERE tenant_id=B` تحت اعتماد A1 → `UPDATE 0`. |
| GATE-04-CROSS-TENANT-INSERT | PASS | `INSERT` بـ`tenant_id=B` تحت A1 → `ERROR: new row violates row-level security policy` (بعد منح عمود `id` — انظر الإصلاح أدناه). |
| GATE-04-LEGIT-INSERT | PASS | `INSERT` بـ`tenant_id=A` تحت A1 → ينجح (ضابط موجب). |
| GATE-05-ARBITRARY-SQL-READ | **OPEN (مُثبت)** | A2 (نطاق SELF تطبيقيًا) يقرأ صفّ A1 عبر SQL حر؛ RLS الحالية تحمي tenant فقط لا ASSIGNED/SELF. |
| GATE-05-ARBITRARY-SQL-UPDATE | **OPEN (مُثبت)** | A2 يُعدّل صفّ A1 مباشرة (`UPDATE 1`) — أُعيد الصفّ لحالته بعد التوثيق. |
| NC-02-WRONG-PASSWORD (SQL) | PASS | كلمة مرور خاطئة لـA1 → `FATAL: password authentication failed`. |
| NC-04-WEAK-POLICY-LEAKS | PASS (يثبت حساسية الهارنس) | تركيب سياسة GUC-based مؤقتًا → تسرّب صفّ tenant B لـA1؛ أُعيدت السياسة القوية فورًا وأُعيد التحقق أنها تمنع التسرّب. |

### طبقة PHP/Laravel (استدعاء مباشر حقيقي لـ`TenantStaffRequestContext::handle()`، Request/Session حقيقيان، اتصال PostgreSQL حقيقي عبر 127.0.0.1:55450)

شُغِّل `tools/security/f06-laravel-i01/middleware_wire_test.php` — **TOTAL=6 PASS=6 FAIL=0**:

| ID | النتيجة |
|---|---|
| GATE-03-GET-A1 | PASS — `status=200`, `session_user=daleel_f06i01_actor_a1`, صفّان. |
| GATE-06-LIFECYCLE-B1-AFTER-A1 | PASS — نفس عملية PHP، طلب B1 بعد A1 مباشرة؛ `session_user=daleel_f06i01_actor_b1`، صفّ واحد فقط من tenant B — **لا توريث اعتماد** بين الطلبين. |
| GATE-04-APP-NO-CROSS-TENANT-LEAK | PASS — استجابة B1 لا تحتوي أي `tenant_id` لـtenant A. |
| GATE-06-DENY-SUSPENDED-A3 | PASS — رُفض قبل أي SQL على بيانات (`AuthenticationException`)، لا fallback. |
| NC-05-HOST-TENANT-MISMATCH | PASS — جلسة تدّعي tenant A بينما الـHost يحلّ tenant B → رفض. |
| GATE-01-FLAG-OFF-TAKES-LEGACY-PATH | PASS — مع العلم OFF، المسار القديم يحاول القراءة من `public.tenants` (الاسم **الحقيقي** للمنتج، لا جدول الـsandbox)، فيفشل بـ`42P01 relation "public.tenants" does not exist` — **دليل أن العلم فعلاً يُحدّد المسار المنفَّذ**، لا مجرد قيمة لا تُستخدم. |

### NC-01/02/03 على `ActorConnectionFactory` مباشرة

شُغِّل `tools/security/f06-laravel-i01/negative_controls_test.php` مرتين: **قبل الإصلاح** (TOTAL=5 PASS=4 FAIL=1) و**بعد الإصلاح** (TOTAL=5 PASS=5 FAIL=0).

**علة حقيقية اكتُشفت وأُصلحت أثناء الاختبار (لا PASS أُعلن قبل الإصلاح):**
عند فشل الاتصال الفعلي (SQLSTATE 08006/28P01) داخل `switchTo()` — قبل حتى الوصول لفحص `session_user` — كان `Config::set()` يبقى عالقًا على اعتماد خاطئ/مكسور إلى ما لا نهاية (لا يُستعاد الأصل)، فيُعطَّل أي اتصال لاحق بنفس `pgsql_tenant_runtime` في نفس العملية. **الإصلاح:** لفّ استدعاء التحقق بـ`try/catch` واستدعاء استعادة غير مشروطة (`forceRestoreOriginalConfig()`) قبل إعادة رمي أي استثناء، وليس فقط عند mismatch في `session_user`. مُطبَّق في `ActorConnectionFactory.php` الحالي (الهاش أعلاه هو **بعد** الإصلاح).

| ID | النتيجة بعد الإصلاح | ملاحظة |
|---|---|---|
| NC-02a-MISSING-PASSWORD | PASS | رفض قبل أي اتصال PDO. |
| NC-02b-WRONG-PASSWORD | PASS | `password authentication failed`، لا fallback. |
| NC-02b-CONFIG-NOT-CORRUPTED | PASS | الإعدادات لم تبق عالقة بعد فشل الاتصال (هذا هو الإصلاح). |
| NC-01-SESSION-USER-MISMATCH | PASS (مع ملاحظة بنيوية) | السيناريو كما صُمّم (استخدام كلمة مرور B1 مع اسم دور A1) يُرفض من PostgreSQL نفسه عند طبقة المصادقة (`password authentication failed`) **قبل** الوصول لفحص `session_user` التطبيقي؛ أي أن نموذج "اعتماد SCRAM حقيقي مستقل لكل دور" يمنع بنيويًا تنفيذ NC-01 الحرفي (تبديل هوية دون كلمة مرور صحيحة لا يمكن أصلاً أن ينجح في PDO ليصل لفحصنا). فحص `session_user` التطبيقي يبقى كخط دفاع ثانٍ موجود في الكود وصحيح منطقيًا، لكنه لم يُمارَس بسيناريو مُنفَّذ فعليًا هنا — `NC-01 = PASS_STRUCTURAL_NOT_EXERCISED`، موثَّق بصدق لا كـPASS كامل. |
| NC-03-PURGE-DURING-OPEN-TX | PASS | `LogicException` فوري، لا purge، لا فقدان معاملة. |

### ما لم يُنفَّذ (NOT_EXECUTED، بصدق)

- **GATE-07/AUTH_WIRE** الكامل (تسجيل دخول حقيقي + كوكي جلسة + CSRF + `auth:tenant_staff` guard الحقيقي عبر `artisan serve`/HTTP socket فعلي).
- **GATE-05 ALL_TENANT write عبر `LeadService::assignLead()` الحقيقية** (تم فقط إثبات القراءة/الكتابة الخام SQL، لا مسار الخدمة PHP لإعادة الإسناد).
- إعادة تشغيل الـ51/51 HTTP أو 29/29 PHPUnit التاريخية (تبقى `DOCUMENTED_PRIOR`).
- اختبار `migrations 001–038` الحقيقية على الـsandbox (استُخدم fixture مكافئ بدلًا من ذلك — `SCHEMA_FIDELITY=SCOPED_EQUIVALENT`).

---

## و) دليل الاتصال الحقيقي (HTTP/SQL) — ملخص غير-مُخَمَّن

- Hostname: `tenant-a.sandbox.local` / `tenant-b.sandbox.local` (صناعي، `TenantHostContext` يُبنى يدويًا في سكربت الاختبار — **لم يُختبر** `TenantHostResolver` الحقيقي الذي يقرأ من DB عبر `pgsql_hostname_resolver`؛ هذا جزء من فجوة GATE-07).
- Route/Method: `GET /api/v1/company/leads` (الاسم الحقيقي، انظر قسم د).
- Session: `Illuminate\Session\Store` حقيقي بـ`ArraySessionHandler`، مفتاح `identity.tenant_staff` بنفس الشكل الذي يكتبه `TenantStaffAuthController` الحقيقي.
- SQL `session_user` المقاس: `daleel_f06i01_actor_a1` / `daleel_f06i01_actor_b1` (قياس فعلي عبر `SELECT session_user`، لا افتراض).
- RLS metadata: `pg_policies` يُظهر سياسة واحدة `f06i01_leads_tenant_boundary` على `f06i01_leads`، `FORCE ROW LEVEL SECURITY`، معرَّفة بدالة `f06i01_actor_tenant_id()` (`SECURITY DEFINER`، `search_path=public`).
- `ON_WIRE_AUTH_METHOD`: **NOT_VERIFIED** — لم يُقَس عبر فحص بروتوكول مستقل (tcpdump/wireshark)؛ الاعتماد هو على `pg_hba.conf`+`password_encryption=scram-sha-256` فقط.

---

## ز) ثلاث طبقات قرار مستقلة

- `TENANT_RLS_SQL_INJECTION_BOUNDARY` = **PASS** — RLS حقيقية مبنية على `session_user`، لا GUC، مُثبتة بثلاث هجمات (SELECT مع GUC مزيّف، UPDATE مباشر، INSERT مباشر) + ضابط NC-04 يثبت حساسية الهارنس.
- `SAME_TENANT_ACTOR_SCOPE_SQL_INJECTION` = **OPEN** — مُثبت صراحة أن actor بنطاق SELF تطبيقيًا يستطيع قراءة/تعديل بيانات زميله في نفس الشركة عبر SQL حر (GATE-05). لا ادّعاء حماية هنا.
- `APP_HTTP_LEADS_SCOPE` = **PASS_SCOPED** — على مستوى استجابة HTTP المُختبرة (direct middleware)، لا تسرّب عبر الشركات؛ لم يُختبر نطاق ALL_TENANT/ASSIGNED/SELF الكامل عبر `LeadController`/`LeadService` الحقيقيين في هذه الجولة (النطاق المُختبر هو استعلام SQL مباشر داخل الإغلاق البديل لـ`$next`، لا استدعاء `LeadService::listLeads()` الفعلي).

F06 **لا يزال مفتوحًا جزئيًا**: الحدود بين الشركات (tenant) أصبحت الآن قائمة على هوية SQL حقيقية غير قابلة للتزوير عبر GUC، لكن الحدود **داخل** الشركة (ALL_TENANT/ASSIGNED/SELF) لا تزال تطبيقية بحتة (WHERE في PHP) وقابلة للتجاوز عبر أي قناة SQL حرة تحت نفس اعتماد actor — تمامًا كما حذّر PHASE PROMPT.

---

## ح) فحوص محدّدة

| البند | النتيجة |
|---|---|
| `GUC_SPOOF` | PASS — RLS تتجاهل `app.tenant_id` المُزيَّف تمامًا. |
| `SET_ROLE` | غير مُستخدم في أي مكان من التنفيذ؛ التبديل عبر LOGIN/PDO حقيقي فقط. |
| `PDO_PURGE_BEFORE_TX` | PASS — `switchTo()` يرفض إن `transactionLevel()>0` (NC-03). |
| `SESSION_REUSE` | PASS — A1 ثم B1 في نفس عملية PHP بلا توريث (GATE-06). |
| `SERVER_CONN_CLEANUP` | PASS — `finally { $factory->reset(); }` غير مشروط؛ مُثبت ضمنيًا بنجاح الطلبات المتتالية في نفس العملية. |
| `CREDENTIAL_EXPOSURE` | لا كلمة مرور ظهرت في stdout/تقرير/Git. الأسرار في ملف مؤقت `chmod 600` خارج المستودع. |
| `T4b/F16` | **خارج النطاق، لم يُلمَسا**؛ `TenantHostResolver` الحقيقي لم يُختبر في هذه الجولة. |
| `SCHEMA_FIDELITY` | `SCOPED_EQUIVALENT` — fixture صناعية، ليست migrations 001–038. |
| `POC_REFERENCE_NOT_TOUCHED` | PASS — الهاشات مطابقة قبل/بعد (قسم ب). |
| `PROTECTED_DB_NOT_ACCESSED` | PASS — لا اتصال بأي من G2/acceptance/scratch/POC01-04/closeout/gate/lastfix؛ كل الاتصالات كانت فقط إلى `127.0.0.1:55450` (sandbox جديدة). |

---

## ط) Delta/Impact Review

- **API contracts**: لا تغيير على شكل استجابة `GET /api/v1/company/leads` (العلم OFF افتراضيًا، ولا تغيير في بنية الاستجابة عند ON في هذه الجولة).
- **RBAC/RLS/ACL**: لا تغيير على مخطط المنتج؛ كل الأدوار/السياسات الجديدة محصورة في قاعدة sandbox منفصلة.
- **Dependencies**: لا package جديد، لا تعديل vendor/framework.
- **DB migrations**: صفر migrations جديدة على أي قاعدة؛ migration 039 **لم تُنشأ ولم تُشغَّل**.
- **Auth flows**: مسار تسجيل الدخول الحقيقي **لم يُمسّ ولم يُختبر** في هذه الجولة (خارج GATE-07).
- **Tests**: 3 سكربتات PHP جديدة (ليست PHPUnit رسمية، تعمل مباشرة عبر `php -d extension=pdo_pgsql`) + fixture SQL، كلها تحت `tools/security/f06-laravel-i01/`، مستقلة تمامًا عن POCs السابقة.
- **Git**: صفر commits، صفر staged، فقط ملفات جديدة/معدّلة في working tree لمستودع API وحده.
- **Debt/Risks**: `PHP_MULTI_CREDENTIAL_COMPROMISE_RISK=OPEN` (لم يُعالَج ولا يمكن أن تعالجه هذه الشريحة بطبيعتها)؛ `ACTOR_SCOPE_ARBITRARY_SQL=OPEN` (مُثبت، قسم GATE-05)؛ اعتماد الـsandbox على HBA مُشدَّد **يدويًا بعد الإنشاء** (صورة postgres:16 الافتراضية غير آمنة بذاتها) — يجب أن تتضمن أي شريحة لاحقة توليد `pg_hba.conf` مُشدَّد **من البداية**، لا تعديله بعديًا.
- **Rollback plan**: تعطيل `F06_ACTOR_SQL_INTEGRATION_ENABLED` (غير معرَّف أصلًا في أي بيئة إنتاج) يُعيد المسار القديم بالكامل، **على الـsandbox فقط**؛ هذا ليس دليل أمان لأي بيئة أخرى.
- إقرار صريح: المشروع **لم يصل إلى Customers/Production** بهذه الشريحة ولا يقترب من ذلك.

---

## ي) GO/NO-GO والخطوة التالية

**`NEXT_GATE` المقترحة الوحيدة**: إغلاق فجوة GATE-07 (AUTH_WIRE كامل عبر HTTP socket حقيقي + CSRF + `auth:tenant_staff`) **ثم** اختبار `LeadService`/`LeadController` الحقيقيين (لا استعلام SQL مباشر بديل) تحت الاتصال المبدَّل — قبل أي حديث عن معالجة `ACTOR_SCOPE_ARBITRARY_SQL=OPEN` أو توسيع نطاق الأدوار. لا طلب لـPOC جديد ولا لتصميم جديد؛ هذه استكمال تنفيذي مباشر لنفس الشريحة.

---

## الأعلام الإلزامية

```
W0_PRECHECK = PASS_VERIFIED_LIVE
GIT_5_REPOS_BASELINE = MATCHED_EXACTLY (ROOT c2ee5a3a..., API e8cee07c..., WEB 6fb01b88..., ADMIN 9fa43bef..., SUPER a802e44b...)
POC_REFERENCE_HASHES = MATCHED (run_tests.sh=befd0b80..., 003_comparison.sql=579259a8...)
NEW_SANDBOX_ONLY = TRUE
POSTGRES_SYSTEM_IDENTIFIER = 7700655491115700263 (NEW_DISTINCT)
REAL_LARAVEL_HTTP_WIRE = PARTIAL (direct middleware invocation with real Request/Session/PostgreSQL; NOT a full artisan-serve/HTTP-socket/cookie-jar path; GATE-07 NOT_EXECUTED)
ACTOR_LOGIN_SESSION_USER = PASS (session_user measured distinct per actor via real SCRAM: a1/a2/b1)
BOOTSTRAP_READONLY_TRUST = PASS (dedicated pgsql_f06_bootstrap connection, SECURITY DEFINER narrow function, no table grants to bootstrap client)
TRANSACTION_CONNECTION_ORDER = PASS (switchTo always runs before beginTransaction in the ON path; verified)
FEATURE_FLAG_DEFAULT_OFF = TRUE
GET_LEADS_API_CONTRACT = PASS_SCOPED (direct middleware call only; real route path is /api/v1/company/leads, not /api/v1/leads as literally named in the phase prompt)
TENANT_RLS_SQL_INJECTION_BOUNDARY = PASS
APP_HTTP_LEADS_SCOPE = PASS_SCOPED
SAME_TENANT_ACTOR_SCOPE_SQL_INJECTION = OPEN (proven, not mitigated in this slice)
GUC_SPOOF = PASS (RLS ignores spoofed app.tenant_id)
SET_ROLE = NOT_USED
PDO_PURGE_NO_OPEN_TRANSACTION = PASS (NC-03)
SAME_WORKER_SESSION_ISOLATION = PASS (A1 then B1 same PHP process, no credential bleed)
NEGATIVE_CONTROLS = PASS_4_OF_5 (NC-01 structurally not exercised as literally specified -- see section هـ; NC-02/03/04/05 fully exercised and PASS)
AUTH_CREDENTIALS_SYNTHETIC_ONLY = TRUE
SCHEMA_FIDELITY = SCOPED_EQUIVALENT
LARAVEL_CONNECTION_POOLING = NOT_FOUND_IN_SCANNED_SCOPE (no Octane/Horizon/queue jobs/PgBouncer found; not re-verified this round beyond prior design-doc finding)
PHP_MULTI_CREDENTIAL_COMPROMISE_RISK = OPEN
T4B_REMEDIATION = NOT_PERFORMED
F16_REMEDIATION = NOT_PERFORMED
MIGRATION_039 = NOT_CREATED_NOT_RUN
G2_RM02_DEV_PROTECTION = PASS (no connection, no docker exec/psql/pg_dump/pg_ctl on any protected resource)
ROOT_DOCS_PRESERVED = PASS (HANDOFF-CURRENT.md, WORK-LEDGER.md, EVIDENCE-REGISTER.md unchanged, still the same pre-existing M)
OTHER_GIT_REPOS_UNCHANGED = PASS (WEB/ADMIN/SUPER HEAD and status identical to baseline)
GIT_COMMIT = NOT_EXECUTED
F06_PRODUCT_REMEDIATION = NOT_PERFORMED
CUSTOMERS = NO_GO
PRODUCTION = NO_GO
NEXT_GATE = GATE-07_AUTH_WIRE_THEN_REAL_LEADSERVICE_CALL
```

</div>
