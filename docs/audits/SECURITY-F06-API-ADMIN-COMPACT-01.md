# SECURITY-F06-API-ADMIN-COMPACT-01 — تقرير التنفيذ المحدود

التاريخ: 2026-10-26. القبعة: Backend engineer + QA/Security reviewer + Docs/handoff keeper. مصدر الإثبات في هذه الجولة: source/SQL catalog/rollback SQL/Laravel HTTPS حقيقي، كلٌّ بحده. **EXECUTIVE_VERDICT=PARTIAL_SAFE_DELTA**. آخر بوابة مكتملة: G4-A وG5 الخاصتان بنطاق GET الإداري والمنح/السحب المباشر `leads.view:SELF` فقط. توقف توسيع G4-B/C/D لأن العمليات تتطلب عقود SQL definer منفصلة وتغطية race/invariant وprovisioning؛ لم يُنشأ مسار كتابة عام.

## W0 — خط الأساس والاستعادة

اكتُشفت نقطة A5 في `I:\WORK\DALEEL-CRM-RECOVERY\SECURITY-F06-A5-RECOVERY-01-20261026T185231-74a4a42d`، وفُحص manifest SHA-256 `180e4ccea0bba06b30a6853cadad628ed33ec9ae2cbec0a96fc414e63ad356c5` مع payload `122/122` و`995078` بايت ومسارات فريدة. تقرير المراجعة الأصلية داخلها SHA-256 `2cbc550bda1c6bebda851e51a775a8d44dc9fbb54dce70be45c7445408cca7d1`. لم تُستعد هذه النقطة ولم تُكتب عليها؛ تقع على محرك I نفسه وتعتمد على Git HEAD.

| المستودع | HEAD قبل/بعد | حالة الجولة |
|---|---|---|
| ROOT | `c2ee5a3a3e128f86147e06d39cd50ca7ff2cf7d9` | 4 tracked M سابقة؛ لم تُلمس؛ staged=0 |
| API | `e8cee07c2c39df5a1531cbd63168695347202371` | 5 tracked M سابقة عند W0، أصبحت 6 بإضافة `ApiErrorResponse.php`؛ untracked السابقة بقيت مع ملفات هذه الجولة؛ staged=0 |
| WEB | `6fb01b8838de52de621dab4691a5cdd5710c29f6` | نظيف |
| ADMIN | `9fa43befadaaa5d4583f8de6bf7a06c60e891bef` | نظيف |
| SUPER | `a802e44b8a269071bcb46fcaa675aafb43b12a87` | نظيف |

بصمة `CLAUDE.md` بقيت `a972f9ef6f3e9959bb86687d7ffa9eae096ce9d78c1d3d515cc66e2191e8487a`، و`config/f06_actor_sql.php` بقيت `30aa43295aec9f0768021a2f48277294f850bcc5f80b08b0cce2ba2cd55f4140`. ملفات ROOT/WEB/ADMIN/SUPER لم تُكتب. لا commit/push/reset/checkout/stage.

## G1 — العقود وحدود الملفات

المصفوفة المفصلة في `tools/security/f06-api-admin-compact-01/CONTRACT_MATRIX.md` والـallowlist المقفلة في `ALLOWLIST.md`. عقد المصدر: Host يحدد tenant، والجلسة الموثقة تحدد الموظف؛ under ON ينتقل الاتصال إلى SQL LOGIN الخاص بالـActor، بينما OFF يستخدم runtime المشترك. A5 في fixture لديه `member.manage/member.view/role.manage/role.view` و`leads.view:SELF`، ولا يملك تفويض `company.administer` أو `ALL_TENANT`. A0 مرساة invariant خامدة. العضو المنشأ حديثًا لا يملك دورة provisioning لمطابقة SQL Actor؛ لذلك G4-D محجوبة تعاقديًا.

اختيرت استثناءات typed في مواضع الجاهزية المحددة، ووظيفة `SECURITY DEFINER` ضيقة للمنح/السحب السابقة داخل Sandbox. حساب Actor لا يملك DML مباشرًا على جداول authority. البديل بخدمة عامة ذات صلاحيات كتابة أو دالة SQL عامة يوسّع السلطة خارج عقد F06. لا migration 039 ولا تغيير routes/config؛ وظائف SQL هنا overlays اصطناعية فقط.

## G2 — تصنيف الخطأ وHTTP

التعديل المصدرّي: `ActorConnectionFactory.php` يميز `MISSING_CREDENTIAL` و`UNMAPPED_ACTOR` قبل اتصال Actor، و`IDENTITY_MISMATCH` بعد فحص `session_user`؛ `ActorSqlUnavailableException.php` نوع صغير برسالة داخلية عامة؛ `ApiErrorResponse.php` يعيد `503/ACTOR_SQL_UNAVAILABLE` برسالة عامة ويسجل reason وrequest_id فقط؛ `LeadService.php` يصنف `42883` في استدعاء `f06scope_assign_lead` تحت ON؛ `TenantStaffRoleMutationService.php` يصنف `42883` في `f06team01_direct_permission` تحت ON. OFF وسائر استثناءات mapper محفوظة. `php -l` نجح في الملفات الستة، و`g2_source_gate.php` أثبت ثلاث حالات، و`git diff --check` نجح.

| الحالة | هوية الجلسة/المسار | النتيجة الحقيقية | عدم الأثر |
|---|---|---|---|
| E1 اعتماد A5 مفقود | A5 POST grant | `503/ACTOR_SQL_UNAVAILABLE`، reason داخلي `MISSING_CREDENTIAL` | بصمة authority+Leads ثابتة |
| E2 اعتماد A4 مفقود | A4 GET Lead | `503/ACTOR_SQL_UNAVAILABLE`، reason `MISSING_CREDENTIAL` | ثابتة |
| E4 direct function غائبة | A5 POST grant قبل overlay 050 | `503/ACTOR_SQL_UNAVAILABLE`، reason `MISSING_FUNCTION` | ثابتة |
| E4 assign function غائبة | A1 PATCH assign في DB clone | `503/ACTOR_SQL_UNAVAILABLE`، reason `MISSING_FUNCTION` | بصمة clone ثابتة؛ أصل الوظيفة لم يُمس |
| E3 mapping مجهول | A5 GET staff في DB clone بعد تغيير mapping الاصطناعي | `503/ACTOR_SQL_UNAVAILABLE`، reason `UNMAPPED_ACTOR` | بصمة clone بعد التحضير ثابتة |

فاحص HTTP راجع مفاتيح `error/meta`، الكود، النص العام، SHA-256 للـbody، ومنع كلمات المرور وSQLSTATE/SQL/function names/stack من الاستجابة. raw wire/logs والأسرار التجريبية بقيت خارج المستودع في temp المذكور في فهرس الأدلة. guest وHost خاطئ أعادا 401، وCSRF المفقود 419، ورفض التفويض المعتاد 403؛ OFF grant/revoke أعادا 201/200. فحص الـlogs دون نشر محتواها أكد reason لكل حالة. فشل service/network أو SQL bug غير المصنف لم يُختبر، ولا يُنسب إلى هذا الـ503. `23503`/`23505` لم تُثبتا كعقد عام؛ تكرار grant المحظور أعاد 403 في المسار الضيق.

## G3 — Sandbox جديدة

الحاوية `daleel-f06-compact01-44e1ef49-pg` تحمل label `control=SECURITY-F06-API-ADMIN-COMPACT-01` و`purpose=synthetic-only`، Docker image `postgres:16`، port `127.0.0.1:55481`، database الأصلية `daleel_f06compact01`، system ID `7701014410365292590`، network/volume باسم الجولة. أنشئت بـ`POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=scram-sha-256`؛ HBA الفعلي SCRAM فقط، كلمة مرور خاطئة rc=2، صحيحة PASS. تطبيق migration حقيقي `38/38` دون إضافة أو تشغيل 039، ثم fixture وoverlays `010/020/030/040/045`؛ overlay `050` أضيفت بعد اختبار غيابها. نسخة `daleel_f06compact01_e4clone` خصصت لاختبارات E3/E4، ولم تُستخدم بوصفها baseline الأصلية.

الـcatalog النهائي في `final_catalog_evidence.json`: 9 سياسات Leads، 3 triggers مستخدم مفعلة للجداول المراقبة، `FORCE RLS` على Leads وعضوية/منح الموظفين، وإغلاق عضويات Actor المباشرة والانتقالية بـ`SET FALSE`، و`PUBLIC CREATE` على schema public = false. مالكا دالتي assign/direct هما NOLOGIN/NOBYPASSRLS/NOSUPER؛ الدالتان SECURITY DEFINER و`PUBLIC EXECUTE=false` وsearch_path `pg_catalog, public, pg_temp`. A5 لا يملك INSERT/UPDATE/DELETE مباشرًا على roles/role_permissions/grants ولا UPDATE على membership ولا INSERT على audit؛ EXECUTE للدالة عبر المجموعة فقط، وتفويضها الداخلي يفحص السلطة. SQL scope `31/31` أثبت أيضًا رفض `SET ROLE` القديم وقراءة cross tenant/التلاعب GUC. حاويات الجولات السابقة لم تُشغل أو تُعدل.

توقفت خدمة Docker Desktop أثناء الجولة بعد G2b؛ فشل deploy 050 قبل أي SQL. أُعيد تشغيل Desktop والحاوية المملوكة فقط، ثم أُعيد إثبات label/system ID/migrations/غياب 050 قبل تطبيقه. سجل المحاولة في `ATTEMPT-LEDGER.md`.

## G4 — مصفوفة الإدارة

الجدول يفصل HTTP المثبت عن المصدر. `request_id=NULL` و`metadata={}` في audit المنح/السحب يطابقان العقد السابق، مع ضعف correlation مفتوح. صفوف المنح/version/audit عادت إلى baseline بعد كل جولة OFF/ON.

| العملية | HTTP OFF | HTTP ON | SQL/business/audit/version | الحكم |
|---|---|---|---|---|
| GET `/roles` بواسطة A5 | 200 و`data.roles` غير فارغ | 200 ونفس الشكل | read فقط؛ لا mutation | PASS_SCOPED |
| GET `/staff` بواسطة A5 | 200 و`data` غير فارغ | 200 ونفس الشكل | read فقط | PASS_SCOPED |
| POST direct `leads.view:SELF` إلى A4 | 201 | 201 | grant واحد، `authorization_version +1`، event واحد؛ SQL rollback موجب | PASS_SCOPED |
| DELETE direct `leads.view:SELF` من A4 | 200 | 200 | revoke واحد، version +1، event واحد؛ fingerprint مستعاد | PASS_SCOPED |
| تكرار/self/nondelegable/overscope/B/suspended/A1/A2/A4/B1 | 403 كما في evidence | 403 كما في evidence | بلا زيادة business/version/audit | PASS_SCOPED |
| POST/PATCH/DELETE `/roles` | NOT_EXECUTED | NOT_EXECUTED | يلزم SQL definer وعقد invariant مستقل | OPEN |
| POST `/staff/{membership}/roles` وDELETE المقابل | NOT_EXECUTED | NOT_EXECUTED | يلزم عقد assign/revoke مؤهل وrace controls | OPEN |
| POST `/staff/{membership}/disable` و`reactivate` | NOT_EXECUTED | NOT_EXECUTED | يلزم lifecycle/last-admin/invalidation | OPEN |
| POST `/staff` | NOT_EXECUTED | NOT_EXECUTED | Actor SQL mapping/provisioning للعضو الجديد خارج النطاق | BLOCKED_SCOPE_DEPENDENCY |
| منح مباشر عام خارج `leads.view:SELF` | NOT_EXECUTED | NOT_EXECUTED | A5 غير مفوض لباقي النطاقات؛ fixture لا يبرر الادعاء | OPEN |

ملف `http_admin_evidence.json` يسجل 38 حالة OFF/ON، منها 4 عمليات GET جديدة، إضافة إلى تحقق مستقل من A1 GET Leads=200 عند غياب اعتماد A5. لا يُستنتج من العدد تكافؤ باقي endpoints.

## G5 — الأمن والانحدار

| ID | الدليل | الحكم |
|---|---|---|
| SEC01 | A1/A2/A4/A5/B1 وmapping مجهول؛ recursive membership catalog وSET FALSE؛ SQL رفض SET ROLE القديم/المجموعة/A1 | PASS_SCOPED؛ جميع سلاسل الهوية الأخرى غير مفحوصة |
| SEC02 | catalog يمنع DML لـA5 على 5 جداول authority المختارة؛ SQL actor A4 لا يستطيع صنع grant؛ definer موجب grant/revoke | PARTIAL؛ لم تُجرب كل عملية DML لكل Actor وكل جدول مطلوب |
| SEC03 | HTTP وSQL يرفضان self وcompany.administer وover-scope وB وsuspended وnon-manager، بلا version/audit إضافي | PARTIAL؛ TEAM/NONE/disabled permission لم تُختبر |
| SEC04 | SQL GUC spoof/tenant B وSET ROLE مرفوضة؛ PUBLIC CREATE/EXECUTE=false؛ مالكا definer NOLOGIN/NOBYPASSRLS | PARTIAL؛ Host selector وowner escape الكامل غير مثبتين |
| SEC05 | 38 HTTP OFF/ON لـGET roles/staff وdirect grant/revoke الضيق، مع row/version/audit و401/403/419 | PARTIAL؛ POST/PATCH/DELETE roles وباقي staff غير منفذة |
| SEC06 | خمسة طلبات 503 حقيقية: A5/A4 credential، دالتا SQL، mapping مجهول؛ body checker وlog reasons؛ A1 موجب مستقل | PASS_SCOPED |
| SEC07 | `sql_scope_evidence.json`: 31/31، A1/A2/A4/B1، SELECT/JOIN/UPDATE/INSERT/DELETE/assign وGUC/SET ROLE | PARTIAL؛ archive HTTP وmixed ASSIGNED+SELF غير منفذين |
| SEC08 | revocation بعد COMMIT وsame-worker/parallel transactions غير مثبتة | NOT_VERIFIED |
| SEC09 | policy/ACL mutation كشفا 2/2 داخل rollback؛ استعيد catalog/baseline ثم أُعيدت SQL scope 31/31 وG5 SQL 6/6 وfinal fingerprint | PASS_SCOPED |
| SEC10 | replay تاريخي 51 HTTP/11 Kernel/29 PHPUnit لم يُشغّل لأن target/RefreshDatabase غير مأمونين وفق العقد؛ PHP `8.6.0RC3`، Node `v24.22.1`، Docker Server `29.9.2` | BLOCKED_UNSAFE_OR_UNMAPPED_TARGET |
| SEC11 | فاحص body/token/SQL/stack للخمسة 503 وshape، تسجيل reason داخلي منقح، فحص أسرار ملفات الدليل = 0 تطابق | PASS_SCOPED |
| SEC12 | same-worker reuse وgrant/revoke double-submit/race مع disable غير مثبتة | NOT_VERIFIED |

البصمة الحتمية لجميع جداول authority المحددة وLeads كانت `f89318f94ce52837ab4556e2d406449b` قبل المحاولات وبعدها؛ `final_catalog.py` راجعها والـpolicies/triggers/ACL. عدم تغيير البصمة لا يثبت replay تاريخيًا أو لحظية إبطال الجلسة. PHP multi credential boundary، T4b/F16، FK oracle، mixed scopes، concurrency والتأثير على query planner OPEN. لم تُضف indexes؛ لا قياسات أداء منشورة.

## G6 — الدلتا والأثر والقرار

`DELTA-SHA256.tsv` يحوي preimage/postimage للملفات المصدرية والملفات الجديدة؛ الملفان المعدلان قبل الجولة (`LeadService.php` و`TenantStaffRoleMutationService.php`) فُصلا عن إضافات هذه الجولة. `ApiErrorResponse.php` كان tracked نظيفًا ثم تعدل. `ActorConnectionFactory.php` كان untracked سابقًا؛ class الجديد والتقرير والأدوات جديدة. SHA المحمي لـ`CLAUDE.md` و`config/f06_actor_sql.php` ثابت. `git diff --check` وlint وفاحص G2 مصدر PASS. لا تعديل API route/OpenAPI contract؛ تغير خطأ الجاهزية المحدد من 500 عام إلى 503 عام مع code مخصص، وقد يحتاج client SDK لاحقًا إلى معالجة 503. 401/403/419/201/200 الضيقة لم تتغير في الفحوص. الوظائف SQL الاصطناعية غير منشورة في migrations المنتج؛ `DEPLOYMENT_NOT_READY` حتى تصميم ونشر مرخصين مع اختبار مستقل.

القرار: قبول **جزئي قابل للمراجعة** لـG2 وG4-A الضيق، ثم مراجعة مستقلة للدلتا قبل أي checkpoint جديد. `NEXT_GATE=INDEPENDENT_REVIEW_THEN_SEPARATE_G4_B_CONTRACT`، مع تصميم وظائف roles لكل عملية وSQL/HTTP/race/last-admin، ثم G4-C ببوابة منفصلة؛ G4-D يحتاج قرار provisioning. لا رفع علم F06 أو العملاء أو الإنتاج. لا checkpoint جديد أنشئ في هذه الجولة.

## الأعلام الختامية الملزمة

| العلم | القيمة |
|---|---|
| W0_FIVE_REPO_BASELINE | PASS |
| A5_RECOVERY_MANIFEST_SHA_VERIFIED | YES |
| A5_RECOVERY_PAYLOAD_122_OF_122 | YES |
| OWNER_APPROVED_CLAUDE_UNTOUCHED | YES |
| G1_ADMIN_SOURCE_CONTRACT_MATRIX | PASS |
| SOURCE_FILE_ALLOWLIST_LOCKED | YES |
| G2_MISSING_ACTOR_A5_FAIL_CLOSED_HTTP_CLASSIFIED | PASS |
| G2_MISSING_ACTOR_A4_FAIL_CLOSED_HTTP_CLASSIFIED | PASS |
| G2_MISSING_SQL_FUNCTION_FAIL_CLOSED_HTTP_CLASSIFIED | PASS_BOTH_FUNCTIONS |
| G2_INVALID_MAPPING_DISTINGUISHED | PASS_SOURCE_AND_CLONE_HTTP |
| G2_OFF_LEGACY_PARITY | PASS_SCOPED |
| G3_FRESH_SANDBOX_OWNED_SYSTEM_ID | PASS |
| G3_SCRAM_FROM_INITDB | PASS |
| G3_REAL_MIGRATIONS_38_OF_38 | PASS |
| G3_ROLE_MEMBERSHIP_SET_FALSE_CLOSURE | PASS_SCOPED_RECURSIVE_CATALOG |
| G3_FUNCTION_SCHEMA_TRUST_CATALOG | PASS_SCOPED |
| G4_ADMIN_ROLES_CREATE_UPDATE_ARCHIVE_PARITY | NOT_EXECUTED |
| G4_STAFF_CREATE_PARITY | BLOCKED_SCOPE_DEPENDENCY |
| G4_STAFF_DISABLE_REACTIVATE_PARITY | NOT_EXECUTED |
| G4_STAFF_ROLE_ASSIGN_REVOKE_PARITY | NOT_EXECUTED |
| G4_DIRECT_PERMISSION_GENERAL_PARITY | NOT_VERIFIED_GENERAL; PASS_NARROW_SELF |
| G4_PREVIOUS_A5_NARROW_GRANT_REVOKE_REGRESSION | PASS_SCOPED_OFF_ON |
| G5_ACTOR_AUTHZ_SOURCE_IMMUTABLE | PASS_SCOPED_CATALOG_AND_MUTATIONS |
| G5_SELF_AND_INDIRECT_ESCALATION_DENIED | PARTIAL_SELF_AND_NONDELEGABLE_TESTED |
| G5_TENANT_AND_GUC_SPOOF_DENIED | PASS_SCOPED_SQL_HTTP |
| G5_LEADS_ACTOR_SCOPE_REGRESSION | PASS_SCOPED_31_OF_31 |
| G5_NEGATIVE_MUTATION_CONTROLS | PASS_2_OF_2 |
| G5_AUDIT_VERSION_INVARIANT_ATOMIC | PASS_A5_NARROW_ONLY |
| G5_HTTP_SAME_WORKER_REUSE | NOT_VERIFIED |
| G5_HISTORICAL_SUITES_REPLAY | BLOCKED_NOT_EXECUTED |
| FINAL_DB_FINGERPRINT_AND_TRIGGER_CATALOG | PASS_BASELINE_RESTORED |
| SOURCE_GIT_WRITES | NONE |
| MIGRATION_039 | NOT_AUTHORIZED_NOT_CHANGED |
| NEW_CHECKPOINT | NO |
| PHP_MULTI_CREDENTIAL_RISK | OPEN |
| T4B | OPEN |
| F16 | OPEN |
| F06_PRODUCT_CLOSED | NO |
| CUSTOMERS | NO_GO |
| PRODUCTION | NO_GO |
| EXECUTIVE_VERDICT | PARTIAL_SAFE_DELTA |
| NEXT_GATE | INDEPENDENT_REVIEW_THEN_SEPARATE_G4_B_CONTRACT |

`PRODUCT_ROLE_PROVISIONING=NOT_IMPLEMENTED`. التقرير لا يجيز staging أو تعديل DB محمية أو بدء G4-B تلقائيًا. الأدلة والـattempt ledger في `tools/security/f06-api-admin-compact-01/`، والحاوية المملوكة أُوقفت بعد إثبات البصمة النهائية مع إبقاء network/volume دون حذف.
