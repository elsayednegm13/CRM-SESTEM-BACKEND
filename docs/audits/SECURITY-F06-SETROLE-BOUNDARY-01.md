# SECURITY-F06-SETROLE-BOUNDARY-01 — تقرير الإثبات والعلاج المحدود

**تاريخ التنفيذ:** 2026-10-25 (UTC، وقت الجولة). **الدور:** Codex — مراجعة أمنية وتنفيذ sandbox محدود.  
**EXECUTIVE_VERDICT = PASS_BOUNDARY_SCOPED.** ثبت تسرب قراءة وكتابة عابر للشركات تحت اعتماد SQL صناعي لـA1 في PostgreSQL 16، ثم رُفض المسار نفسه بعد تعديل عضوية actors الثلاثة في fixture I02 وحدها. الحكم مقصور على حد SQL في sandbox؛ `HTTP_SMOKE=NOT_EXECUTED`، ولا يعني إغلاق F06 المنتج.

## 1. التفويض وW0

قُرئت نقطة الدخول وبروتوكول DEIP والذاكرة والتسليم والسجل والأدلة والقرارات وتقارير التصميم وIMPLEMENT-01/02. التفويض الحالي يعلو القيود التاريخية في تلك الملفات بمقدار نطاقه فقط. قبل أي كتابة طابقت Git رؤوس الفروع الخمسة التالية، بلا ملفات staged:

| Repo | Branch | HEAD قبل وبعد | Status قبل | Status بعد التقرير |
|---|---|---|---|---|
| ROOT | master | `c2ee5a3a3e128f86147e06d39cd50ca7ff2cf7d9` | 3 M، 6 ?? | 3 M، 6 ?? |
| API | preserve/rm02-rm05-baseline | `e8cee07c2c39df5a1531cbd63168695347202371` | 3 M، 54 ?? | 3 M، 60 ?? متوقعة (5 harness/evidence + التقرير) |
| WEB | master | `6fb01b8838de52de621dab4691a5cdd5710c29f6` | clean | clean |
| ADMIN | master | `9fa43befadaaa5d4583f8de6bf7a06c60e891bef` | clean | clean |
| SUPER | master | `a802e44b8a269071bcb46fcaa675aafb43b12a87` | clean | clean |

تعديلات ROOT الثلاث القديمة هي `HANDOFF-CURRENT.md` و`WORK-LEDGER.md` و`EVIDENCE-REGISTER.md`. ملفات API المتتبعة المعدلة الثلاث بقيت ببصماتها في Manifest السابق. فُحص checkpoint الخارجي دون تعديله: `manifest/FILES_SHA256.tsv` SHA-256=`b51e870fae9a5218114dbb34b5494e403088182d509db1dcf06aa1edf906d0cf`، و19/19 ملفًا مطابقًا قبل التعديل. مرجعا POC04 مطابقان: `run_tests.sh`=`befd0b8066569479351ad38c88272ba2b8af26fcd3a61055e6029f3954d7a2ba`، `003_comparison.sql`=`579259a851c8763b2da0038434bfc3805f8d8017e2badff47ff302bf0d7cf20b`. بصمة provisioner القديمة `5ff7620eb69bf6d3432c442a5a55e20eec030cdcab15a7978c9b757933c92f86`، وبصمة `002_actor_sql_fixture.sql` الثابتة `33942af36e8eb734ed9558a2fc038991d6153632d9dc91ecd9b4771b9c9fea22`.

## 2. بيئتا الإثبات الجديدتان

| | BEFORE / A | AFTER / B |
|---|---|---|
| container | `daleel-f06-setrole-b01-ce1acac9-pg-a` | `daleel-f06-setrole-b01-ce1acac9-pg-b` |
| labels | `control=SECURITY-F06-SETROLE-BOUNDARY-01`, `run=daleel-f06-setrole-b01-ce1acac9` | مثل A |
| port | `127.0.0.1:55470→5432` | `127.0.0.1:55471→5432` |
| networks | `daleel-f06-setrole-b01-ce1acac9-net-a` (internal) و`-net-a-host` | `-net-b` (internal) و`-net-b-host` |
| volume | `daleel-f06-setrole-b01-ce1acac9-data-a` | `daleel-f06-setrole-b01-ce1acac9-data-b` |
| system_identifier | `7700699346203131942` | `7700700553592188966` |
| PostgreSQL | 16.15 | 16.15 |
| الحالة في النهاية | exited؛ المنفذ غير مستمع | exited؛ المنفذ غير مستمع |

الشبكتان المضيفتان جديدتان ومخصصتان للجولة؛ ربط المنفذ loopback فقط. بدأ كل cluster بـ`POSTGRES_HOST_AUTH_METHOD=scram-sha-256` و`POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=scram-sha-256`. قرئت HBA داخل الحاويتين الجديدتين: كل قواعد local/host تستخدم SCRAM، ولا توجد قاعدة trust. الاتصال الهجومي نفسه `psql -h 127.0.0.1` داخل الحاوية وبكلمة مرور actor الصناعية، وأثبت `inet_client_addr()=127.0.0.1`. الأسرار الصناعية في مجلد runtime خارجي مقيد ACL، ليست في المستودع أو checkpoint، ولم تُدرج في الأدلة. لم تُشغّل أو تُعدّل أي حاوية قديمة.

في A طُبّق provisioner الأصلي أولًا؛ وفي B طُبّق provisioner المصحح من الصفر. احتاجت migrations 028–030 إلى دورَي LOGIN provider/config منفصلين لأن migrations تتحقق منهما ولا تُنشئهما؛ أُنشئا في كل sandbox بملف overlay جديد مخصص للجولة، بلا عضوية actor أو كلمة مرور. تعثرت محاولة A الأولى عند migration 028 بسبب غياب إعداد هذين الدورين، ثم استؤنف التسلسل بعد overlay؛ جدول `migrations` أثبت **38/38** في A، وفي B نُفذت **38/38** دفعة جديدة كاملة. محاولة fixture A أولى بقيمة hash غير Argon2id رُفضت بقيد schema وتراجعت معاملتها؛ أُعيدت بمدخلات Argon2id صناعية. بعد ذلك طُبقت `001_fixture_real_schema.sql` و`002_actor_sql_fixture.sql` الأصليتان على كلا المخططين الحقيقيين: شركتان A/B، ثلاث Leads (A=2، B=1)، FORCE RLS، والسياسة RESTRICTIVE المقيّدة بأدوار A1/A2/B1. هذا ليس مخطط toy.

## 3. BEFORE — تسرب مثبت حيًا

`pg_auth_members` في A: عضوية A1/A2/B1 المباشرة في `daleel_tenant_runtime` كانت لكل واحد `admin_option=f`, `inherit_option=t`, `set_option=t`؛ الدور الجماعي NOLOGIN، والأدوار الثلاثة LOGIN بلا SUPERUSER/BYPASSRLS/CREATEROLE. لا توجد سلسلة عضوية أخرى من A1 إلى المجموعة. مالك `leads` هو `postgres` مع FORCE RLS؛ مالك جدول mapping ودالته هو `daleel_f06i02_identity_resolver`. دور المجموعة لا يملك جداول أو دوال أو schemas، ولا يملك A1 حق CREATE على public أو قاعدة البيانات.

الضوابط: A1 على هويته الأصلية قرأ Leadَي A؛ B1 قرأ Lead B الواحد؛ A1 نفّذ `UPDATE 1` و`INSERT 0 1` شرعيين داخل A مع ROLLBACK. محاولة A1 `SET ROLE actor_b1` رُفضت `42501`/`rc=1`. تزوير GUC إلى B مع بقاء A1 في دوره أعطى `SELECT 0` و`UPDATE 0` ورفض INSERT بسياسة RLS (`42501`/`rc=1`). إذن fixture والامتيازات والصف الهدف كانت صالحة قبل الهجوم.

الهجوم: اتصال TCP/SCRAM باسم `daleel_f06i02_actor_a1` نفّذ `SET ROLE daleel_tenant_runtime` بنجاح (`rc=0`)، مع `session_user=A1` ثابت و`current_user=daleel_tenant_runtime`. بعد ضبط GUCs صناعية إلى B، أعاد SELECT **صف B الواحد** (`rc=0`)، ونفّذ `UPDATE 1` و`INSERT 0 1` عابرين للشركتين (`rc=0`) داخل BEGIN/ROLLBACK. فعل A2 وB1 أيضًا `SET ROLE` إلى المجموعة بنجاح. `RESET ROLE` و`SET ROLE NONE` أعادا A1 الأصلي؛ `SET SESSION AUTHORIZATION` إلى المجموعة رُفض `42501`. الفاحص المشروط يطلب هذه النتائج الإيجابية قبل أن يقبل حساسية الاختبار؛ لم يعتبر خطأ SQL عامًا نجاحًا. بصمة Leads قبل وبعد الجولة `3|61faf995a950bf89224a3b2c3018e703` بلا تغيير.

**EXPLOIT_REPRODUCED = YES**: تسرب قراءة كافٍ مستقلًا؛ ونجاح UPDATE/INSERT يضيف إثبات كتابة قابلة للتراجع. مصدر الخلل ليس إمكان SET ROLE إلى actor آخر؛ كان ذلك مرفوضًا أصلًا. سياسة PERMISSIVE إضافية لا تكفي لأن OR يسمح ببقاء مسار GUC؛ وسياسة RESTRICTIVE الحالية `TO` أدوار actor لا تنطبق عندما يصبح `current_user` هو الدور الجماعي.

## 4. تعديل المصدر وAFTER

**التعديل الوحيد في ملف I02 قائم:** `tools/security/f06-laravel-i02/000_provision_roles.sql`: أزيلت `IN ROLE daleel_tenant_runtime` من إنشاء أدوار A1/A2/B1 الثلاثة، وأضيفت بعد إنشاء الأدوار ثلاث عبارات صريحة `GRANT daleel_tenant_runtime TO actor WITH ADMIN FALSE, INHERIT TRUE, SET FALSE`. لم يتغير shared bootstrap أو أسماء الأدوار أو passwords الصناعية أو fixture 002 أو migrations أو PHP. SHA-256 الجديد: `4c80758ae7ce2b7e5849196aa8f7ae90ecfa8b0e72da5df3d05030acb18db57f`.

في B أثبت `pg_auth_members` لكل actor `admin=f`, `inherit=t`, `set=f`؛ لا توجد عضوية غير مباشرة بديلة إلى المجموعة. `SET ROLE daleel_tenant_runtime` من A1/A2/B1 رفض بـ`42501`/`rc=1`، وكذلك `SET ROLE actor_b1` من A1. سلسلة الهجوم التي تبدأ بـSET ROLE توقفت عند الأمر نفسه للـSELECT/UPDATE/INSERT. تزوير GUC دون تبديل هوية أعطى `SELECT 0` و`UPDATE 0` وINSERT مرفوضًا بسياسة RLS (`42501`). في المقابل بقيت A1 ترى Leadَي A وB1 يرى Lead B، ونجح UPDATE/INSERT الشرعيان لـA1 داخل A مع ROLLBACK. هذا يثبت استمرار وراثة المنح المطلوبة. بقيت FORCE RLS والسياسات PERMISSIVE/RESTRICTIVE وأصحاب الكائنات كما في A، ولا يملك الدور الجماعي كائنات SQL يمكن استغلال وراثة امتيازاتها لإعادة تعريفها. بصمة Leads في B قبل وبعد `3|61faf995a950bf89224a3b2c3018e703`.

مصدر القاعدة: PostgreSQL 16 يفعّل `SET` لعضوية `IN ROLE` افتراضيًا، ويجيز `GRANT ... WITH ADMIN FALSE, INHERIT TRUE, SET FALSE`، ولا يجيز `SET ROLE` عبر سلسلة إلا إذا كانت كل حلقاتها SET TRUE؛ كما يحذّر من امتلاك الدور الموروث كائنات SQL. راجع [CREATE ROLE](https://www.postgresql.org/docs/16/sql-createrole.html)، [GRANT](https://www.postgresql.org/docs/16/sql-grant.html)، [Role Membership](https://www.postgresql.org/docs/16/role-membership.html)، [SET ROLE](https://www.postgresql.org/docs/16/sql-set-role.html)، [RLS](https://www.postgresql.org/docs/16/ddl-rowsecurity.html).

## 5. Delta / Impact / حدود الحكم

الجولة عالجت مسار `SET ROLE` في عضويات actor الصناعية داخل fixture I02؛ **لم تعالج مسار shared bootstrap** الذي لا يزال يحتفظ بعضويته، ولا حل امتلاك عدة بيانات اعتماد في عملية PHP. `ACTOR_SCOPE_ARBITRARY_SQL=OPEN` خارج حد هذا السيناريو؛ اختبارات SQL هنا لا تثبت عقد HTTP أو worker reuse. `HTTP_SMOKE=NOT_EXECUTED` و`FLAG_OFF_SMOKE=NOT_EXECUTED` و`LD-03=NOT_EXECUTED`. لم تُعدل RLS أو ACL أو migration أو API contract أو أي تبعية منتج. T4b وF16 مستقلتان ومفتوحتان.

الـcheckpoint السابق محفوظ كما هو، لكنه يثبت بايتات provisioner **القديمة** فقط؛ لا يغطي SHA الجديد أو harness/report هذه الجولة. لا توجد نقطة حفظ جديدة للدلتا في هذا التفويض. إعادة التشغيل تتطلب المحافظة على مصدر fixture الجديدة وبيئتي الجولة المتوقفتين؛ لم يُنفذ Git commit، وملفات API الجديدة محلية غير متتبعة. نتيجة SQL boundary = **GO محدود للمراجعة المستقلة لهذه الدلتا**؛ الجاهزية لتغييرات IMPLEMENT-03 = **NO_GO** حتى مراجعة مستقلة ونقطة استرجاع جديدة بتفويض منفصل، مع بقاء مخاطر المنتج الأخرى تحت بواباتها الخاصة. الحذف اللاحق للحاويتين/الشبكات/volumes يتطلب تفويضًا مستقلًا؛ لم تُحذف.

**الملفات التي تغيرت:** provisioner أعلاه؛ `tools/security/f06-setrole-boundary-01/00_migration_runtime_roles.sql` و`01_admin_evidence.sql` و`run_actor_boundary.ps1` و`evidence_before-a.txt` و`evidence_after-b.txt`؛ هذا التقرير. بقيت الملفات الثلاثة المتتبعة M في API وfixture 001/002 وبقية I01/I02 وROOT/WEB/ADMIN/SUPER ثابتة. ملفات الأسرار الصناعية الخارجية لم تدخل التقرير أو Git.

## 6. أعلام ختامية

```text
W0_PRECHECK = PASS
RECOVERY_CHECKPOINT_SHA_AND_SCOPE = VERIFIED_OLD_19_OF_19_BEFORE_PATCH; PRESERVED_UNMODIFIED
PROTECTED_RESOURCE_ACCESS = NONE (metadata inventory only)
FRESH_SANDBOX_SYSTEM_IDENTIFIER = A:7700699346203131942; B:7700700553592188966
REAL_38_MIGRATIONS = A:38/38; B:38/38
BEFORE_ROLE_MEMBERSHIP_SET_OPTION = A1/A2/B1:TRUE
BEFORE_SET_ROLE_GROUP = SUCCESS_RC0
BEFORE_CROSS_TENANT_SELECT = B_ROWS_1_RC0
BEFORE_CROSS_TENANT_UPDATE = UPDATE_1_RC0_ROLLBACK
BEFORE_CROSS_TENANT_INSERT = INSERT_0_1_RC0_ROLLBACK
EXPLOIT_REPRODUCED = YES
SOURCE_FIX_APPLIED = YES_PROVISIONER_ONLY
AFTER_MEMBERSHIP_INHERIT_TRUE_SET_FALSE_ADMIN_FALSE = ALL_THREE_VERIFIED
AFTER_SET_ROLE_GROUP_DENIED = ALL_THREE_SQLSTATE_42501_RC1
AFTER_GUC_SPOOF_SELECT_UPDATE_INSERT_DENIED = SELECT_0_UPDATE_0_INSERT_42501
LEGITIMATE_ACTOR_PRIVILEGES_PRESERVED = A1_SELECT_UPDATE_INSERT_AND_B1_SELECT_VERIFIED
ROLE_GROUP_OBJECT_OWNERSHIP_RISK = NO_OWNED_TABLES_FUNCTIONS_SCHEMAS_IN_B; REASSESS_FOR_PRODUCT
SQLSTATE_AND_RC_CLASSIFICATION = VERIFIED_BY_PSQL_VERBOSE_AND_EXIT_CODE
SCHEMA_FIDELITY = REAL_38_MIGRATIONS_PLUS_ORIGINAL_I02_FIXTURES
HTTP_SMOKE = NOT_EXECUTED
DATA_FINGERPRINT_UNCHANGED = YES_A_AND_B
I01_I02_RECOVERY_POINT = PRESERVED_OLD_SCOPE
CURRENT_DELTA_RECOVERY_POINT = NOT_CREATED
SOURCE_CHANGE_SCOPE = ONE_I02_PROVISIONER_PLUS_NEW_HARNESS_AND_THIS_REPORT
GIT_COMMIT = NOT_EXECUTED
F06_PRODUCT_REMEDIATION = NOT_PERFORMED
ACTOR_SCOPE_ARBITRARY_SQL = OPEN
PHP_MULTI_CREDENTIAL_COMPROMISE_RISK = OPEN
T4B_REMEDIATION = NOT_PERFORMED
F16_REMEDIATION = NOT_PERFORMED
MIGRATION_039 = NOT_CREATED_NOT_RUN
CUSTOMERS = NO_GO
PRODUCTION = NO_GO
NEXT_GATE = INDEPENDENT_DELTA_REVIEW_THEN_RECOVERY_REFRESH_BEFORE_IMPLEMENT_03
```
