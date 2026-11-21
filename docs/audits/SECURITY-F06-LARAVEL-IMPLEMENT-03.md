<div dir="rtl">

# SECURITY-F06-LARAVEL-IMPLEMENT-03 — توقف هندسي قبل التنفيذ

**التاريخ:** 2026-10-25. **الصفات:** Backend/PostgreSQL/Security/QA وDevOps للفحص التشغيلي. **القرار:** `NO_GO_SOURCE_CONTRACT_BLOCKER`؛ لم تُنشأ sandbox ولم تُشغّل migrations أو HTTP أو اختبارات تاريخية. هذا التقرير يصف فحصًا مباشرًا للمصدر وGit ونقطة الاسترجاع، ولا يدّعي تحققًا تشغيليًا جديدًا أو مراجعة مستقلة للدلتا.

## W0 وخط الأساس

قُرئ التكليف وملفات دخول المشروع وتعليمات الجذر وAPI والحالة/الذاكرة/المنهج والسجلات، ثم فُحص Git قراءة فقط. الفروع وHEADs: ROOT `master`/`c2ee5a3a3e128f86147e06d39cd50ca7ff2cf7d9`؛ API `preserve/rm02-rm05-baseline`/`e8cee07c2c39df5a1531cbd63168695347202371`؛ WEB `6fb01b8838de52de621dab4691a5cdd5710c29f6`؛ ADMIN `9fa43befadaaa5d4583f8de6bf7a06c60e891bef`؛ SUPER `a802e44b8a269071bcb46fcaa675aafb43b12a87`. لا staged في أي مستودع. الثلاثة ملفات ROOT المعدلة والثلاثة ملفات API المعدلة وستة عناصر ROOT غير متتبعة وستون عنصر API غير متتبع وافقت جرد checkpoint؛ المستودعات الأمامية نظيفة. لم يكن مسار i03 أو هذا التقرير موجودًا قبل الجولة.

نقطة الاسترجاع `I:\WORK\DALEEL-CRM-RECOVERY\SECURITY-F06-SETROLE-REVIEW-AND-RECOVERY-01-20261025T203722Z-d085f7dd`: SHA-256 للـmanifest `08f4a8b841330b97e626ff409d2a1ef2b99193d3ab70b179b29d8362630adb7d`؛ فحص `verify-payload` أعاد `PASS 25/25`، ومقارنة SHA/حجم المصدر الحيّ مع manifest أعادت `25/25`. بصمة provisioner المصحح `4c80758ae7ce2b7e5849196aa8f7ae90ecfa8b0e72da5df3d05030acb18db57f`، وfixture `002_actor_sql_fixture.sql` ‏`33942af36e8eb734ed9558a2fc038991d6153632d9dc91ecd9b4771b9c9fea22`. بصمتا POC04 closeout: `run_tests.sh` ‏`befd0b8066569479351ad38c88272ba2b8af26fcd3a61055e6029f3954d7a2ba` و`003_comparison.sql` ‏`579259a851c8763b2da0038434bfc3805f8d8017e2badff47ff302bf0d7cf20b`. لم تُمس نقطة الاسترجاع.

فُحصت أسماء الحاويات الموجودة ومنافذها عبر Docker metadata فقط؛ بقيت الموارد السابقة دون دخول أو تشغيل أو إيقاف. مصدر migrations الحالي 38 ملفًا. لم يُستخدم منفذ 5432 أو أي منفذ قاعدة محمية.

## خطة التنفيذ التي أوقفها فحص العقد

كان التسلسل المطلوب: تجهيز PostgreSQL 16 جديدة محصورة على loopback مع SCRAM؛ إثبات هويتها وHBA؛ provisioner لأدوار NOLOGIN/LOGIN بلا `SET ROLE` جماعي؛ تشغيل 38 migrations الأصلية؛ إنشاء A4 وLeads اصطناعية بنطاق `ASSIGNED`؛ إضافة طبقة RLS `RESTRICTIVE TO A4`؛ اختبار SQL العدائي وHTTP الحقيقي تحت FLAG OFF/ON؛ ثم فحص تاريخي آمن. لم تبدأ خطوة كتابة من هذا التسلسل لأن اعتماد A4 غير قابل للتمرير عبر إعداد التطبيق الحالي ضمن قائمة الملفات المسموح تعديلها.

## المانع القابل لإعادة الإنتاج من المصدر

1. `config/f06_actor_sql.php:28-35` يعرّف خريطة `synthetic_actor_passwords` مغلقة بأدوار I01 وI02، A1/A2/B1 فقط. لا مدخل A4 ولا مدخل أدوار I03. إضافة `F06_ACTOR_PW_A4` كمتغير بيئة وحده لا تضيف مفتاحًا للخريطة.
2. `ActorSqlIdentityResolver.php:19-27` يقرأ `config('f06_actor_sql.synthetic_actor_passwords.'.$sqlRoleName)` ويعيد `null` عند غياب المدخل. `TenantStaffRequestContext.php:133-145` يستخرج اسم SQL من bootstrap lookup ثم يمرر كلمة المرور إلى `ActorConnectionFactory::switchTo`. الأخير يرفض `null` صراحةً قبل فتح الاتصال في `ActorConnectionFactory.php:45-49`. هذا تحليل مسار مصدر؛ **لم يُشاهد HTTP status فعلي**.
3. `002_actor_sql_fixture.sql:29-48` يسجل A1/A2/B1 فقط في خريطة هوية SQL ويضع هؤلاء وحدهم في `GRANT EXECUTE` و`CREATE POLICY ... AS RESTRICTIVE TO ...`. يمكن توسيع fixture داخل i03 كما يسمح التكليف، لكن ذلك لا يضيف مفتاح اعتماد A4 إلى إعداد Laravel.
4. استخدام هوية SQL من الثلاثة القديمة لـA4 يلغي شرط الدور المستقل والـ`session_user` الخاص به. إنشاء مدخل config cache مغاير خارج المصدر سيختبر إعداد تطبيق مشتقًا لا الإعداد الحالي الذي كُلّفنا بالتحقق منه؛ التكليف لا يصرّح بتغيير خريطة اعتماد المنتج أو `config/f06_actor_sql.php`. لذلك لم يُستخدم هذا الالتفاف.

عقد `LeadService.php:190-216`: `ASSIGNED` يعني `assigned_membership_id = membershipId`؛ `SELF` يعني `created_by_membership_id = membershipId`؛ `ALL_TENANT` يتجاوز فلتر الصف داخل الشركة. `assignLead` في السطور 146-164 يتطلب `leads.manage` بنطاق `ALL_TENANT`. `TenantStaffAuthorizationService::effectiveGrants` يجمع grants من الأدوار والمنح المباشرة بعد صلاحية العضوية. هذه قراءة مصدر فقط؛ لا إثبات HTTP أو SQL لـA4.

مرجع PostgreSQL 16: `GRANT ... WITH ADMIN FALSE, INHERIT TRUE, SET FALSE` هو الصيغة الصحيحة، و`SET ROLE` عبر سلسلة عضويات يتطلب `SET TRUE` في كل حلقة؛ كما يجب ألا يملك الدور الجماعي كائنات SQL قابلة للاستغلال عند وراثة الامتيازات مع منع SET. راجع [GRANT](https://www.postgresql.org/docs/16/sql-grant.html) و[Role Membership](https://www.postgresql.org/docs/16/role-membership.html). لا يُعد هذا إثباتًا حيًا لأدوار I03 التي لم تُنشأ.

## بوابات النتائج

| البوابة | النتيجة | السبب |
|---|---|---|
| W0_PRECHECK / FIVE_REPO_GIT_BASELINE | `PASS_SCOPED_READ_ONLY` | الفروع وHEADs والجرد وstaged مطابقة لحظة الفحص. فحص العقود الكاملة لم يكتمل بسبب stop. |
| RECOVERY_CHECKPOINT_25_HASH_MATCH | `PASS_READ_ONLY` | manifest والـ25 payload والـ25 مصدر مطابقة. |
| NEW_SANDBOX_IDENTITY_AND_HBA / REAL_MIGRATIONS_APPLIED | `NOT_EXECUTED` | توقف قبل إنشاء مورد. |
| A4_ASSIGNED_FIXTURE_AND_ACTOR_ROLE / A4_RESTRICTIVE_RLS_APPLIES / ACTOR_SET_FALSE_ALL_ROLES | `NOT_EXECUTED` | لا أدوار I03 أو fixture جديدة. |
| SET_ROLE_SQLSTATE_AND_RC / GUC_CROSS_TENANT_NEGATIVE_CONTROLS | `NOT_EXECUTED` | لا SQL عدائي؛ لا rc أو SQLSTATE جديد. |
| HTTP_CSRF_AUTH_HOST_SESSION_WIRE / LEADCONTROLLER_LEADSERVICE_REAL / FLAG_OFF_ON_COMPARISON | `NOT_EXECUTED` | لا خادم/طلب HTTP؛ لا status/body/keyset جديد. |
| LD03_ASSIGNED_READ_AND_WRITE / LD03_LEAD_REASSIGNMENT_CONTRACT | `SOURCE_SUPPORTED / NOT_VERIFIED_RUNTIME` | عقد المصدر مذكور أعلاه؛ لم تُنشأ A4. |
| HTTP_SAME_WORKER_REUSE | `NOT_VERIFIED` | لا خادم عامل جديد. |
| ROLE_PROVISIONING_SANDBOX_REPRODUCIBLE | `NOT_EXECUTED` | لا provisioner I03 ولا قاعدة جديدة. |
| ROLE_PROVISIONING_PRODUCT | `NOT_IMPLEMENTED` | خارج التفويض. |
| HISTORICAL_51_HTTP / HISTORICAL_11_KERNEL / HISTORICAL_29_PHPUNIT | `DOCUMENTED_PRIOR / NOT_REEXECUTED` | لم يُشغّل اختبار تاريخي أو يُنسب نجاح سابق إلى هذه الجولة. |
| TENANT_SQL_BOUNDARY_AFTER_SETROLE | `DOCUMENTED_PRIOR / NOT_REVERIFIED` | دليل SETROLE السابق محفوظ؛ لا تكرار في I03. |
| ACTOR_SCOPE_ARBITRARY_SQL / PHP_MULTI_CREDENTIAL_COMPROMISE_RISK | `OPEN` | لم تُعالج. |
| T4B_REMEDIATION / F16_REMEDIATION | `OPEN / NOT_EXECUTED` | خارج التفويض. |
| MIGRATION_039 / ROOT_PROTECTED_DOCS / GIT_COMMIT / CUSTOMERS / PRODUCTION | `NOT_EXECUTED / UNTOUCHED` | لا تعديل أو اتصال. |
| EXECUTIVE_VERDICT | `NO_GO_SOURCE_CONTRACT_BLOCKER` | لا يمكن منح PASS لـG03-A/B مع A4 تحت FLAG=ON من دون مدخل اعتماد في التطبيق. |
| NEXT_GATE | `OWNER_DECISION_ON_BOUNDED_TEST_CREDENTIAL_MAPPING` | تفويض مستقل يحدد طريقة إضافة A4 إلى الخريطة أو تهيئة اختبارية معتمدة، ثم جولة تنفيذ ومراجعة دلتا مستقلة. |

## الأثر والتراجع

أظهر فحص W0 الختامي نفس حالات Git السابقة مع إضافة هذا التقرير غير المتتبع وحده في API؛ لا staged، ولا حاوية I03. لا تغيّر في كود المنتج، ولا بيانات أو Docker أو Git. الملف الجديد الوحيد هو هذا التقرير. لا حاجة إلى rollback تشغيلي. قبل أي جولة لاحقة تُراجع هوية Git والcheckpoint والموارد من جديد؛ هذا التقرير لا يحجز البيئة أو يمنح صلاحية فتحها تلقائيًا.

</div>
