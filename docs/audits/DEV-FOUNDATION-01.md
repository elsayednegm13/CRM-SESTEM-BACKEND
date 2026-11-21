# DEV-FOUNDATION-01 — Reproducible Isolated Development & Acceptance Foundation

**التاريخ:** 2026-10-24، Africa/Cairo  
**الدور:** Backend / DevOps / QA-Security / توثيق  
**التصنيف النهائي:** PARTIAL / NO-GO  
**تفويض المالك:** Option B — بيئة محلية جديدة ومعزولة فقط؛ لا مساس بـscratch، ولا Customers أو نشر.

## A. EXECUTIVE SUMMARY

أُنشئت بيئة PostgreSQL 16 جديدة ومعزولة، واتصلت بها اتصالات Laravel السبعة، ونُفذت migrations الـ36 على DEV وTEST. تطابقت بصمة schema-only بين القاعدتين، وتأكدت ملكية الجداول وبيانات أدوار التشغيل وخصائص RLS من الكتالوجات.

لم تجتز البوابة: صلاحية onboarding المطلوبة غائبة في TEST؛ اختبارات RLS/A-B لم تثبت العزل؛ والنتيجة الحالية للمجموعة الكاملة 53 نجاحًا و42 خطأ و5 إخفاقات و24 تخطيًا من 124. لذلك البيئة **مؤسسة تقنيًا لكنها غير مقبولة للتقدم إلى Customers**. لا تعني نتيجة هذه المهمة جاهزية إنتاجية.

## B. OWNER AUTHORIZATION & SAFETY BOUNDARIES

التفويض الوارد في DEV-FOUNDATION-01 Option B أتاح حاوية PostgreSQL محلية جديدة، volume وشبكة وDBs جديدة، ملفات acceptance مستقلة، migrations وfixtures واختبارات على الهدف الجديد فقط، وتوثيق النتائج. أُضيف D-12 لتسجيل هذا النطاق المحدد.

لم يُستخدم المضيف 5432، ولم تُشغّل Compose أو lifecycle commands على scratch أو على Compose الأصلي. لم تُعدّل ملفات التطبيق أو migrations أو اختبارات المصدر أو الواجهات. لم يُنفذ DROP أو reset أو teardown أو commit/stage/push/deploy. بقيت بيانات الاعتماد وسجلات PHPUnit في مجلد خاص ومهمل Git.

## C. SOURCE CHECKPOINT & GIT

مساحة العمل الفعلية: I:\WORK\DALEEL-CRM؛ الجذر ليس Git repository. الحالات قبل/بعد:

| المستودع | HEAD قبل/بعد | الحالة قبل | الحالة بعد |
|---|---|---|---|
| daleel-crm-api | d6870839f38b1f05786288071dbe0bb7719d5386 | تقرير DB-VERIFY-01.md غير متتبع | التقرير السابق نفسه + DEV-FOUNDATION-01.md غير متتبع |
| daleel-crm | 6fb01b8838de52de621dab4691a5cdd5710c29f6 | نظيف | نظيف |
| daleel-crm-admin | 9fa43befadaaa5d4583f8de6bf7a06c60e891bef | نظيف | نظيف |
| daleel-crm-super-admin | a802e44b8a269071bcb46fcaa675aafb43b12a87 | نظيف | نظيف |

لا تغييرات Git في الرؤوس أو الملفات المتتبعة؛ مجلد acceptance وملفات docs الجذر خارج المستودعات. لم يُنفذ add أو commit. لا تُعامل إضافة هذا التقرير غير المتتبع على أنها تحفظ ملفات الجذر أو التقرير السابق.

## D. PRE-FLIGHT / BASELINE

ورثت الحالة الموثقة في DB-VERIFY-01 / RESUME-02: scratch تحمل بصمة DALEEL-CRM لكن grants التشغيلية ناقصة، ولم يكن هناك قبول runtime أو A/B. أوضح المالك أن daleel_dev القديمة كانت فارغة ومحذوفة؛ هذا لا يصف daleel-pg-scratch. لم تُعَد مراحل Phase 0/1 أو Staff/Roles/Leads.

قبل الإنشاء كان Docker Desktop يعمل على desktop-linux. ظهر scratch وحدها كهدف محمي على 127.0.0.1:55432، مع volume معلوم. أسماء المشروع والحاوية والvolume والشبكة والـports الجديدة كانت غير موجودة/غير محجوزة بحسب manifest. PHP Herd 8.4.27 مع pdo_pgsql وintl وfileinfo متاح؛ PHP 8.5 من winget لا يملك الامتدادات المطلوبة، فلم يُستخدم. لا صورة PHP محلية كانت متاحة.

## E. ACCEPTANCE TARGET MANIFEST

| العنصر | القيمة المثبتة |
|---|---|
| Compose project | daleel-crm-acceptance |
| Container | daleel-pg-acceptance؛ ID d6ce6f4c1e92f8e381ed2830125d697bcee269b01078e6c7402b4ae2f6402908؛ running/healthy |
| Image | PostgreSQL 16.15، digest sha256:9e2cf6287f25c3151f4c9421ccce2b17f3e60061c111a29165e0d2cdd9ff0a97 |
| Volume | daleel_acceptance_pg_data → /var/lib/postgresql/data |
| Networks | daleel-acceptance-internal، internal=true؛ daleel-acceptance-loopback، bridge مع IP masquerading disabled |
| DEV | daleel_acceptance_dev، port 127.0.0.1:55433 → container :5432، owner daleel_b10b_owner، OID 16412 |
| TEST | daleel_crm_b10b_disposable، port 127.0.0.1:55437 → container :5432، owner daleel_b10b_owner، OID 16413 |
| Cluster identity | system identifier 7699972247235194919؛ عنوان الحاوية الداخلي المرصود 172.19.0.2 |

الـportين مربوطان بـ127.0.0.1 فقط. المنفذ 5432 ظاهر داخل حاوية القبول فقط؛ لم يُستخدم listener المضيف 5432. تفاصيل الهدف محفوظة دون اعتماد سري في tools/dev-db/acceptance/TARGET_MANIFEST.md وملف القفل الخاص.

## F. DOCKER BUILD & ISOLATION

أنشئ مشروع Compose منفصلًا وحاوية واحدة وvolume وشبكة داخلية وشبكة bridge منفصلة للاتصال المحلي. في البداية لم ينشر Docker Desktop المنافذ مع الشبكة الداخلية وحدها؛ أُضيفت شبكة loopback مخصصة مع تعطيل IP masquerading، دون استبدال الحاوية أو تغيير volume. بعد ذلك ظهرت خريطتا المنفذ على loopback.

الهدف الجديد لا يركّب checkout للمصدر. يعمل PHP من المضيف عبر 55433/55437. لم يُسحب image، ولم تُنشأ حاوية PHP runner. أعيد فحص scratch بعد التنفيذ: ما زال ID b05a2967dfcbd726258a42336ae977bf806cc413bd5ac6217f298854272749fd، running، 127.0.0.1:55432→5432، والـvolume الأصلي e6b3342f2f3c4c30c4c7b6dc8ef5cab60c00e20e816a4c61fb8672d1f65cf53b؛ القيم مطابقة لما قبل التنفيذ.

## G. ROLE BOOTSTRAP STRATEGY

لم يُشغّل bootstrap-roles.sql الأصلي كاملًا على قاعدة جديدة، لأن منح الجداول في آخره يعتمد على وجود الجداول. استُخدمت scripts محلية acceptance-only:

1. roles-pre.sql أنشأ مجموعات NOLOGIN وهويات الاتصال المحلية المطلوبة قبل migrations وعضويات ضيقة. عُيّنت كلمات مرور عشوائية من ملفات خاصة دون طباعتها أو وضعها في argv.
2. المالك daleel_b10b_owner نفّذ migrations على القاعدتين.
3. roles-post.sql طبّق فقط منح provider-table/sequence الموجودة في المصدر بعد إنشاء الجداول؛ لم يستخدم GRANT ALL أو SUPERUSER أو BYPASSRLS.

نجاح ترتيب الإنشاء لا يثبت اكتمال grants المطلوبة؛ بقيت فجوة onboarding موثقة في القسم J. فشل أول استئناف بعد حفظ DBs وملف القفل عند ضبط ACL لملف metadata؛ عُدّلت scripts acceptance لإزالة عملية ACL الزائدة عن ملف القفل. المجلد الخاص وملفات الاعتماد ظلت محمية؛ لم يُجرَ reset أو حذف لإكمال المسار.

## H. MIGRATION RESULTS

| الفحص | DEV | TEST | النتيجة |
|---|---:|---:|---|
| ملفات المصدر | 36 | 36 | ثابتة؛ لم تعدل |
| migrations المسجلة | 36 | 36 | 36/36 في كل قاعدة |
| اختلاف الاسم/العدد | 0 | 0 | parity |
| جداول public | 36 | 36 | متطابقة |
| RLS enabled / forced | 18 / 18 | 18 / 18 | metadata فقط |
| policies / constraints | 94 / 223 | 94 / 223 | متطابقة |
| indexes / functions / triggers | 87 / 26 / 15 | 87 / 26 / 15 | متطابقة |

بصمة pg_dump schema-only بعد استبعاد سطري framing العشوائيين \restrict/\unrestrict في PostgreSQL 16 متطابقة في DEV وTEST: bd323752a5591527071460600a0b85579856fca608c97cea5d0b65c3ea4024f6. لا يثبت هذا وحده صحة runtime grants أو سلوك التطبيق.

### الأوامر التشغيلية المنفذة (منقحة)

- فحوص Docker قراءة فقط: جرد الحاويات بالاسم، خرائط المنافذ، وحقول inspect منتقاة للحالة والصورة والـlabels والـmounts؛ وفحص Compose config للملف acceptance المحدد. لم يُخرج Environment أو JSON كاملًا.
- تشغيل Compose للملف tools/dev-db/acceptance/docker-compose.yml بمشروع daleel-crm-acceptance لإنشاء الهدف الجديد فقط؛ لم تُشغّل أوامر lifecycle على Compose الأصلي أو scratch.
- تشغيل Compose المحدد ثم Resume-Acceptance.ps1؛ فشل استئناف مبكر عند مقارنة تمثيل عنوان loopback ثم أُصلح verifier. محاولة لاحقة أكملت roles/DBs ثم توقفت عند ACL لملف metadata، وأزيلت خطوة ACL الزائدة من scripts دون حذف المورد.
- Run-Migrations.ps1 لتطبيق migrations واحدة واحدة على DEV وTEST بعد preflight؛ ثم Verify-RuntimeIdentities.ps1 وVerify-Schema.ps1 للقراءة فقط.
- Run-AcceptanceTests.ps1 ثلاث مرات بسبب ضبط التقاط stdout/stderr؛ JUnit النهائي الخاص هو المصدر الرقمي المعتمد. لا تُستخدم سجلات المحاولات السابقة كنجاح.
- git rev-parse HEAD وgit status --short للمستودعات الأربعة، وفحص PowerShell parser وphp -l للـPHP verifier. الأوامر لم تطبع credentials.

أعاد أول قالب inspect في المراجعة النهائية خطأ تنسيق لأنه حاول قراءة Name من bind mount خاص بالـCompose secret؛ لم يحدث أي تغيير على Docker. عُدّل القالب ليعرض volume Name فقط عند Type=volume وعند غير ذلك نوع mount ووجهته، ثم نجح الجرد.

لم يُنفذ docker compose down/up على المشروع الأصلي، migrate:fresh على DEV أو scratch، restore/seed خارجي، image pull، Composer install/update، أو تشغيل runner داخل Docker.

## I. ENV / CONNECTION MATRIX

نجحت كل named connections السبعة في اختبار الهوية الحية على القاعدتين. كل اتصال أكد قاعدة البيانات والمستخدم المتوقعين، current_user=session_user، server address داخلي 172.19.0.2، server port 5432، واتصال العميل من loopback المضيف. لا توجد كلمات مرور في هذا التقرير.

| اتصال Laravel | principal | DEV | TEST | الدور |
|---|---|---|---|---|
| pgsql | daleel_b10b_owner | PASS | PASS | migrations فقط؛ ليس دليل runtime |
| pgsql_provider | dl_provider | PASS | PASS | provider authentication/team |
| pgsql_provider_control | dl_provider_ctl | PASS | PASS | عمليات التحكم |
| pgsql_onboarding | dl_onboarding | PASS | PASS | إدراج مستخدم onboarding |
| pgsql_hostname_resolver | dl_host | PASS | PASS | حل host |
| pgsql_tenant_auth | dl_tauth | PASS | PASS | مصادقة موظفي tenant |
| pgsql_tenant_runtime | dl_truntime | PASS | PASS | tenant runtime |

الأدوار الثمانية التي تحقق منها فحص هوية TEST المباشر شملت أيضًا daleel_b10b_provider_runtime وdaleel_b10b_tenant_runtime. هويات التشغيل غير superuser وNOBYPASSRLS وNOCREATEDB وNOCREATEROLE، ولا تملك CREATE على schema؛ ولا تملك جداول RLS.

## J. EFFECTIVE PRIVILEGES

نتائج الجدول أدناه هي عدد الجداول التي يملك الدور عليها كل امتياز effective في TEST؛ العمود الخامس عدد أعمدة id التي لها SELECT. ليست هذه نسبة منحة عامة، وقد تشمل عضوية موثقة.

| الدور | SELECT / INSERT / UPDATE / DELETE جداول | SELECT على id | ملاحظة |
|---|---:|---:|---|
| daleel_b10b_owner | 36 / 36 / 36 / 36 | 24 | مالك schema والجداول؛ لا يستخدم كدليل runtime |
| daleel_b10b_provider_runtime | 5 / 5 / 1 / 1 | 3 | يرث grants provider المحدودة |
| daleel_b10b_tenant_runtime | 0 / 0 / 0 / 0 | 4 | grants أعمدة محدودة |
| dl_provider | 5 / 5 / 1 / 1 | 2 | grants provider |
| dl_provider_ctl | 2 / 1 / 0 / 0 | 6 | grants/قراءات محدودة |
| dl_onboarding | 0 / 0 / 0 / 0 | 0 | لا INSERT على users؛ فجوة مؤكدة |
| dl_host | 2 / 0 / 0 / 0 | 0 | قراءة محدودة |
| dl_tauth | 0 / 0 / 0 / 0 | 0 | دالة auth SECURITY DEFINER عبر عضوية محدودة |
| dl_truntime | 0 / 0 / 0 / 0 | 4 | قراءات أعمدة محدودة |

كل الأدوار ذات الصلة لديها schema USAGE وdatabase CONNECT؛ أدوار التشغيل لا تملك schema CREATE. أعداد sequence/function الفعالة أُخرجت في فحص الكتالوج: dl_provider لديه sequence USAGE/SELECT على تسلسل واحد؛ مالك migrations لديه 1/1/1؛ لا sequence grants مباشرة لـdl_onboarding أو dl_truntime. دالة lookup_tenant_staff_credentials مملوكة لـdaleel_tenant_auth_lookup ومسموح تنفيذها للـclient عبر membership؛ تحقق اختبار مباشر أن dl_tauth عضو وأن EXECUTE فعّال. دالتا التحكم ذات SECURITY DEFINER مملوكتان للمالك وACL الخاص به فقط.

**Finding DF01-G3-003 — HIGH / ثقة عالية:** PROVIDER_CONTROL_OPERATIONS.md يحدد أن pgsql_onboarding يدرج فقط id,email,password,email_verified_at,created_at,updated_at على users. المصدر يستعمل DB::connection('pgsql_onboarding')->table('users')->insert(...) في ProviderControlOperationService.php:989. استعلام effective privilege في TEST وجد INSERT على الجدول وعلى كل واحد من الأعمدة الستة = false. لا يوجد grant للمستخدم dl_onboarding في bootstrap الأصلي أو migrations. الأثر المحتمل: direct provider provisioning يفشل عند إدراج المستخدم. لم تُنفذ محاولة DML ولم يُضف grant. يلزم تفويض منفصل قبل تعديل منح القبول أو المصدر.

## K. RLS AND A/B ISOLATION

في TEST، جميع الجداول الـ18 التي تفعّل RLS مملوكة لـdaleel_b10b_owner، وكلها relrowsecurity=true وrelforcerowsecurity=true؛ إجمالي السياسات 94. المالك نفسه non-superuser وNOBYPASSRLS، لكن وجود flags والسياسات يثبت **RLS configured** فقط، ولا يثبت **tenant isolation**.

لم يُنجز أي اختبار A/B ناجح. PostgresRlsIsolationTest أخفق في إنشاء fixture tenant بسبب رفض RLS إدراج صف في tenants؛ المجموعة المركزة سجلت 9 errors، ولا توجد نتائج allow/deny بين شركتين. لذلك لا يمكن إعلان أن tenant A يستطيع A ولا يستطيع B. كما لم يثبت فصل RLS عن application authorization أو Host-derived tenant identity في هذه البيئة.

## L. LARAVEL / ACCEPTANCE / FULL TESTS

PHP المستخدم هو Herd 8.4.27 مع pdo_pgsql وintl وfileinfo. لا تعديل لـPHP النظامي أو Composer lock، ولا تثبيت package. مخارج JUnit خاصة داخل tools/dev-db/acceptance/.private/reports/.

| المجموعة | العدد | Passed | Errors | Failures | Skipped | Assertions | الزمن |
|---|---:|---:|---:|---:|---:|---:|---:|
| full suite | 124 | 53 | 42 | 5 | 24 | 470 | 28.15 ثانية |
| focused runtime | 17 | 1 | 14 | 2 | 0 | 92 | 5.36 ثانية |

في full suite، 36 من 42 error كانت QueryException / SQLSTATE 42501؛ وتضمنت ستة أخطاء RuntimeException. في focused suite، 12 من 14 error كانت SQLSTATE 42501، إضافة إلى خطأين ProviderAccessException. ظهرت أخطاء RLS عند إنشاء tenants في fixtures. لا ننسب كل فشل إلى عيب كود مؤكد قبل فصل setup/context عن سلوك الخدمة.

إخفاقات PHPUnit الخمسة في full suite:

- SecurityAuditTest::test_schema_vocabulary_provider_actor_and_metadata_are_constrained
- Eng06CompanyContextAuthorizationTest::test_company_context_authorization_and_provider_regression_over_real_http
- Eng06CompanyContextAuthorizationTest::test_provider_execute_exception_redacts_canary_before_reporting
- Eng03DisposableFixtureTest::testGenuineProviderApprovalDirectAdminsAndHostFirstTenantIsolation
- ProviderControlVocabularyTest::test_10c_event_vocabulary_matches_enum_database_constraints_and_rls

المجموعة المركزة غطت SecurityAuditRuntimeRoleTest (3 errors)، ProviderConcurrencyTest (1 error وfailure واحد)، ProviderRuntimeRoleTest (1 error وfailure واحد)، وPostgresRlsIsolationTest (9 errors). لا تُحسب هذه محاولة A/B ناجحة.

كانت هناك ثلاث محاولات لتشغيل runner بسبب مشكلة التقاط stdout/stderr ثم null-stderr في script؛ تعديل الالتقاط داخل acceptance فقط أتاح JUnit نهائيًا بالأرقام أعلاه. لا تُعد المحاولتان السابقتان دليل نجاح. لاختلاف setup، لا نقارن 53 passing الحالية كأنها regression مؤكد عن baseline التاريخي.

## M. BUGS / ROOT CAUSES

| Finding | الشدة / الثقة | ما ثبت | الأثر / المطلوب |
|---|---|---|---|
| DF01-G3-003 | HIGH / عالية | dl_onboarding ليس لديه INSERT على users أو الأعمدة الستة رغم عقد المصدر | قد يمنع provisioning؛ تفويض منفصل لتحليل grant الصحيح |
| DF01-G4-001 | HIGH / عالية لعدم القبول؛ متوسطة لسبب fixture | Postgres رفض إدخال tenant أثناء إعداد اختبار RLS؛ 9 أخطاء في PostgresRlsIsolationTest | A/B غير مثبت؛ تتبع transaction/GUC/role bootstrap قبل أي تعديل |
| DF01-G5-001 | HIGH / عالية للنتيجة | full suite ليست خضراء (42 errors/5 failures/24 skips) | البوابة NO-GO؛ تمييز harness عن product root cause في تكليف لاحق |
| DF01-G5-002 | MEDIUM / عالية للنتيجة | focused runtime suite 1/17 فقط يمر | لا runtime acceptance كاملة |

الأخطاء من التشغيل الحالي فقط. لا نعيد إنتاجها ولا نعدل application/migrations في هذا التكليف. فشل capture في محاولات runner الأولى كان من script القبول، وأصلح داخل acceptance؛ لا يمحو نتائج PHPUnit الحالية.

## N. FILE AND RESOURCE DIFF

أُنشئت ملفات acceptance التالية في workspace root، خارج Git: .gitignore، TARGET_MANIFEST.md، docker-compose.yml، roles-pre.sql، roles-post.sql، common.ps1، Initialize-Acceptance.ps1، Resume-Acceptance.ps1، Run-Migrations.ps1، Verify-Schema.ps1، Verify-RuntimeIdentities.ps1، verify-connections.php، Run-AcceptanceTests.ps1، README.md. أُنشئ مجلد .private لتخزين local credentials وtarget-lock وstdout/stderr/JUnit وملفات مؤقتة؛ ignored ومحمي ACL.

مورد Docker الجديد: Compose project واحد، container واحد، volume واحد، شبكتان، وقاعدتا DEV/TEST المذكورتان في القسم E. لم يُحذف أو يعدل مورد Docker قائم.

أُنشئ هذا التقرير داخل API كملف غير متتبع. بقي تقرير DB-VERIFY-01.md السابق دون تعديل. لا كود أو migration أو اختبار مصدر أو config أو OpenAPI أو ملفات الواجهات تغيرت.

## O. SECURITY REVIEW

- المنافذ المنشورة على المضيف 127.0.0.1:55433 و127.0.0.1:55437 فقط؛ لا استخدام لـ127.0.0.1:5432 أو 0.0.0.0:5432.
- الأسرار ولدت محليًا، ولم تُقرأ إلى التقرير أو تطبع أو تمرر في argv. .private محمية بACL خاص بالمستخدم الحالي؛ reports ترث القاعدة نفسها، ولم تظهر محتويات صفوف الأعمال في الأدلة.
- image digest pinned ومتوافر محليًا؛ لم يسحب image أو Composer dependency.
- لا أدوار SUPERUSER أو BYPASSRLS أو CREATE إضافي لأدوار runtime. لا GRANT ALL.
- الـvolume والحاوية الجديدان ما زالا موجودين للمراجعة؛ لا teardown. scratch لم يتغير.
- القبول المحلي ليس إثبات إنتاج أو اعتماد أمني نهائي.

## P. DOCUMENTATION CHANGES

1. أضيف هذا التقرير: daleel-crm-api/docs/audits/DEV-FOUNDATION-01.md.
2. أضيفت النتائج الفعلية إلى tools/dev-db/acceptance/TARGET_MANIFEST.md وREADME.md.
3. أضيف أحدث checkpoint في docs/STATUS.md، مع بقاء الإنجازات السابقة دون تغيير.
4. أضيفت بوابة DEV-FOUNDATION قبل Customers في docs/PLAN.md.
5. أضيف checkpoint handoff في أعلى docs/HANDOFF.md وحُفظ checkpoint RESUME-02 السابق.
6. أضيف D-12 لتثبيت تفويض Option B وحدوده؛ D-1 إلى D-11 لم تعدل.

ملفات docs الجذرية وملفات tools/dev-db/ خارج Git؛ يلزم حفظ/نسخ يدوي معتمد منها. لا يدعي هذا التقرير أن API commit مستقبلية ستحفظها. API audit جديد وغير متتبع، ولا ينبغي ضمه ضمن staging تلقائي.

بصمة SHA-256 لتقرير DB-VERIFY-01 السابق قبل وبعد هذه الجلسة متطابقة: E7C66607ED5B0997E085D1DA9C7C683FCF983174247BA17C82CA2CAC78FA774C؛ لم يتغير محتواه.

## Q. GATES G0..G5 + GO/NO-GO

| البوابة | الحالة | الدليل / القرار |
|---|---|---|
| G0 preflight/manifest | PASS | DF01-G0-001؛ هدف جديد وأسماء ومنافذ وصورة محلية منفردة قبل الإنشاء |
| G1 إنشاء وعزل | PASS | DF01-G1-001 وDF01-G1-002؛ الهدف يعمل وscratch مطابقة قبل/بعد |
| G2 bootstrap/migrations/schema | PARTIAL | DF01-G2-001 وDF01-G2-002؛ 36/36 parity وتطابق schema، لكن grants runtime فيها فجوة |
| G3 roles/effective privileges | PARTIAL / NO-GO | DF01-G3-001 وDF01-G3-003؛ أدوار non-owner صحيحة إجمالًا، وonboarding INSERT مفقود؛ CRUD probes غير مكتملة |
| G4 tenant A/B | BLOCKED / NOT PROVEN | DF01-G4-001؛ RLS flags موجودة لكن fixture رفضها RLS ولم يثبت A/B |
| G5 Laravel/regression | NO-GO | DF01-G5-001 وDF01-G5-002؛ suite فيها errors/failures/skips |

**قرار البوابة العليا:** DEV-FOUNDATION-01 PARTIAL / NO-GO. لا قبول runtime مكتمل، لا readiness إنتاجية، ولا انتقال إلى Customers. يلزم تفويض مالك جديد وخطة إغلاق محددة لـG3–G5.

## R. KNOWN GAPS / DEFERRED

- 24 skipped في full suite الحالي؛ بينها اختبارات FND-ID-02 التي تحتاج DB/fixture IDs/hosts غير موجودة. لا تُصطنع هذه القيم.
- اختبارات provider الستة ذات runner الداخلي لم تنجح ضمن ظروف target/fixtures المطلوبة. لم تتوافر صورة PHP محلية أو actor fixtures معتمدة؛ لا image pull ولا runner container.
- حالات HTTP/DNS/fixture المعروفة (Eng03/Eng06) لم تُبنَ لها stack منفصلة؛ ظهرت ثلاثة failures في suite الحالي.
- الـA/B fixture لم يكتمل ولم توجد allow/deny نتائج؛ لا تدّعِ أن 18 RLS flags أو 94 policy تثبت العزل.
- خط الأساس التاريخي 124/82/33/9 ليس نتيجة هذه الجلسة؛ نتيجة اليوم 124/53/24/42/5 كما في القسم L.
- OpenAPI المعروف من قبل لا يتأثر هنا؛ لا عقد API تغير.

## S. NEXT SINGLE RECOMMENDATION

تكليف واحد جديد، يتطلب موافقة المالك: تشخيص فجوة INSERT الخاصة بـdl_onboarding وسبب رفض إعداد tenant في RLS fixtures داخل TEST المعزول، مع اعتماد أقل grant مطلوب/إصلاح harness فقط بعد إثبات الجذر، ثم إعادة تشغيل اختبارات G3–G5 المستهدفة. النطاق لا يلمس scratch أو production ولا يبدأ Customers؛ شروط التوقف: أي اختلاف target identity، الحاجة لتغيير app/migration، أو الحاجة إلى grant أوسع من العقد الموثق. معيار القبول: privilege contract موثق، non-owner allow/deny probes وA/B ناجحة، وsuite مستهدفة بنتائج قابلة للتفسير دون errors/failures غير محلولة.

## T. NEXT-TOOL HANDOFF

ابدأ بقراءة STATUS.md ثم PLAN.md وDECISIONS.md وHANDOFF.md وAGENTS.md، ثم هذا التقرير وTARGET_MANIFEST.md وREADME.md. احتفظ ببيئة daleel-crm-acceptance وvolumeها، ولا تعِد إنشاءها. اقرأ تقرير DB-VERIFY-01 التاريخي لفهم scratch ولا تكرر اكتشافه. لا تستخدم المنفذ 5432 على المضيف، ولا تعاود تشغيل migrations أو full suite قبل معالجة targeted root cause. دليل الاختبارات الخام الخاص موجود في tools/dev-db/acceptance/.private/reports/ ولا يُنسخ للتوثيق. الخطوة الأولى هي الحصول على تفويض متابعة جديد؛ لا تنفيذ بعد هذا التقرير.

## U. COPY-READY SUMMARY FOR CHATGPT

1. نُفذ DEV-FOUNDATION-01 بتفويض Option B على I:\WORK\DALEEL-CRM بتاريخ 2026-10-24.
2. تأسست بيئة Postgres 16 جديدة: daleel-pg-acceptance، مشروع daleel-crm-acceptance.
3. DEV على 127.0.0.1:55433 وTEST على 127.0.0.1:55437؛ لا استعمال لمضيف 5432.
4. daleel-pg-scratch بقيت كما هي؛ ID والمنفذ 55432 والvolume تطابقت قبل/بعد.
5. اتصالات Laravel السبعة نجحت على DEV وTEST مع principals المقصودة.
6. شُغلت 36 migration على كل قاعدة؛ schema-only hashes متطابقة، و36 جدولًا بكل قاعدة.
7. يوجد 18 جدولًا FORCE+ENABLE RLS و94 policy؛ هذه metadata ولا تثبت A/B.
8. في TEST، dl_onboarding لا يملك INSERT على users أو الأعمدة الستة المطلوبة؛ لم تُمنح صلاحية.
9. full suite: 124 = 53 pass / 42 errors / 5 failures / 24 skipped.
10. focused runtime: 17 = 1 pass / 14 errors / 2 failures؛ A/B غير مثبت.
11. القرار PARTIAL / NO-GO؛ لا Customers ولا commit/deploy.
12. التالي يتطلب تفويضًا جديدًا لتشخيص onboarding grant وRLS fixture context ثم إغلاق G3–G5.
13. التقرير: daleel-crm-api/docs/audits/DEV-FOUNDATION-01.md؛ manifest والـJUnit محفوظة محليًا.
14. root docs خارج Git؛ احفظها بآلية منفصلة، ولا تكرر إنشاء الموارد أو استهداف scratch.

## Evidence register

| Evidence ID | Timestamp (Africa/Cairo) | Source | Claim |
|---|---|---|---|
| DF01-G0-001 | 2026-10-23 23:55 | TARGET_MANIFEST.md / preflight | Docker/image/PHP and candidate names/ports verified before creation |
| DF01-G1-001 | 2026-10-24 00:38 | Final filtered docker inspect and network metadata | New container, networks, volume, loopback mappings, project label and image identity |
| DF01-G1-002 | 2026-10-24 00:35 | Verify-Schema.ps1 scratch guard + docker metadata | Scratch ID/state/55432 mapping/volume unchanged |
| DF01-G2-001 | 2026-10-24 before 00:16 | Run-Migrations.ps1 output and migrations table | 36 source migrations in DEV and TEST |
| DF01-G2-002 | 2026-10-24 00:35 | Verify-Schema.ps1 | Schema counts and identical normalized schema-only hashes |
| DF01-G3-001 | 2026-10-24 before 00:16 | verify-connections.php and Verify-RuntimeIdentities.ps1 | Seven named connections and non-owner role identities |
| DF01-G3-003 | 2026-10-24 00:35 | Verify-Schema.ps1; ProviderControlOperationService.php:989; PROVIDER_CONTROL_OPERATIONS.md:35 | Live effective onboarding INSERT absent vs source contract |
| DF01-G4-001 | 2026-10-24 00:21:46 | focused-runtime-suite.junit.xml last write | 9 PostgresRlsIsolationTest errors; no A/B pass |
| DF01-G5-001 | 2026-10-24 00:21:30 | full-suite.junit.xml last write | Current full suite counts and five failure names |
| DF01-G5-002 | 2026-10-24 00:21:46 | focused-runtime-suite.junit.xml last write | Current focused runtime counts |
| DF01-SEC-001 | 2026-10-24 00:32 | Windows ACL inspection and .gitignore | private/reports ACL scope; ignored local outputs |
| DF01-DOC-001 | 2026-10-24 00:38 | Final Git status and workspace file list | Allowed documentation/acceptance diff only; no source repo changes |

## REMEDIATION-01 — Runtime Permissions & RLS Acceptance Recovery

**Execution date:** 2026-10-24, Africa/Cairo. **Authorization:** owner supplied the narrowly scoped REMEDIATION-01 task for the existing isolated acceptance TEST. **Scope held:** acceptance scripts, exact TEST grant, synthetic TEST fixtures, and documentation only. No application, migration, original test, RLS policy, original compose/bootstrap, DEV, scratch, frontend, or API contract files were changed. No migration, seed, reset, full suite, HTTP/DNS suite, or Customers work was started.

### Decision and current state

Result remains **PARTIAL / NO-GO**. The onboarding INSERT subcheck is now proven on TEST. G3 remains partial, G4 remains NOT_PROVEN, and G5 is NO-GO. The RLS test did not pass and its teardown left synthetic tenant identities protected by an intentional database invariant. The acceptance target is retained; no attempt was made to delete those identities, bypass the trigger, or reset TEST.

### Evidence and execution ledger

| Evidence ID | Time (Africa/Cairo) | Class | Source / command | Result |
|---|---|---|---|---|
| DF01-RM01-001 | 2026-10-24, before DB write | FACT | `Assert-AcceptanceContainer`, `target-lock.json`, `Verify-Schema.ps1`, read-only catalog identity | TEST confirmed as `daleel_crm_b10b_disposable` OID 16413, owner `daleel_b10b_owner`; container `daleel-pg-acceptance`, cluster system ID `7699972247235194919`, volume `daleel_acceptance_pg_data`, host port 55437. DEV OID 16412 remained a read-only comparison target. |
| DF01-RM01-002 | 2026-10-24, before grant | FACT | `Apply-OnboardingGrant.ps1` exact ACL pre-state | `dl_onboarding` had no table-level or column-level privilege on `public.users`; no grant option. TEST safety counts showed no tenant/business rows and only the 12 pre-existing synthetic users. |
| DF01-RM01-003 | 2026-10-24, after grant | FACT | `Apply-OnboardingGrant.ps1`; `roles-test-only.sql`; read-only `has_table_privilege` / `has_column_privilege` | Applied exactly `INSERT (id,email,password,email_verified_at,created_at,updated_at)` on `public.users` to `dl_onboarding` in TEST. After state: six named column INSERT privileges only; table-level SELECT/INSERT/UPDATE/DELETE false; other column SELECT/UPDATE false; zero grant option; owner unchanged. |
| DF01-RM01-004 | 2026-10-24, after grant | FACT | Non-owner positive and negative transaction probes in `Apply-OnboardingGrant.ps1` | `dl_onboarding` inserted one synthetic row inside an explicit transaction and rolled it back; marker count remained zero. SELECT, UPDATE, and DELETE were denied with insufficient privilege. No `SET ROLE` or fixture row persisted. |
| DF01-RM01-005 | 2026-10-24, after grant | FACT | `Verify-Schema.ps1` | 36/36 migrations in DEV and TEST; schema-only hashes identical; each DB has 36 tables, 18 ENABLE+FORCE RLS tables, 94 policies, 223 constraints, 87 indexes, 26 functions, and 15 triggers. These facts establish parity/configuration only, not A/B isolation. |
| DF01-RM01-006 | 2026-10-24, after grant | FACT | `Verify-RuntimeIdentities.ps1`; `verify-connections.php` | Eight runtime/login principals and all seven Laravel connections identified on TEST. All named runtime connections were non-superuser, NOBYPASSRLS, non-owner, and lacked schema CREATE. The default `pgsql` connection was explicitly `postgres` with `fixture_admin=true` for TEST fixture setup only; it is not runtime security proof. |
| DF01-RM01-007 | 2026-10-24 01:15:10–01:16:26 | FACT | `Run-AcceptanceTests.ps1 -Suite rls`; JUnit `remediation-01-rls-20261024T011510.junit.xml` | 9 tests, 0 pass, 6 errors, 3 failures, 0 skipped, 22 assertions, 24.49 seconds. Outer process exit status was not captured after the tool returned a running session; counts are taken from JUnit. No second test run was made to recover the exit code. |
| DF01-RM01-008 | 2026-10-24, after RLS run | FACT | Read-only aggregate counts on TEST; source migration 015; JUnit errors | TEST changed from 12 users / 0 tenants to 39 users / 18 tenants. The suite created 27 synthetic users and 18 `rls08-*` tenant identities. It removed mutable child fixtures (tenant memberships, roles, role permissions, membership roles now count 0), then `DELETE FROM tenants` raised SQLSTATE 23514 under `tenants_registry_immutable`; subsequent user cleanup did not run. The migration deliberately makes tenant identities permanent. No row identifiers or fixture values are recorded here. |
| DF01-RM01-009 | 2026-10-24, after analysis | FACT | Read-only live ACL query for `daleel_b10b_tenant_runtime` and role-group membership | The login inherits `daleel_tenant_runtime`. On the legacy tables used by `PostgresRlsIsolationTest`, table-level S/I/U/D are false for `tenants`, `tenant_memberships`, `roles`, `role_permissions`, `membership_roles`, and `users`; limited column SELECT exists on `tenants` (2 columns), `roles` (6), and `role_permissions` (4). No SELECT columns were present on `tenant_memberships`, `membership_roles`, or `users`. This explains the exact test-query permission failures; whether those legacy object grants are part of the current product contract remains unresolved. |
| DF01-RM01-010 | 2026-10-24, after analysis | STATIC_RISK + FACT | `PostgresRlsIsolationTest.php`; live TEST catalog; migration 026; `RLS_ARCHITECTURE.md` | The test asserts an older six-table RLS inventory, table-level `users` SELECT, and five role-permission rows; live B10B reports 18 RLS tables and the test observed seven role-permission rows. It also runs `count(*)`/legacy reads on `tenant_memberships`, for which the runtime role has no SELECT privilege. Do not add broad grants only to satisfy these assertions; the current contract needs owner review. |
| DF01-RM01-011 | 2026-10-24, after analysis | FACT | `Run-AcceptanceTests.ps1` preflight guard; read-only trigger metadata | Added a guard that blocks the RLS suite when the permanent tenant DELETE trigger is present. Guard validation emitted the expected stop before PHPUnit and left JUnit count unchanged. |
| DF01-RM01-012 | 2026-10-24, final review | FACT | Final repo status/HEAD and protected target checks | API HEAD `d6870839f38b1f05786288071dbe0bb7719d5386`; frontends unchanged and clean. Scratch ID, state, port 55432, and volume still match preflight. Root docs and `tools/dev-db/acceptance/` are outside Git; the API audit remains untracked. |

### Root-cause classification

تفصيل JUnit دون قيم صفوف: 4 أخطاء SQLSTATE `42501` كانت رفض صلاحية على استعلامات `tenant_memberships`؛ خطآن SQLSTATE `23514` كانا رفض حذف الهويات الدائمة في cleanup. الإخفاقات الثلاثة: جرد RLS يتوقع 6 جداول بدل 18، اختبار يتوقع table-level `users SELECT` غير الممنوح، وعدد `role_permissions` المتوقع 5 مقابل 7 live. هذه التواقيع لا تبرر توسيع المنح تلقائيًا.

| Finding | Severity / confidence | Root cause and impact | Evidence | Separate authorization needed? |
|---|---|---|---|---|
| DF01-RM01-F01 — onboarding ACL absent before remediation | High / high | The `pgsql_onboarding` service contract requires a six-column users INSERT, but TEST initially had none. The narrow grant now satisfies that TEST-only contract and passed the authorized positive/negative probe. It does not prove the direct first-admin path or any production grant. | DF01-RM01-002–004; `PROVIDER_CONTROL_OPERATIONS.md` | Yes for any DEV/production grant or broader operation. |
| DF01-RM01-F02 — RLS fixture teardown conflicts with permanent tenant identity | High / high | `PostgresRlsIsolationTest::tearDown()` deletes its created tenants, while migration 015's BEFORE DELETE trigger rejects every tenant deletion. The exception interrupts teardown before it deletes the users, leaving 18 permanent synthetic tenant identities and 27 users. Repeating the test would add more. | DF01-RM01-007–008; migration `2026_10_10_000015_create_tenant_hostname_registry.php`; JUnit | Yes to change the original test/fixture lifecycle or choose a different approved TEST strategy. No trigger bypass/reset is authorized. |
| DF01-RM01-F03 — current runtime ACL and legacy RLS test contract do not align | High / high for the attempted SQL; medium for product impact | The non-owner role receives modern column-scoped tenant-staff grants, but the legacy test attempts operations on core tables without the required object grants. Some test assertions also conflict with the current B10B schema and least-privilege column ACLs. The live 42501 failures are real for those statements; they do not establish that broader grants are appropriate for current endpoints. | DF01-RM01-009–010; `roles-pre.sql`; migration 026; `RLS_ARCHITECTURE.md` | Yes before modifying source tests, roles, migrations, or granting broader access. |
| DF01-RM01-F04 — overall acceptance remains open | High / high | No A/B test passed; the focused RLS result is red, runtime suite/full suite were not run, and full suite may reset TEST. G4 and G5 therefore remain NO-GO. | DF01-RM01-007–011 | Yes before any further suite requiring fixtures/reset or source-test changes. |

### Static-versus-live summary

| Area | Source / migration expectation | Live TEST result | Status |
|---|---|---|---|
| Migrations/schema | 36 source migrations; 18 ENABLE+FORCE RLS tables; 94 policies | 36/36; counts match in DEV/TEST; schema-only hashes equal | VERIFIED parity/configuration only |
| `dl_onboarding` users INSERT | Six-column INSERT stated in `PROVIDER_CONTROL_OPERATIONS.md` | Exact six-column grant applied; runtime insert/rollback passed; SELECT/UPDATE/DELETE denied; DEV unchanged | VERIFIED on TEST for this subcheck |
| Runtime role identity | Non-owner, non-superuser, NOBYPASSRLS, no schema CREATE | All named runtime connections met those identity flags; the fixture-only default was superuser | VERIFIED identity; not full G3 |
| Legacy tenant core ACL | RLS doc describes tenant-scoped policies; legacy test expects core table access/CRUD | Selected test SQL hit 42501 on `tenant_memberships`; effective grants are absent or column-scoped on the listed legacy tables | LIVE statement denial; intended application grant set is UNKNOWN |
| RLS behavior | Policies are present and forced | No successful non-owner A/B evidence; 9-test suite had 0 passes | NOT_PROVEN |
| HTTP/host spoof / full regression | Separate HTTP/DNS and full-suite acceptance | Not run; existing gaps and reset risk remain | NOT_EXECUTED / BLOCKED |

### Changes and process notes

- Modified acceptance files: `common.ps1` permits a `fixture-admin` default only for locked TEST; `verify-connections.php` allows that superuser identity only on the exact TEST database/port and still checks all other connections as non-owner; `Run-AcceptanceTests.ps1` captures focused results, blocks `full`, enforces pre/post aggregate checks, and now refuses RLS PHPUnit when immutable tenant cleanup is detected.
- Added `roles-test-only.sql` and `Apply-OnboardingGrant.ps1` for the idempotent, exact TEST-only grant and its probes. All modified PowerShell passed the PowerShell parser; modified PHP passed `php -l` before the database grant.
- The owner instruction required the diagnostic and grant justification to be written in this report before the grant was applied. Pre-grant ACL and target evidence were captured and reviewed, but the persistent report appendix was written after the grant; this sequencing requirement was not met. The BEFORE output is preserved in the tool transcript and this report identifies the deviation without backdating it. No other grant was attempted.
- `docs/STATUS.md`, `docs/PLAN.md`, `docs/HANDOFF.md`, this audit, `tools/dev-db/acceptance/README.md`, and `TARGET_MANIFEST.md` were updated. `docs/DECISIONS.md` was read but not changed because no new architectural decision was made. Root docs and acceptance tools are outside Git and need owner-controlled preservation; the API repo does not own them.

SHA-256 continuity check: the following files expected to remain untouched matched their captured pre-run digests: `AGENTS.md` = `F562A5AD8214DC9644DE00B9CE64E8792B08FB20E421AD055C7FFEBE8EA4EB2D`; `docs/DECISIONS.md` = `53536169F35785D55943DF3ED398939ACDABE0607D23C53F8B3CACF2B1F05FDF`; `PostgresRlsIsolationTest.php` = `9EA386BDF37DA3301DA076E310260C1F3CD9FFE6C2B06DEF6BE723888DEFDFE7`; `CompanyAdminBootstrap.php` = `F922733E7813EFCD11E3EB8555C52D287E11A7816F1EE1AD8A21F853970EE853`; `create_users_table` migration = `B7894246A68D8150C4E5C0B7C62EAEEDA3B1EB225F24A982C23D9AACC916EF53`; `enable_tenant_rls` migration = `2E633FC4177FBAF3F6E921D0B3AC48F08B85002A4E97034A3C106A3007A5F592`; `ProviderControlOperationService.php` = `0783A0824EAD671F78DBD6BA3F18762249D75906DCFC9F6F8874CDD6FC0146E8`. Acceptance/doc files changed are listed in the handoff; their post-edit hashes were captured at final review. These digests confirm no app/source/test/migration edits in this remediation.

### Gate decision and next owner step

- **G3:** PARTIAL. Onboarding's exact TEST privilege contract is verified; other application/runtime permission contracts were not accepted, and the legacy test statements encounter live privilege denials.
- **G4:** BLOCKED / NOT_PROVEN. No non-owner A/B suite passed. The existing test expects a different schema/ACL contract and cannot clean its permanent tenant fixtures.
- **G5:** NO-GO. The targeted suite failed. Runtime and full suites were not run; full suite remains unsafe while `RefreshDatabase` paths can reset TEST.
- **Overall:** PARTIAL / NO-GO. Do not start Customers, reset the target, remove permanent tenant identities, disable triggers, or rerun suites.

**Single next step:** owner to approve a dedicated RLS test-contract and fixture-lifecycle remediation for the current B10B schema, including a decision for the 18 permanent synthetic tenant identities now in TEST. That approval must define cleanup/rollback without bypassing the tenant registry invariant. Acceptance criteria: a non-owner raw A/B test that matches the current schema and least-privilege grants, no persistent fixture residue, and then a bounded runtime regression run. Any need for source-test, migration, policy, or broader role changes remains outside this task until explicitly approved.

### Evidence paths

- Private JUnit: `tools/dev-db/acceptance/.private/reports/remediation-01-rls-20261024T011510.junit.xml`.
- Private stdout/stderr: matching `.stdout.log` and `.stderr.log` under the same ignored `.private/reports/` directory.
- Private SHA-256 ledger (pre/post hashes for scoped files and unchanged source): `tools/dev-db/acceptance/.private/reports/remediation-01-hashes.txt`.
- Acceptance grant script/SQL: `tools/dev-db/acceptance/Apply-OnboardingGrant.ps1` and `tools/dev-db/acceptance/roles-test-only.sql`.
- Latest state and safe-stop instructions: root `docs/STATUS.md`, `docs/PLAN.md`, `docs/HANDOFF.md`, `tools/dev-db/acceptance/README.md`, and `TARGET_MANIFEST.md`.

## REMEDIATION-02 — RLS Test Contract & Fixture Lifecycle Recovery

**التاريخ المرجعي:** 2026-10-24، Africa/Cairo. **الأداة/الأدوار:** Claude Code — Backend + QA/Security + Docs. **التفويض:** تكليف المالك DEV-FOUNDATION-01 / REMEDIATION-02 (إنشاء قاعدة جديدة واحدة فقط باسم `daleel_crm_rm02_isolated` داخل cluster القبول على 127.0.0.1:55437، وتعديل `PostgresRlsIsolationTest.php` وملفات acceptance والتوثيق فقط). لا قرار ADR جديد؛ `docs/DECISIONS.md` لا يتغير.

### RM02 — PRE-WRITE DIAGNOSIS RECORDED (كُتب هذا القسم على القرص قبل أي كتابة على أي قاعدة بيانات)

#### G0 — Pre-flight (قراءة فقط)

| Evidence ID | الدليل | النتيجة |
|---|---|---|
| DF01-RM02-001 | `git rev-parse`/`git status --short` للمستودعات الأربعة | API HEAD `d6870839f38b1f05786288071dbe0bb7719d5386` (فرع `phase-0-stabilize-baseline`) والمتغير الوحيد `?? docs/audits/`؛ marketing `6fb01b88…`، admin `9fa43bef…`، super-admin `a802e44b…` نظيفة. |
| DF01-RM02-002 | ledger خاص `.private/reports/remediation-02-hashes-before.txt` | بصمات AGENTS.md وDECISIONS.md و`PostgresRlsIsolationTest.php` مطابقة لبصمات REMEDIATION-01؛ بصمات تجميعية لـmigrations وapp+routes وtests محفوظة للمقارنة اللاحقة. |
| DF01-RM02-003 | `docker inspect` (Bash) | الحاوية `daleel-pg-acceptance` ID `d6ce6f4c1e92…2908`، image digest `sha256:9e2cf628…0a97`، running/healthy، مشروع `daleel-crm-acceptance`، volume `daleel_acceptance_pg_data`، المنفذان 127.0.0.1:55433 و127.0.0.1:55437 → 5432، IP الحلقة 172.19.0.2 — مطابق لـ`target-lock.json`. scratch: ID `b05a2967…`، running، 127.0.0.1:55432، volume `e6b3342f…` — مطابق. |
| DF01-RM02-004 | SELECT كتالوجي read-only (`default_transaction_read_only=on`) | system identifier `7699972247235194919`، PostgreSQL 16.15؛ القواعد: DEV OID 16412، TEST القديمة OID 16413، postgres OID 5؛ **`daleel_crm_rm02_isolated` غير موجودة (0)**؛ لا جلسات عميل أخرى نشطة (لا concurrency)؛ أدوار runtime كلها NOSUPERUSER/NOBYPASSRLS/NOCREATEDB/NOCREATEROLE. |
| DF01-RM02-005 | عدّادات تجميعية فقط | DEV: صفر صفوف أعمال، 36 migration، 18 جدول ENABLE+FORCE RLS، 94 policy. TEST القديمة: 39 users، 18 tenants، 0 memberships/roles، 1 security_audit_event، 36/18/94 — **PRESERVE_AS_IS**، لا تُلمس. |
| DF01-RM02-006 | البيئة | `pwsh` (PowerShell 7) **غير مثبت** على هذا المضيف؛ PowerShell 5.1 يكسر قوالب `docker inspect` في `common.ps1` (خطأ template parsing ظهر في فحص read-only). لذلك أدوات الهدف الجديد تُكتب بـPHP 8.4.27 (Herd، فيه pdo_pgsql/intl/fileinfo) مع `proc_open` بمصفوفة وسائط وبيئة، بلا أسرار في argv، ولا تُعدَّل سكربتات B10B القائمة. |
| DF01-RM02-008 | `has_table_privilege`/`has_column_privilege` كتالوجي على TEST القديمة لـ`daleel_b10b_tenant_runtime` (36 جدولًا) | لا INSERT/UPDATE/DELETE على أي جدول؛ SELECT أعمدة فقط على `tenants(id,status)`، `tenant_staff_users` (بدون `password_hash`)، `tenant_staff_memberships`، `tenant_staff_membership_roles`، `tenant_staff_permission_grants`، `roles`، `role_permissions`، `permissions`؛ لا شيء على `users`/`tenant_memberships`/`membership_roles`/`leads`/`tenant_staff_security_events`/`tenant_subscriptions`/`tenant_limit_overrides`. |
| DF01-RM02-009 | JUnit REMEDIATION-01 (أسماء الاختبارات وSQLSTATE فقط، بلا payload) | 4 errors = 42501 مرجعها `tenant_memberships`؛ 2 errors = 23514 في tearDown بعد نجاح 8 و6 assertions على A/B لـ`tenants`؛ 3 failures = توقعات قديمة. |
| DF01-RM02-007 | ملاحظة إجرائية | بحث Grep على مستوى مساحة العمل طابق ملف `.private/acceptance.pgpass` وأظهر سطرًا منه في مخرجات الأداة المحلية. لم تُنسخ القيمة إلى أي ملف أو تقرير، وتُستبعد `.private` من أي بحث لاحق. يُنصح المالك بتدوير كلمات مرور القبول المحلية عند أي مراجعة لاحقة (بيئة محلية فقط). |

#### G1 — مصفوفة العقد (Contract Matrix)

العقد الحالي لمبدأ runtime الخاص بالـtenant (`daleel_b10b_tenant_runtime` ← `daleel_tenant_runtime`) معرّف كاملًا في migration 026 (السطور 229–236): **SELECT على أعمدة محددة فقط** لـ`tenants(id,status)`، `tenant_staff_users`، `tenant_staff_memberships`، `tenant_staff_membership_roles`، `tenant_staff_permission_grants`، `roles`، `role_permissions`، `permissions`. لا INSERT/UPDATE/DELETE على أي جدول، ولا أي صلاحية على `users`/`tenant_memberships`/`membership_roles`/`leads`/`tenant_staff_security_events`/`tenant_subscriptions`. أُكّد ذلك حيًّا على TEST القديمة بدوال `has_table_privilege`/`has_column_privilege` (DF01-RM02-008). المسار القديم (global `users` + `tenant_memberships`) أُخرج من HTTP في Phase 0؛ صلاحيات runtime القديمة (Control 08) لم تُعرَّف في أي migration أو bootstrap مصدري، وكانت تُمنح يدويًا في harnesses سابقة.

| Test (REMEDIATION-01) | العقد الأمني المقصود | افتراض الاختبار القديم | دليل المصدر | ACL/الكتالوج الحي | السبب الجذري | الفئة |
|---|---|---|---|---|---|---|
| `test_exact_table_policy_inventory_and_runtime_role_flags` | جرد RLS دقيق + هوية runtime غير مالكة | 6 جداول (+outbox لـ10c)، 20 policy | migrations 008/015/023–026/033/036 | 18 جدول ENABLE+FORCE، 94 policy | توقع تاريخي قبل B10B | stale test |
| `test_no_context_and_invalid_context_deny_all_five_tables_and_writes` | بلا context: صفر صفوف، والكتابة مرفوضة | SELECT على `tenant_memberships`/`membership_roles` ممنوح | migration 026 لا تمنح الجدولين | `tenant_memberships`: لا SELECT → 42501 | الاختبار يقرأ نموذجًا قديمًا غير ممنوح | stale test |
| `test_tenant_runtime_cannot_mutate_global_identity_rows_directly` | runtime لا يعدّل الهوية العامة | `users` SELECT = true | لا grant على `users` في المصدر | `users`: SELECT=false | العقد الحالي أضيق (أقل صلاحية) | stale test |
| `test_discovery_exposes_only_server_user_active_membership` | discovery يكشف عضوية الفاعل النشطة فقط | `TENANT_DISCOVERY` على `tenant_memberships` | نموذج tenant-staff بلا discovery (host-first) | 42501 على `tenant_memberships` | سطح discovery القديم خارج عقد runtime | stale test |
| `test_raw_a_b_select_update_delete_insert_and_own_write` | عزل A/B، والكتابة الذاتية تمر عبر WITH CHECK | 5 role_permissions، و runtime يملك كتابة على `roles` | migration 036 أضافت leads.* للقالب (7)؛ 026 لا تمنح كتابة | 7 صفوف؛ لا INSERT/UPDATE/DELETE | توقع عدد قديم + افتراض grant كتابة غير موجود | stale test (+ انظر F05) |
| `test_same_backend_connection_a_b_none_and_rollback_exception_reset` | GUC محلي للمعاملة لا يتسرب | — | — | 8 assertions نجحت ثم 23514 في tearDown | `DELETE FROM tenants` يصطدم بـ`tenants_registry_immutable` (migration 015) | fixture lifecycle |
| `test_two_simultaneously_open_runtime_transactions_keep_a_and_b_separate` | اتصالان متزامنان لا يتشاركان context | — | — | 6 assertions نجحت ثم 23514 في tearDown | نفس السبب | fixture lifecycle |
| `test_real_laravel_runtime_role_resolver_guard_and_rbac_freshness` | مسار Laravel الحقيقي + تحديث RBAC فورًا | `ResolveTenantContext` القديم عبر `tenant_memberships` | HTTP يستخدم `TenantStaffContextGuard`/`TenantStaffAuthorizationService` | 42501 على `tenant_memberships` | يختبر مسارًا متقاعدًا | stale test |
| `test_nested_transaction_scope_restores_previous_context_and_global_disable_preserves_admin` | context متداخل يُستعاد + آخر مدير محمي | `RlsDatabaseContext` + `UserAccountStatusService` على `users` | المسار الحالي `TenantStaffAdminInvariant` | 42501 على `tenant_memberships` | يختبر مسارًا متقاعدًا | stale test |

**تصنيف G1:** 7 stale test، 2 fixture lifecycle، 0 missing documented grant، 0 unknown. لا يتطلب أي إصلاح منح grant إضافي على الهدف الجديد: كل ما يحتاجه الاختبار المعدّل ممنوح أصلًا بـmigration 026.

#### نتائج ثابتة جديدة (خارج إصلاح هذه الجولة — تحتاج قرار مالك)

| Finding | الشدة/الثقة | الوصف | الدليل | الإجراء |
|---|---|---|---|---|
| DF01-RM02-F05 | **P1 / عالية** | خدمات Phase 2 (`TenantStaffRoleMutationService`، `TenantStaffAccountService`، `TenantStaffAuditWriter`، `LeadService`) تكتب/تقرأ عبر `pgsql_tenant_runtime`، لكن العقد الحالي لا يمنح هذا المبدأ أي INSERT/UPDATE/DELETE، ولا أي صلاحية على `leads` أو `tenant_staff_security_events`. في أي نشر بمبدأ غير مالك ستفشل هذه المسارات بـ42501. اختبارات Phase 2 السابقة (جلسة 2026-10-23) أُجريت على scratch مع `GRANT ALL` واسع فأخفت الفجوة. | migration 026:229–236؛ migration 036 (`REVOKE ALL ON leads FROM PUBLIC` بلا GRANT)؛ DF01-RM02-008 | يحتاج migration منح أعمدة دقيقة + اختبارات A/B للكتابة — **خارج النطاق، STOP لهذا المسار**. |
| DF01-RM02-F06 | P2 / عالية | سياسات `tenants`/`tenant_staff_users`/`tenant_staff_memberships`/`roles`/`role_permissions` تربط الصف بالـtenant فقط، لا بالفاعل؛ ربط الفاعل يحدث في `TenantStaffContextGuard` وفي سياسات `tenant_staff_membership_roles`/`tenant_staff_permission_grants` فقط. GUC مزوَّر داخل اتصال runtime يكشف صفوف tenant آخر في الجداول الأولى. هذا حد موثق في `RLS_ARCHITECTURE.md` («Custom GUCs … could be forged»)، لا عيبًا جديدًا. | migrations 008/023/024 | توثيق؛ يُختبر أن الجداول المرتبطة بالفاعل تعيد صفرًا مع context مزوّر. |

#### G2 — تصميم دورة حياة fixtures (معتمد قبل التنفيذ)

1. **قاعدة واحدة جديدة:** `CREATE DATABASE daleel_crm_rm02_isolated OWNER daleel_b10b_owner TEMPLATE template0 ENCODING 'UTF8'` — نفس صيغة إنشاء DEV/TEST في `Initialize-Acceptance.ps1`. يُرفض الإنشاء إن وُجدت القاعدة أو ملف القفل `.private/rm02-lock.json`، أو إن لم يكن هذا القسم موجودًا في التقرير. لا أدوار جديدة: الأدوار cluster-wide موجودة من `roles-pre.sql`.
2. **schema:** الـ36 migration واحدة واحدة بمبدأ المالك `daleel_b10b_owner` (نفس منطق `Run-Migrations.ps1`)، ثم `roles-post.sql` كما هو (منح provider الضيقة). **لا** `roles-test-only.sql` (غير لازم للعزل)، ولا أي grant إضافي.
3. **fixtures ثابتة ومحددة وغير متراكمة** (`rm02-fixtures.sql`، معاملة واحدة كمبدأ `postgres` على القاعدة الجديدة فقط، UUIDs اصطناعية ثابتة، بريد `@proof.invalid`): مستخدم provider اصطناعي واحد، عمليتا `company.provision` بحالة SUCCEEDED (لإثبات provenance المطلوب بواسطة trigger `tenant_staff_membership_creator_valid` دون تعطيله)، tenantان `rm02-a` و`rm02-b` (ACTIVE)، صف `tenant_registry_domains` واحد (`acceptance.localhost`، LOCAL_TEST)، hostnameان، 3 أدوار (company_admin لكل tenant + `rm02_viewer` بلا صلاحيات في A)، صلاحيات القالب منسوخة، 4 موظفين/عضويات (admin-a، reader-a، suspended-a بعضوية SUSPENDED، admin-b)، 4 إسنادات أدوار، منحتان مباشرتان `member.view`. الإنشاء يتم مرة واحدة؛ إعادة التشغيل تتحقق من البصمة وتنتهي no-op؛ أي حالة جزئية = STOP.
4. **لا حذف لأي هوية:** لا DELETE على `tenants`/`tenant_hostnames`/`tenant_staff_*`، ولا تعطيل trigger، ولا `session_replication_role`. الضبط الوحيد لـGUC هو `set_config('app.user_id', …, true)` داخل معاملة الـfixture ليطابق شرط trigger «المنشئ هو الفاعل النشط»، كما يفعل التطبيق.
5. **البيانات القابلة للتغيير أثناء الاختبار:** صف واحد فقط `role_permissions(rm02_viewer, role.view)` يُدرج ويُحذف (صافي صفر) لإثبات تحديث RBAC؛ `setUp`/`tearDown` يطبّعانه. باقي البراهين داخل معاملات runtime تُعمل لها rollback.
6. **ترتيب الالتزام:** fixtures ملتزمة قبل PHPUnit لأن اتصال runtime المستقل لا يرى بيانات غير ملتزمة. تعديل `role_permissions` في اختبار التحديث يتم بالتزام على اتصال fixture المنفصل بين استدعاءات runtime (READ COMMITTED).
7. **تصنيف نهاية الجولة:** fixtures تبقى في القاعدة الجديدة = **ISOLATED_PENDING_OWNER_DISPOSAL**؛ لا DROP.

#### G3 — تغييرات الاختبار المقترحة (قبل التعديل)

- allowlist صارم: `current_database() = 'daleel_crm_rm02_isolated'` و port 55437 و system identifier `7699972247235194919` و OID القاعدة مطابق لـ`ACCEPTANCE_RM02_DB_OID` (من ملف القفل). تُزال أهداف b08/b10a/b10b/b10c القديمة لأن التوقعات الجديدة تخص schema B10B الحالية فقط، ولمنع أي تشغيل على TEST القديمة.
- `setUp` يقرأ fixtures بالـslug ولا ينشئ أو يحذف tenants؛ fixtures مفقودة = فشل صريح لا skip.
- خريطة الأسماء (لا حذف لتغطية؛ إعادة تسمية حيث تغيّر المعنى):

| القديم | الجديد | التغطية |
|---|---|---|
| `test_exact_table_policy_inventory_and_runtime_role_flags` | نفس الاسم | جرد 18 جدولًا بالاسم + 94 policy + هوية runtime + عضوية الدور الوحيدة + لا ملكية + لا CREATE |
| `…deny_all_five_tables_and_writes` | `test_no_context_and_invalid_context_deny_reads_and_writes` | صفر صفوف بلا/بسياق خاطئ على 7 جداول مقروءة؛ الكتابة 42501 (object-level)؛ الجداول غير الممنوحة 42501 |
| `test_tenant_runtime_cannot_mutate_global_identity_rows_directly` | نفس الاسم | `users` بلا أي صلاحية (أضيق من القديم)؛ `tenant_staff_users` لا كتابة ولا قراءة `password_hash` حتى داخل context صحيح |
| `test_discovery_exposes_only_server_user_active_membership` | `test_discovery_mode_and_inactive_or_forged_actor_expose_no_staff_access` | `TENANT_DISCOVERY` لا يكشف شيئًا؛ فاعل SUSPENDED أو context مزوّر لا يرى إسنادات/منح؛ الفاعل النشط يرى إسنادات tenant-ه فقط |
| `test_raw_a_b_select_update_delete_insert_and_own_write` | `test_raw_a_b_select_isolation_and_write_denial` | A يرى صفوف A فقط و B يرى B فقط (مقارنة بمجموعات fixture لا أرقام ثابتة)؛ الكتابة الذاتية والعابرة 42501 |
| `test_same_backend_connection_…` | نفس الاسم | كما هو، مع admin لكل tenant |
| `test_two_simultaneously_open_runtime_transactions_…` | نفس الاسم | كما هو |
| `test_real_laravel_runtime_role_resolver_guard_and_rbac_freshness` | `test_real_laravel_host_resolver_staff_guard_and_rbac_freshness` | `TenantHostResolver` (dl_host) + `TenantStaffContextGuard` + `TenantStaffAuthorizationService::listRoles` تحت المبدأ غير المالك؛ منح/سحب `role.view` يظهر فورًا؛ رفض العضو المعلق وجلسة A على host B وإصدار تفويض قديم |
| `test_nested_transaction_scope_…_global_disable_preserves_admin` | `test_savepoint_rollback_restores_context_and_last_admin_invariant_is_tenant_bound` | استعادة context بعد ROLLBACK TO SAVEPOINT؛ `TenantStaffAdminInvariant` ينجح لـA ويفشل مغلقًا لـB تحت context A |

- **تغطية لم تعد قابلة للإثبات تحت العقد الحالي (تُوثّق ولا تُخفى):** نجاح الكتابة الذاتية عبر RLS WITH CHECK لمبدأ runtime (لا grant كتابة — F05)؛ ترشيح صفوف `leads` (لا grant)؛ ترشيح صفوف الجداول القديمة `tenant_memberships`/`membership_roles`/`users` ومسار `UserAccountStatusService` (مسار متقاعد بلا grant). هذه تُسجّل NOT_PROVEN/NOT_EXECUTED، ويُستبدل بها إثبات الرفض على مستوى الكائن.

#### الأوامر المتوقعة والتوقف

- `php tools/dev-db/acceptance/rm02-tool.php preflight` (قراءة فقط) ← `create-db` ← `migrate` ← `fixtures` ← `verify` (قراءة فقط) ← `probe` (raw A/B، معاملات rollback) ← `test` (PHPUnit مقيد بـ`PostgresRlsIsolationTest` فقط).
- كل أمر يعيد فحص: هوية الحاوية/الصورة/volume/المنافذ مقابل `target-lock.json`، system identifier، `inet_server_port()=5432` و`inet_server_addr()=172.19.0.2`، واسم/OID القاعدة مقابل `rm02-lock.json`، وscratch دون تغيير. أي اختلاف = STOP بلا إعادة محاولة تلقائية.
- `test` يرفض أي ملف اختبار يحوي `RefreshDatabase|DatabaseMigrations|migrate:fresh|db:wipe|TRUNCATE`، ويقارن عدادات fixtures قبل/بعد (أي انحراف = STOP)، ويحفظ stdout/stderr/JUnit في `.private/reports/` مع exit code صريح.
- **Rollback/Stop:** لا يوجد rollback مدمر مصرح به. عند فشل الإنشاء/migration تبقى القاعدة الجديدة كما هي للمراجعة (لا DROP). لا full suite، ولا runtime suite، ولا أي تشغيل على DEV/TEST القديمة/scratch.

### RM02 — سجل التنفيذ (بعد تسجيل التشخيص أعلاه)

| Evidence ID | الوقت (UTC؛ Cairo = UTC+3) | الأمر | النتيجة |
|---|---|---|---|
| DF01-RM02-010 | 2026-10-23 ~22:52 | `php -l` + تحميل الصنف بـReflection | الملفات الثلاثة نظيفة. Reflection كشف تعارضين مع أسماء موروثة (`count()` من PHPUnit و`session()` من Laravel TestCase) فأُعيدت تسميتهما `visible()`/`staffSession()` قبل أي تشغيل؛ 9 test methods محمّلة. |
| DF01-RM02-011 | ~22:53 | `rm02-tool.php preflight` (قراءة فقط) | هوية الحاوية/المشروع/volume/IP/المنفذ مطابقة؛ scratch مطابقة؛ system id مطابق؛ `RM02_EXISTS=false`؛ `OTHER_CLIENT_SESSIONS=0`. |
| DF01-RM02-012 | ~22:53 | `create-db` | أُنشئت `daleel_crm_rm02_isolated` **OID 21227**، المالك `daleel_b10b_owner`، template0، UTF8؛ قُفلت في `.private/rm02-lock.json` (disposal = ISOLATED_PENDING_OWNER_DISPOSAL). |
| DF01-RM02-013 | ~22:54 | `migrate` | الاتصالات السبعة تحققت على RM02 قبل البدء؛ 36/36 migration كل واحدة بعد فحص هوية الاتصال الافتراضي؛ ثم `roles-post.sql` كما هو على RM02 فقط. |
| DF01-RM02-014 | ~22:55 | `fixtures` ×2 | الإنشاء نجح من المحاولة الأولى مع كل triggers مفعّلة؛ التشغيل الثاني no-op بنفس البصمة (إثبات عدم التراكم): 2 tenants، 2 hostnames، 1 registry domain، 4 staff/4 memberships، 3 roles، 14 role_permissions (2×7)، 0 viewer grant، 4 assignments، 2 direct grants، 1 provider user، 2 operations، 0 users/legacy memberships/leads/audit events. |
| DF01-RM02-015 | ~22:55 | `verify` (قراءة فقط) | 36 migrations/36 tables/18 ENABLE+FORCE RLS/94 policies/15 triggers، trigger حذف tenant مفعّل؛ **بصمة pg_dump schema-only (شاملة ACL والملكية) = DEV** (`ffc2c38c…50cc`)؛ 8 مبادئ login: لا superuser/bypassrls/createdb/createrole/schema CREATE/ملكية؛ **ACL الـtenant runtime يطابق migration 026 حرفيًا** (SELECT أعمدة على 8 جداول، صفر صلاحيات جدولية أو كتابة على 36 جدولًا)؛ `dl_onboarding` بلا INSERT على `users` في RM02 (لم يُطبّق `roles-test-only.sql`). |
| DF01-RM02-016 | ~22:56 | `probe` (raw SQL بمبدأ `daleel_b10b_tenant_runtime`) | **64 PASS / 0 FAIL**: بلا context/سياق غير صالح/mode خاطئ = 0 صفوف على 7 جداول؛ A يرى صفوفه فقط (1/3/3/3/1/2/7) وB صفوفه فقط (1/1/1/1/1/1/7)؛ أدوار الطرف الآخر = 0؛ 9 عبارات object-level لكل tenant = 42501؛ فاعل معلّق ومزوّر = 0 إسنادات/منح؛ context يُمسح بعد rollback؛ negative control بالمبدأ fixture يرى البيانات. ملاحظة F06 مؤكدة: context مزوّر يكشف tenants/staff/roles لـB (1/1/1). البصمة بعد الفحص بلا تغيير. |
| DF01-RM02-017 | 22:56:50Z | `test` (PHPUnit `PostgresRlsIsolationTest`) | **9 tests / 9 passed / 165 assertions / 0 errors / 0 failures / 0 skipped، exit 0**، 8.26s؛ stderr فارغ؛ البصمة قبل = بعد. JUnit: `.private/reports/remediation-02-rls-20261023T225650Z.junit.xml`. |
| DF01-RM02-018 | 22:57:32Z | `guard-selftest` | رفض الاتصال بأسماء DEV/TEST القديمة/scratch قبل أي شبكة (exit 2 ×3)؛ تشغيل اختبار بقفل OID خاطئ فشل مغلقًا في `setUp` (exit 2، «Refusing RLS proof…»)؛ لا انحراف fixtures. |
| DF01-RM02-019 | 22:57:40Z | `test` مرة ثانية | نفس النتيجة 9/9، 165 assertions، exit 0، 4.6s، بلا انحراف — قابلية التكرار مثبتة دون مضاعفة هويات. |
| DF01-RM02-020 | ~22:58 | عدادات تجميعية read-only + ledger بعد + Git | DEV بلا تغيير (0 صفوف، 36/18/94، onboarding=false)؛ TEST القديمة بلا تغيير (39 users، 18 tenants، 1 audit event، onboarding column grant باقٍ من RM01)؛ قواعد cluster: أُضيفت RM02 فقط؛ أدوار `dl_*/daleel_*` = 15 بلا إضافة؛ بصمات migrations وapp+routes وAGENTS وDECISIONS بلا تغيير؛ المتغير المتتبع الوحيد `M tests/Feature/Tenancy/PostgresRlsIsolationTest.php`. |

### REMEDIATION-02 — التقرير النهائي (A–U)

**A. EXECUTIVE SUMMARY.** صُحّح عقد اختبار RLS ليطابق عقد runtime الحالي (migration 026)، وصُمّمت fixtures دائمة ومحددة لا تحتاج حذف أي هوية tenant، وأُنشئت قاعدة معزولة واحدة `daleel_crm_rm02_isolated` (OID 21227). أثبت مبدأ غير مالك وغير superuser وNOBYPASSRLS عزل A/B للقراءة عبر SQL خام (64/64) وعبر PHPUnit (9/9، 165 assertions، مرتين)، شاملًا مسار Laravel الحقيقي (host resolver + staff guard + RBAC freshness + last-admin invariant). **النتيجة: G4 PASS ضمن نطاق العقد الحالي؛ G3 PARTIAL؛ G5 PARTIAL؛ القرار العام NO-GO لـCustomers** بسبب F05 (مسارات كتابة Phase 2 بلا grants).

**B. SCOPE & AUTHORIZATION.** مسموح ونُفّذ: قراءة المشروع، إنشاء القاعدة المسماة فقط، migrations وroles-post عليها، fixtures اصطناعية عليها، تعديل `PostgresRlsIsolationTest.php` و`verify-connections.php`، ملفات acceptance جديدة، والتوثيق. غير منفذ (غير مسموح): أي DROP/reset/حذف، أي لمس لـDEV/TEST القديمة/scratch سوى SELECT تجميعي وpg_dump schema-only للـDEV، كود أعمال/migrations/policies/openapi/واجهات، أدوار جديدة، GRANT إضافي، تثبيت حزم، Git stage/commit/push.

**C. READ-FIRST / SOURCE CHECKPOINT.** قُرئت AGENTS/STATUS/PLAN/DECISIONS (D-12)/HANDOFF/ARCHITECTURE، `daleel-crm-api/AGENTS.md`، RLS_ARCHITECTURE، TENANT_STAFF_*، تقرير DEV-FOUNDATION-01 كاملًا، TARGET_MANIFEST وREADME، الاختبار المصدر، migrations 003/006/007/008/011/014/015/021/023/024/026/036 والخدمات ذات الصلة. API HEAD `d6870839…` (فرع `phase-0-stabilize-baseline`)، الواجهات `6fb01b88`/`9fa43bef`/`a802e44b`.

**D. PRE-FLIGHT SAFETY.** الحاوية `daleel-pg-acceptance` (`d6ce6f4c1e92…`)، image `sha256:9e2cf628…`، volume `daleel_acceptance_pg_data`، cluster `7699972247235194919`، PostgreSQL 16.15، loopback 55433/55437→5432، IP 172.19.0.2؛ DEV OID 16412، TEST القديمة OID 16413، RM02 OID 21227. لا جلسات متزامنة. host 5432 لم يُستخدم. `pwsh` غير مثبت فكُتبت الأدوات بـPHP 8.4.27.

**E. CONTRACT MATRIX.** انظر جدول G1 أعلاه (9 حالات: 7 stale test، 2 fixture lifecycle).

**F. ROOT CAUSES.** (1) الاختبار المصدر يستهدف نموذج global-users/`tenant_memberships` المتقاعد ويفترض grants لم تُعرَّف في المصدر (migration 026:229–236 هي العقد) → 4×42501 و3 توقعات قديمة (6 جداول بدل 18 — migrations 015/023–026/033/036؛ `users` SELECT؛ 5 role_permissions بدل 7 — migration 036). (2) `tearDown` يحذف tenants بينما migration 015:65 تمنع ذلك دائمًا → 2×23514 (DF01-RM02-009).

**G. FIXTURE LIFECYCLE DESIGN.** fixtures ثابتة بمعرفات اصطناعية ثابتة في `rm02-fixtures.sql`، تُنشأ مرة واحدة كمعاملة واحدة، وتُتحقق كبصمة؛ إعادة التشغيل no-op، والحالة الجزئية STOP. provenance الحقيقي عبر عمليتي `company.provision` اصطناعيتين يرضي triggers دون تعطيلها. الصف الوحيد القابل للتغيير (`role_permissions` لدور viewer) صافي صفر ويُطبَّع في setUp/tearDown. الحد الأقصى للهوية: 2 tenants، 4 staff، 1 provider user — لا يزيد مهما تكرر التشغيل (DF01-RM02-014/019).

**H. NEW ISOLATED TARGET.** أُنشئت: `daleel_crm_rm02_isolated`، OID 21227، المالك `daleel_b10b_owner`، داخل cluster القبول عبر 127.0.0.1:55437 → 5432. لا حاوية/volume/دور جديد. لا STOP.

**I. SOURCE TEST & RUNNER DIFF.** `tests/Feature/Tenancy/PostgresRlsIsolationTest.php` أعيدت كتابته (خريطة الأسماء في G3 أعلاه؛ allowlist مقتصر على RM02 + port + system id + OID). `tools/dev-db/acceptance/verify-connections.php`: يسمح بمبدأ fixture-admin على RM02 فقط بشرط تطابق OID الحي مع القفل. جديد: `rm02-tool.php` (preflight/create-db/migrate/fixtures/verify/probe/test/guard-selftest؛ لا أمر حذف) و`rm02-fixtures.sql`. لم تُعدّل سكربتات PowerShell القائمة.

**J. GRANTS / ROLE VALIDATION.** لا GRANT جديد خارج `roles-post.sql` المعتاد. ACL مبدأ tenant runtime على RM02 يطابق migration 026 حرفيًا، وكل مبادئ login الثمانية least-privilege (DF01-RM02-015). المبدأ الافتراضي في PHPUnit هو `postgres` لإعداد/قراءة fixtures فقط ولا يُستخدم دليلًا على العزل.

**K. RAW A/B RESULTS.** 64/64 PASS (DF01-RM02-016). مثبت: ترشيح صفوف RLS للقراءة على 7 جداول tenant (tenants، tenant_staff_users، tenant_staff_memberships، tenant_staff_membership_roles، tenant_staff_permission_grants، roles، role_permissions)، والرفض على مستوى الكائن (42501) للكتابة ولـ`leads`/`users`/`tenant_memberships`/`password_hash`/`tenant_staff_security_events`. **غير مثبت:** عزل الكتابة عبر RLS WITH CHECK لمبدأ runtime، وترشيح صفوف `leads` والجداول القديمة — لعدم وجود grants (F05).

**L. FOCUSED / REGRESSION TESTS.** `PostgresRlsIsolationTest`: 9 tests، 9 passed، 0 errors، 0 failures، 0 skipped، 165 assertions، exit 0، 8.26s (ثم 4.6s في التكرار). negative control: exit 2 مغلقًا. **NOT_EXECUTED:** runtime suites (`SecurityAuditRuntimeRoleTest`/`ProviderRuntimeRoleTest`/`ProviderConcurrencyTest` مثبتة على اسم B10B القديم، وأحدها يحذف tenants) وfull suite (6 ملفات تستخدم `RefreshDatabase`/reset). JUnit خاصة: `remediation-02-rls-20261023T225650Z`، `remediation-02-rls-20261023T225740Z`، `remediation-02-negative-control-20261023T225732Z`.

**M. FIXTURE INVENTORY.** TEST القديمة: **PRESERVE_AS_IS** — 18 tenant identities، 39 users (27 من RM01)، 1 security audit event؛ قرار التخلص معلّق للمالك. RM02: 2 tenants، 2 hostnames، 1 registry domain، 4 staff/memberships، 3 roles، 14 role_permissions، 4 assignments، 2 direct grants، 1 provider user، 2 provider operations — **ISOLATED_PENDING_OWNER_DISPOSAL** (لا يوصف CLEAN). DEV: فارغة كما هي.

**N. SECURITY REVIEW.** لم يُضعف شيء: FORCE/ENABLE RLS، trigger حذف tenant، والسياسات بلا تغيير (بصمة migrations ثابتة، trigger مفعّل). لا SUPERUSER/BYPASSRLS/GRANT ALL لأي runtime. الاختبار المعدل أضيق من القديم (`users` بلا SELECT، `password_hash` بلا قراءة، allowlist أضيق). الأسرار لم تُطبع ولم تُمرر في argv. ملاحظة: مخرجات أداة بحث محلية أظهرت سطرًا من ملف pgpass الخاص (DF01-RM02-007) — لم يُنسخ؛ يُوصى بتدوير كلمات مرور القبول.

**O. DOCUMENTATION DIFF.** هذا الملحق؛ `docs/STATUS.md` و`docs/PLAN.md` و`docs/HANDOFF.md` (checkpoint جديد في الأعلى)؛ `tools/dev-db/acceptance/TARGET_MANIFEST.md` و`README.md` (قسم RM02). `docs/DECISIONS.md` لم يتغير (لا قرار مالك جديد). ملفات الجذر و`tools/dev-db/acceptance/` خارج Git وتحتاج حفظًا مستقلًا؛ تقرير API غير متتبع.

**P. GIT / HASH LEDGER.** قبل/بعد: API HEAD ثابت `d6870839…`؛ قبل: `?? docs/audits/`؛ بعد: `M tests/Feature/Tenancy/PostgresRlsIsolationTest.php` + `?? docs/audits/`. الواجهات نظيفة ثابتة. ledgers خاصة: `remediation-02-hashes-before.txt`/`-after.txt`. تغيّرت فقط: الاختبار (`9ea386bd…`→`dfa9546f…`)، `verify-connections.php` (`d15b96cc…`→`a5a1532d…`)، هذا التقرير؛ وأُضيفت `rm02-tool.php` و`rm02-fixtures.sql` و`rm02-lock.json`. لا commit.

**Q. RISK REGISTER.**

| ID | الأولوية | الحالة | الخطر |
|---|---|---|---|
| F05 | **P1** | CONFIRMED (ACL حي + مصدر) | خدمات Phase 2 (staff/roles CRUD، audit writer، Leads) تفشل 42501 تحت مبدأ runtime غير مالك؛ عزل الكتابة غير مثبت. |
| OLD-TEST | P2 | CONFIRMED | 18 tenant و39 user اصطناعية دائمة في TEST القديمة؛ تحتاج قرار تخلص. |
| F06 | P2 | CONFIRMED (موثق كحد) | GUC مزوّر داخل اتصال runtime يكشف صفوف tenant-scoped لجداول بلا ربط فاعل. |
| CRED | P2 | CONFIRMED (محلي) | سطر pgpass ظهر في مخرجات أداة محلية؛ تدوير موصى به. |
| SUITES | P2 | NOT TESTED | runtime/full suites غير منفذة على هدف متوافق. |
| PWSH | P3 | CONFIRMED | سكربتات PowerShell 7 الأصلية غير قابلة للتشغيل على هذا المضيف. |

**R. GATE DECISIONS.** G3 = **PARTIAL** (المبادئ والـACL مطابقة للعقد ومثبتة؛ العقد نفسه لا يغطي كتابة Phase 2 — F05). G4 = **PASS** لعزل القراءة A/B وno-context وcross-tenant تحت مبدأ غير مالك في RM02 (raw + Laravel)؛ عزل الكتابة وleads NOT_PROVEN. G5 = **PARTIAL** (المجموعة المستهدفة خضراء ومكررة؛ runtime/full NOT_EXECUTED). **المرحلة ككل: PARTIAL / NO-GO لـCustomers.** ثقة عالية في النتائج المنفذة؛ لا تعني جاهزية DEV أو Production.

**S. NEXT SINGLE STEP.** تكليف مالك واحد (REMEDIATION-03): تعريف عقد grants الكتابة لمبدأ tenant runtime بأعمدة دقيقة (roles، role_permissions، tenant_staff_users/memberships، assignments، direct grants، `tenant_staff_security_events` INSERT، `leads`) عبر migration أمامية جديدة، ثم اختبارات A/B للكتابة (WITH CHECK own/cross) على RM02. يتطلب اعتماد تعديل migrations وسياسة الصلاحيات. STOP إن احتاج الحل BYPASSRLS أو GRANT واسعًا أو تعديل سياسات قائمة دون مراجعة.

**T. NEXT-TOOL HANDOFF.** ابدأ بـ`docs/HANDOFF.md` (checkpoint أعلى الملف) ثم هذا الملحق. لا تعِد إنشاء RM02 ولا تشغّل `create-db`/`migrate` مجددًا؛ للتحقق استخدم `php tools/dev-db/acceptance/rm02-tool.php verify` ثم `probe` ثم `test` (Herd PHP 8.4). لا تشغّل `Run-AcceptanceTests.ps1 -Suite rls` (الاختبار الآن يرفض أي هدف غير RM02، والـrunner يرفض TEST القديمة). لا تبدأ Customers.

**U. COPY-READY SUMMARY (لـChatGPT).**
1. نُفّذ REMEDIATION-02 في 2026-10-24 على I:\WORK\DALEEL-CRM ضمن التفويض فقط.
2. سبب فشل RLS السابق: الاختبار يستهدف نموذج global-users المتقاعد (4×42501، 3 توقعات قديمة) وteardown يحذف tenants المحمية (2×23514).
3. عقد runtime الحالي (migration 026): SELECT أعمدة فقط على 8 جداول، صفر كتابة.
4. أُنشئت قاعدة واحدة جديدة: daleel_crm_rm02_isolated، OID 21227، على 127.0.0.1:55437، بلا حاوية/volume/دور جديد.
5. 36/36 migration، 18 RLS forced، 94 policy، بصمة schema (مع ACL) مطابقة لـDEV.
6. ACL مبدأ tenant runtime يطابق migration 026 حرفيًا؛ 8 مبادئ login least-privilege.
7. fixtures ثابتة (2 tenants) بلا حذف ولا تعطيل triggers؛ إعادة التشغيل no-op.
8. raw A/B: 64/64 PASS بمبدأ غير مالك/NOBYPASSRLS.
9. PHPUnit PostgresRlsIsolationTest: 9/9، 165 assertions، 0 skipped، exit 0 — مرتين بلا انحراف.
10. negative control: هدف/OID خاطئ يُرفض مغلقًا.
11. مسار Laravel الحقيقي (host resolver + staff guard + RBAC freshness + last-admin invariant) مثبت تحت المبدأ غير المالك.
12. اكتشاف P1 (F05): خدمات Phase 2 (staff/roles/audit/Leads) بلا grants كتابة لمبدأ runtime → ستفشل في نشر حقيقي.
13. اختبارات Phase 2 السابقة أخفت ذلك لأنها جرت على scratch مع GRANT ALL.
14. عزل الكتابة وleads: NOT_PROVEN حتى تُعرّف grants.
15. DEV وTEST القديمة وscratch بلا تغيير؛ TEST القديمة PRESERVE_AS_IS (18 tenant/39 user) بانتظار قرار.
16. RM02 = ISOLATED_PENDING_OWNER_DISPOSAL.
17. runtime suites وfull suite: NOT_EXECUTED (أهداف مثبتة قديمة/RefreshDatabase).
18. G3 PARTIAL، G4 PASS (قراءة)، G5 PARTIAL؛ القرار: NO-GO لـCustomers.
19. لا تعديل لكود الأعمال/migrations/policies/openapi/الواجهات؛ لا commit/push.
20. الخطوة التالية: REMEDIATION-03 لتعريف grants الكتابة بأعمدة دقيقة + اختبارات A/B للكتابة على RM02.

## REMEDIATION-03 — Tenant Runtime Write Contract, Least-Privilege Grants & Write Isolation

**التاريخ المرجعي:** 2026-10-24، Africa/Cairo. **الأداة/الأدوار:** Claude Code — Backend + QA/Security + Docs. **التفويض:** تكليف المالك REMEDIATION-03 (migration أمامية واحدة للصلاحيات، تطبيقها على RM02 فقط، اختبارات/أدوات/توثيق). لا قرار ADR جديد.

### REMEDIATION-03 / PRE-WRITE CONTRACT REVIEW (مكتوب قبل أي migration أو GRANT أو DML)

#### G0 — الهوية والأقفال (قراءة فقط)

| Evidence ID | الدليل | النتيجة |
|---|---|---|
| DF01-RM03-001 | Git للمستودعات الأربعة | API HEAD `d6870839…` بلا تغيير منذ نهاية RM02: `M tests/Feature/Tenancy/PostgresRlsIsolationTest.php`، `?? docs/audits/`؛ الواجهات نظيفة. |
| DF01-RM03-002 | `rm02-tool.php preflight` + `verify` (قراءة فقط) | الحاوية/المشروع/volume/IP/المنفذ مطابقة للقفل؛ cluster `7699972247235194919`؛ RM02 OID 21227 مطابق لـ`rm02-lock.json`؛ لا جلسات أخرى؛ 36 migrations، 18 RLS، 94 policies، ACL مطابقة لـ026، بصمة fixtures مطابقة لنهاية RM02؛ **لا migration 037** في المصدر أو القاعدة. |
| DF01-RM03-003 | كتالوج الأدوار + عدادات تجميعية | 15 دورًا كما في RM02، لا superuser/bypassrls؛ `daleel_b10b_tenant_runtime` و`dl_truntime` يرثان `daleel_tenant_runtime` فقط. DEV (0/0/0، 36/94) وTEST القديمة (39 users/18 tenants/1 audit، 36/94) بلا تغيير. |
| DF01-RM03-004 | ledger خاص `remediation-03-hashes-before.txt` | بصمات migrations (36) وapp+routes وtests مطابقة لـledger نهاية RM02. |

#### G1 — مصفوفة العقد على مستوى العملية (من المصدر + فحص حي)

كل العمليات تمر عبر `TenantStaffRequestContext` (معاملة واحدة على `pgsql_tenant_runtime`، GUCs محلية) ثم `TenantStaffAuthorizationService::runWithCapability()`/`effectiveGrants()`. FK checks تُنفَّذ داخليًا ولا تحتاج صلاحيات على الجداول المرجعية. «موجود» = ممنوح في migration 026.

| العملية (المصدر) | الجدول | الفعل والأعمدة المطلوبة | RLS المطبقة | الفجوة / التصنيف |
|---|---|---|---|---|
| `createRole` (RoleMutation:37) | roles | INSERT(id,tenant_id,display_name,normalized_name,created_at,updated_at) | roles_tenant_insert WITH CHECK tenant | MISSING_GRANT |
| `roleForUpdate` (:187) | roles | SELECT(id,status,**version**) + WHERE tenant_id,id + FOR UPDATE (يتطلب UPDATE على عمود واحد على الأقل) | select+update USING tenant | MISSING_GRANT: SELECT(version) + UPDATE |
| `updateRoleGrants` (:64–72) | role_permissions / roles | DELETE (جدولي) WHERE tenant_id,role_id؛ INSERT(tenant_id,role_id,permission_key,scope)؛ UPDATE roles(version,updated_at) | tenant-only | MISSING_GRANT؛ DELETE جدولي لازم (لا يوجد DELETE عمودي) |
| `archiveRole` (:83) | roles | UPDATE(status,archived_at,updated_at,version) | tenant-only | MISSING_GRANT |
| `denyOwnRoleEdit` (:197) | tenant_staff_membership_roles | `->exists()` = `EXISTS(SELECT *)` ⇒ SELECT على **كل** الأعمدة | actor-bound | MISSING_GRANT: SELECT(id,assigned_by_membership_id,assigned_by_provider_operation_id,assigned_at,revoked_by_membership_id,created_at,updated_at) — لا أسرار |
| `assignRole` (:104) | tenant_staff_membership_roles | INSERT(id,tenant_id,membership_id,role_id,assigned_by_membership_id,assigned_by_provider_operation_id,assigned_at,created_at,updated_at) | WITH CHECK actor-bound + `assigned_by_provider_operation_id IS NULL` | MISSING_GRANT |
| `revokeRole` (:128) | tenant_staff_membership_roles | UPDATE(revoked_at,revoked_by_membership_id,updated_at) WHERE (ممنوح) | actor-bound | MISSING_GRANT |
| `grantPermission`/`revokePermission` (:149/:175) | tenant_staff_permission_grants | INSERT(id,tenant_id,membership_id,permission_key,scope,granted_by_membership_id,granted_at,created_at,updated_at)؛ UPDATE(revoked_at,revoked_by_membership_id,updated_at) | actor-bound | MISSING_GRANT |
| `targetMembershipForUpdate`/`incrementMembershipVersion`/disable/reactivate | tenant_staff_memberships | SELECT (ممنوح) + FOR UPDATE؛ UPDATE(status,authorization_version,updated_at) | tenant + user-not-null | MISSING_GRANT |
| `createStaffMember` (Account:52–64) | tenant_staff_users / memberships | `->exists()` على tenant_staff_users ⇒ **يتطلب SELECT(password_hash)**؛ INSERT users(10 أعمدة بما فيها password_hash)؛ INSERT memberships(10 أعمدة بما فيها created_by_provider_operation_id) | tenant-only + triggers | **F07 — APPLICATION_CODE_CONFLICT (STOP للمسار)** |
| `TenantStaffAuditWriter::insert` (:51) | tenant_staff_security_events | INSERT(id,occurred_at,tenant_id,event_type,outcome,request_id,actor_membership_id,provider_operation_id,target_staff_user_id,target_role_id,metadata)؛ بلا SELECT/UPDATE/DELETE | WITH CHECK actor-bound + provider_operation_id IS NULL؛ trigger append-only | MISSING_GRANT (INSERT فقط) |
| LeadService list/get/forManage (`->get()`/`->first()` = `SELECT *`) | leads | SELECT كل الأعمدة الـ18 + FOR UPDATE | tenant-only | MISSING_GRANT |
| `createLead` (:83) | leads | INSERT 18 عمودًا | WITH CHECK tenant | MISSING_GRANT |
| update/stage/assign/archive (:129–168) | leads | UPDATE(name,phone,email,city,country,source,campaign,interest_level,estimated_value_minor,pipeline_stage,last_contacted_at,assigned_membership_id,status,updated_at) | tenant-only | MISSING_GRANT؛ لا UPDATE(tenant_id/id/created_by/created_at) ولا DELETE (archive = UPDATE) |
| `assignLead` (:154) | tenant_staff_memberships | `->exists()` ⇒ SELECT كل الأعمدة | tenant + user | MISSING_GRANT: SELECT(joined_at,created_by_membership_id,created_by_provider_operation_id,created_at,updated_at) |
| triggers `tenant_staff_membership_creator_valid` / `tenant_staff_membership_role_guard` | provider_control_operations (بلا RLS) | فرع `provider_operation_id IS NOT NULL` يقرأ الجدول؛ الدوال SECURITY INVOKER | — | **F08 — DOCUMENTED_RESIDUAL_RISK/UNKNOWN** (انظر أدناه) |

**حقائق حية تثبت التصنيف (قراءة فقط بمبدأ runtime، معاملات rollback):**
- DF01-RM03-005: `SELECT EXISTS(SELECT * FROM tenant_staff_users …)` و`…membership_roles` و`…memberships` = **42501**، بينما `EXISTS(SELECT 1 …)` مسموح. إذن `->exists()` في Laravel يحتاج SELECT على جميع الأعمدة.
- DF01-RM03-006: تعبير `($1 IS NOT NULL AND NOT EXISTS (SELECT … FROM provider_control_operations …))` بقيمة NULL = **42501 مع generic plan** ومسموح مع custom plan (طي الثوابت). triggers plpgsql تبدأ بـcustom plans؛ احتمال التحول إلى generic plan قائم نظريًا ⇒ فشل متقطع محتمل لإدراج العضويات/الإسنادات.

**F07 (P1، FACT):** `createStaffMember` لا يمكن تشغيله تحت least-privilege دون SELECT(password_hash) — ممنوع بالعقد. الإصلاح الصحيح تغيير سطر واحد في الخدمة (`exists()` → فحص على عمود `id`) — **كود أعمال خارج التفويض: STOP لمسار إنشاء الموظف عبر الخدمة**. ستُمنح أعمدة INSERT الخاصة بإنشاء الموظف (بما فيها password_hash للإدراج فقط) لأنها جزء من عقد الخدمة، وتُثبت بـraw SQL، بينما يبقى اختبار Laravel لهذا المسار NOT_EXECUTED.
**F08 (P2، INFERENCE+FACT جزئي):** لن يُمنح SELECT على `provider_control_operations` (جدول provider بلا RLS؛ المنح يكشف معرفات كل الشركات وعملياتها). يُختبر المسار تكراريًا (≥25 إدراجًا في جلسة واحدة لكل trigger)؛ إن فشل = يُسجّل ويُطلب قرار (trigger hardening SECURITY DEFINER أو منحة بعد مراجعة أمنية مستقلة).

#### G2 — حدود الثقة وF06

| الادعاء | الدليل | التصنيف |
|---|---|---|
| الـtenant يُشتق من Host فقط | `ResolveTenantHost` → `TenantHostResolver::resolve($request->getHost())`؛ لا trusted proxies؛ controllers لا تقبل tenant_id؛ الخدمات تستخدم `$actor->tenantId` دائمًا | TRUST_BOUNDARY_PROVEN_FOR_HTTP (مصدر + RM02 test 8 للـresolver) |
| الجلسة مربوطة بالـhost والإصدارات | `TenantStaffContextGuard::activateFromSession` يقارن tenant/hostname ويعيد التحقق من status/auth_version/authorization_version؛ RM02 test 8: جلسة A على host B، هوية مزورة، إصدار قديم، عضو معلّق — كلها مرفوضة | TRUST_BOUNDARY_PROVEN_FOR_HTTP (طبقة guard؛ ليس عبر HTTP kernel كاملًا) |
| GUC تُضبط من الخادم فقط | `set_config` في مستوى tenant موجود فقط في `TenantStaffRequestContext`/`TenantStaffContextGuard`/`TenantHostResolver`؛ لا مدخل API يصل إليه | TRUST_BOUNDARY_PROVEN_FOR_HTTP (مصدر) |
| لا تسرب context بين الطلبات | معاملة لكل طلب مع commit/rollback يمسح SET LOCAL؛ لا PDO persistent ولا Octane؛ RM02 test 6/9 تثبت مسح السياق | TRUST_BOUNDARY_PROVEN_FOR_HTTP |
| F06 بعد منح الكتابة | سياسات roles/role_permissions/leads/tenant_staff_users/memberships tenant-only: اتصال runtime مخترق بـGUC مزوّر يستطيع **الكتابة** في tenant آخر (ليس القراءة فقط). سياسات tsmr/tspg/tsse تربط الفاعل لكنها تقبل user_id مزورًا معروفًا. | **DOCUMENTED_RESIDUAL_RISK — يزداد الأثر** (P2→P1 تحت اختراق قاعدة البيانات)؛ لا مسار HTTP قابل للاستغلال وُجد |
| provenance مزوّر | INSERT(created_by_provider_operation_id) على memberships مطلوب لأن الخدمة تُدرج العمود صراحة (NULL)؛ اتصال مخترق قد يضع معرّف عملية provision حقيقية لنفس tenant (trigger يقبلها) | DOCUMENTED_RESIDUAL_RISK (P2)؛ الإصلاح لاحقًا بحذف العمود من الإدراج في الخدمة |
| `createLead` يقبل `assigned_membership_id` دون فحص ACTIVE | FK مركب يمنع عضوية tenant آخر؛ لكن عضو معلّق في نفس tenant مقبول | APPLICATION_AUTHZ_GAP (P3، خارج النطاق) |

**قرار G2:** لا مسار استغلال HTTP معروف ضمن الصلاحيات المقترحة ⇒ المتابعة مسموحة، مع إفصاح F06 (أثر أكبر بعد الكتابة) وF07/F08.

#### G3 — المنح المقترحة (migration أمامية واحدة `2026_10_24_000037_grant_tenant_runtime_phase2_write_contract.php`)

المستهدف: مجموعة `daleel_tenant_runtime` (NOLOGIN) فقط؛ يرثها `dl_truntime` و`daleel_b10b_tenant_runtime`. Preconditions fail-closed: الدور موجود، NOLOGIN، NOSUPERUSER، NOBYPASSRLS، NOCREATEDB، NOCREATEROLE، لا يملك جداول، بلا CREATE على schema. `down()` يرمي استثناء (forward-only). GRANT بطبيعته idempotent.

- `roles`: SELECT(version)؛ INSERT(id,tenant_id,display_name,normalized_name,created_at,updated_at)؛ UPDATE(status,archived_at,version,updated_at).
- `role_permissions`: INSERT(tenant_id,role_id,permission_key,scope)؛ **DELETE (جدولي — الحالة الوحيدة)**، مبرره استبدال منح الدور؛ تحكمه RLS tenant + `role.manage` + منع تعديل الدور الذاتي + last-admin invariant داخل نفس المعاملة.
- `tenant_staff_users`: INSERT(id,tenant_id,canonical_email,display_email,display_name,password_hash,status,auth_version,created_at,updated_at)؛ **لا SELECT(password_hash)، لا UPDATE، لا DELETE**.
- `tenant_staff_memberships`: SELECT(joined_at,created_by_membership_id,created_by_provider_operation_id,created_at,updated_at)؛ INSERT(id,tenant_id,staff_user_id,status,authorization_version,joined_at,created_by_membership_id,created_by_provider_operation_id,created_at,updated_at)؛ UPDATE(status,authorization_version,updated_at).
- `tenant_staff_membership_roles`: SELECT(id,assigned_by_membership_id,assigned_by_provider_operation_id,assigned_at,revoked_by_membership_id,created_at,updated_at)؛ INSERT(id,tenant_id,membership_id,role_id,assigned_by_membership_id,assigned_by_provider_operation_id,assigned_at,created_at,updated_at)؛ UPDATE(revoked_at,revoked_by_membership_id,updated_at).
- `tenant_staff_permission_grants`: INSERT(id,tenant_id,membership_id,permission_key,scope,granted_by_membership_id,granted_at,created_at,updated_at)؛ UPDATE(revoked_at,revoked_by_membership_id,updated_at).
- `tenant_staff_security_events`: INSERT(11 عمودًا) فقط.
- `leads`: SELECT(كل الأعمدة الـ18)؛ INSERT(18 عمودًا)؛ UPDATE(14 عمودًا أعلاه).
- **لا شيء** على tenants (كتابة)، users، tenant_memberships، membership_roles، provider_*، plans، subscriptions، sequences، PUBLIC. لا تغيير لأي policy أو trigger أو FORCE RLS. `tenant_id` غير قابل للتحديث على مستوى ACL في كل الجداول.

#### G4/G5 — خطة الاختبار

1. **قبل التطبيق:** `php -l`، reflection للاختبار الجديد، قراءة migration.
2. **التطبيق:** أمر جديد `rm02-tool.php apply-migration` (يرفض إن لم يكن عدد migrations = 36 بالضبط وكان 037 هو الملف الوحيد المعلق؛ يفحص الهوية؛ يلتقط ACL قبل/بعد في `.private/reports`).
3. **تشغيل مسبق للاختبارات القديمة بلا تعديل** لإثبات الأثر: يُتوقّع أن تسقط عمدًا (tripwires) الحالات التي كانت تؤكد «لا كتابة»: في `PostgresRlsIsolationTest` — `test_no_context…` (SELECT leads صار ممنوحًا)، `test_tenant_runtime_cannot_mutate…` (staff_insert=true، وINSERT staff ينجح)، `test_raw_a_b…` (INSERT roles/DELETE role_permissions/SELECT leads)؛ وفي `rm02-tool verify/probe` (P06). تُسجّل النتيجة كما هي، ثم تُحدَّث هذه التأكيدات للعقد الجديد مع الحفاظ على التغطية: الرفض على مستوى الكائن لما بقي غير ممنوح (برسالة `permission denied`)، والرفض بـRLS لما صار ممنوحًا (برسالة `row-level security` أو صفر صفوف).
4. **probes خام جديدة** (معاملات rollback): A يكتب في A (roles/role_permissions/tsmr/tspg/tsse/leads/staff)، INSERT بـtenant_id لـB = RLS violation، UPDATE/DELETE صفوف B = 0 صفوف، UPDATE(tenant_id) = 42501 كائني، DELETE على roles/leads/tsse/tenants/staff = 42501 كائني، UPDATE/DELETE audit = 42501، SELECT password_hash = 42501، بلا context = RLS deny، RETURNING على أعمدة ممنوحة/غير ممنوحة؛ تكرار triggers 25 مرة (F08).
5. **اختبار PHPUnit جديد** `tests/Feature/Tenancy/TenantRuntimeWriteContractTest.php` (نفس قفل RM02): raw A/B للكتابة، وخدمات Laravel الحقيقية تحت guard ومبدأ غير مالك داخل معاملة rollback واحدة: createRole/updateRoleGrants/archiveRole، assign/revoke role، grant/revoke permission، disable/reactivate، Leads بنطاقات ALL_TENANT/ASSIGNED/SELF وعبور B، رفض RBAC، عدّ أحداث التدقيق بـ`pg_stat_xact_user_tables.n_tup_ins` (حدث واحد لكل عملية ناجحة، صفر للمرفوضة)، atomicity عند فشل الإسناد المكرر.
6. **Regression:** probe 64 القديمة (بعد تحديث P06) + `PostgresRlsIsolationTest` 9/9، ثم تكرار كامل؛ بصمة fixtures قبل/بعد يجب أن تتطابق (كل الكتابات rollback).
7. **NOT_EXECUTED مسبقًا:** createStaffMember عبر Laravel (F07)، runtime/full suites (أهداف قديمة/RefreshDatabase)، HTTP kernel end-to-end.

**Rollback/Stop:** لا DROP/REVOKE تصحيحي تلقائي. فشل migration ⇒ يُترك RM02 كما هو ويُوثّق حال المعاملة. أي drift في بصمة fixtures ⇒ STOP. DEV/TEST القديمة/scratch: قراءة فقط. `Run-Migrations.ps1` لـDEV/TEST يتوقع 36 ملفًا وسيرفض الآن بوجود 037 (حماية إضافية؛ لن يُشغَّل).

**الملفات المتوقع تغييرها:** جديد `database/migrations/2026_10_24_000037_grant_tenant_runtime_phase2_write_contract.php`، جديد `tests/Feature/Tenancy/TenantRuntimeWriteContractTest.php`، تعديل `tests/Feature/Tenancy/PostgresRlsIsolationTest.php` (tripwires فقط)، تعديل `tools/dev-db/acceptance/rm02-tool.php`؛ التوثيق (هذا الملحق، STATUS/PLAN/HANDOFF، README/TARGET_MANIFEST). لا كود أعمال، لا policies، لا openapi، لا الواجهات.

### REMEDIATION-03 — سجل التنفيذ (بعد حفظ المراجعة أعلاه)

| Evidence ID | الوقت | الأمر | النتيجة |
|---|---|---|---|
| DF01-RM03-007 | 2026-10-24 05:47:11 Cairo | حفظ PRE-WRITE والتحقق منه | القسم موجود مرة واحدة؛ SHA-256 للتقرير عند الحفظ `87c4b7aa…88d0b7` (مسجّل في ledger قبل أي كتابة). |
| DF01-RM03-008 | ~05:50 | `php -l` (migration، الاختبار الجديد، الأداة) + reflection | نظيف؛ الاختبار الجديد 6 tests، القديم 9 tests. تصحيح قبل التشغيل: عدد أحداث التدقيق المتوقع 9 لا 10، واستبدال placeholder مكرر بـCTE. |
| DF01-RM03-009 | ~05:52 | `rm02-tool.php apply-migration` | الشروط: 36 مطبقة، 37 في المصدر، 037 الوحيد المعلق، لا جلسات. **`artisan migrate` exit 0** على RM02 فقط كمالك؛ migrations=37؛ لقطات ACL قبل/بعد `.private/reports/remediation-03-acl-{before,after}.json`. |
| DF01-RM03-010 | 02:48:55Z | probe + `PostgresRlsIsolationTest` **دون تعديل** بعد 037 | كما تنبأ PRE-WRITE حرفيًا: probe = 6 FAIL فقط (INSERT roles own، DELETE role_permissions own، SELECT leads ×2 tenant)؛ PHPUnit 9 tests: 6 pass / 3 failures (الثلاثة المتوقعة، كلها عند tripwire `assertObjectDenied`)؛ اختبارات عزل القراءة كلها ناجحة؛ لا انحراف fixtures. JUnit `remediation-02-rls-20261024T024855Z`. |
| DF01-RM03-011 | ~05:54 | تحديث tripwires في `PostgresRlsIsolationTest` + الأداة | helper يميّز `permission denied` (كائني) عن `row-level security` (RLS)؛ ما بقي غير ممنوح يبقى كائني؛ ما صار ممنوحًا يُثبت محصورًا بـRLS (INSERT عابر = RLS، UPDATE/DELETE عابر = 0 صفوف)؛ إضافة leads لجداول القراءة؛ `SELECT *` على staff = كائني (password_hash). لم تُحذف أي تغطية. |
| DF01-RM03-012 | ~05:55 | `verify` (قراءة فقط) | 37 migrations، 36 tables، 18 RLS، **94 policies و15 triggers بلا تغيير**؛ بنية schema (بلا ACL) = DEV، وACL تختلف فقط بعقد 037؛ **ACL الـruntime يطابق 026+037 عمودًا بعمود** على 36 جدولًا؛ DELETE جدولي فقط على role_permissions؛ لا SELECT/INSERT/UPDATE جدولي. الوراثة مثبتة للدخولين `dl_truntime` و`daleel_b10b_tenant_runtime`. |
| DF01-RM03-013 | ~05:55 | `probe` ×2 | **79 PASS / 0 FAIL** في كل مرة: 59 فحص قراءة أساسي (P01–P10) + 20 فحص كتابة (P11)؛ البصمة بلا تغيير. ملاحظات: P12 (F06) — GUC مزوّر (user A على tenant B) **يستطيع INSERT roles في B** بينما إدراج تدقيق بفاعل B مرفوض بـRLS؛ P13 — تزوير provenance لعضوية (عملية provider) = 42501 لأن trigger يقرأ `provider_control_operations` غير الممنوح. |
| DF01-RM03-014 | 02:56:02Z | `test write` | `TenantRuntimeWriteContractTest`: **6/6، 221 assertions، exit 0**. JUnit `remediation-03-write-20261024T025602Z`. |
| DF01-RM03-015 | 02:56:26Z / 02:56:33Z / 02:57:03Z | `test rls`، `test all` ×2 | RLS: **9/9، 220 assertions**؛ all: **15/15، 441 assertions، exit 0** مرتين؛ 0 skipped؛ stderr فارغ؛ البصمة قبل = بعد (leads=0، staff_audit=0). |
| DF01-RM03-016 | ~05:57 | `guard-selftest` | رفض الأسماء المحمية ×3، وقفل OID خاطئ يفشل مغلقًا، بلا انحراف. |
| DF01-RM03-017 | ~05:58 | عدادات read-only + ledger بعد + Git | DEV وTEST القديمة بلا تغيير ولا تملكان منح 037 (`f/f`)؛ بصمة الـ36 migration التاريخية وapp+routes ثابتة؛ التغييرات: الاختبار المعدّل، الأداة، الاختبار الجديد، migration 037، هذا التقرير. |

**تصحيح سجل سابق (شفافية):** تقرير REMEDIATION-02 ذكر «raw A/B probe 64/64»؛ العد الفعلي لأسطر PASS في ذلك الـprobe هو **59/59** (0 FAIL). الخطأ في العدّ فقط لا في النتيجة؛ الرقم الصحيح المعتمد للخط الأساسي = 59.

### REMEDIATION-03 — التقرير النهائي (A–V)

**A. EXECUTIVE SUMMARY.** عُرّف عقد كتابة least-privilege لمبدأ tenant runtime في migration أمامية واحدة (037)، وطُبّقت على RM02 فقط. ثبت بمبدأ غير مالك: كتابة A في A مسموحة، الكتابة العابرة إلى B مرفوضة بـRLS أو تؤثر في صفر صفوف، `tenant_id` غير قابل للتحديث، التدقيق insert-only، `password_hash` غير مقروء. خدمات Laravel الحقيقية للأدوار/العضويات/التدقيق/Leads (ALL_TENANT/ASSIGNED/SELF) تعمل الآن تحت least-privilege. **النتيجة: PARTIAL / NO-GO لـCustomers** بسبب F07 (إنشاء موظف لا يعمل دون SELECT على password_hash — يحتاج تعديل كود أعمال) وF06 (يمتد الآن إلى الكتابة تحت اختراق اتصال DB).

**B. SCOPE & AUTHORIZATION.** نُفّذ ضمن التفويض: migration واحدة، تطبيق على RM02 فقط، اختبارات/أدوات/توثيق. لم يُعدّل كود أعمال أو policies أو triggers أو الـ36 migration أو openapi أو الواجهات؛ لا DROP/reset/حذف؛ لا Git write. **انحراف واحد معلن:** لا يوجد.

**C. CHECKPOINT/GIT.** قبل: API `d6870839…` مع `M PostgresRlsIsolationTest.php`، `?? docs/audits/`. بعد: نفسه + `?? database/migrations/2026_10_24_000037_…php`، `?? tests/Feature/Tenancy/TenantRuntimeWriteContractTest.php`. الواجهات `6fb01b88`/`9fa43bef`/`a802e44b` نظيفة قبل/بعد.

**D. TARGET IDENTITY.** cluster `7699972247235194919`، الحاوية `d6ce6f4c1e92…`، RM02 OID 21227 عبر 127.0.0.1:55437→5432، مقفلة بـ`rm02-lock.json`. DEV 16412 وTEST القديمة 16413 وscratch: قراءة فقط، بلا تغيير، بلا منح 037.

**E. PRE-WRITE EVIDENCE.** القسم «REMEDIATION-03 / PRE-WRITE CONTRACT REVIEW» حُفظ 05:47:11 Cairo ببصمة `87c4b7aa…` قبل أول كتابة (apply-migration ~05:52). توقّع PRE-WRITE الـtripwires بدقة قبل حدوثها (DF01-RM03-010).

**F. F05 CONTRACT MATRIX.** انظر جدول G1 أعلاه (كل عملية → جدول → أعمدة/أفعال → RLS → تصنيف). حقيقتان حاسمتان: `EXISTS(SELECT *)` يتطلب SELECT على كل الأعمدة (DF01-RM03-005)، ومسار provider في triggers يتطلب قراءة جدول provider مع generic plan (DF01-RM03-006).

**G. F06 TRUST BOUNDARY.** مثبت للـHTTP (مصدر + guard tests): tenant من Host فقط، الجلسة مربوطة بالـhost والإصدارات، GUC من الخادم فقط، لا تسرب بين الطلبات. **متبقٍّ موثق (FACT P12):** اتصال runtime مخترق بـGUC مزوّر يكتب في جداول tenant-scoped لشركة أخرى (roles/role_permissions/leads/staff/memberships)؛ الجداول المرتبطة بالفاعل (tsmr/tspg/tsse) تحتاج user_id حقيقيًا من الشركة الأخرى. F06 **لم يُغلق**.

**H. MIGRATION DIFF.** ملف جديد واحد `2026_10_24_000037_grant_tenant_runtime_phase2_write_contract.php`: guard fail-closed لخصائص `daleel_tenant_runtime`، 18 عبارة GRANT بأعمدة محددة، `down()` يرمي. لا REVOKE، لا policy، لا trigger.

**I. EFFECTIVE GRANTS BEFORE/AFTER.** قبل: SELECT أعمدة على 8 جداول، صفر كتابة. بعد: SELECT أعمدة على 9 جداول (+leads، +roles.version، +أعمدة metadata لـmemberships/assignments)، INSERT/UPDATE أعمدة على 8 جداول، DELETE جدولي على role_permissions وحده؛ لا UPDATE لأي `tenant_id`/`id`/`created_by`؛ tenant_staff_users: INSERT فقط (password_hash للإدراج)؛ tsse: INSERT فقط. موروثة لـ`dl_truntime` و`daleel_b10b_tenant_runtime` (اختبار حي للدخولين).

**J. RLS IMPACT.** صفر تغيير: 94 policies و15 triggers و18 FORCE RLS كما هي؛ بنية schema = DEV.

**K. FIXTURES.** لا fixtures جديدة. كل كتابات الاختبار داخل معاملات rollback؛ بصمة RM02 قبل/بعد كل تشغيل متطابقة (2 tenants، 4 staff، 3 roles، 14 role_permissions، leads=0، audit=0).

**L. RAW PROBES.** 79/79 ×2: كتابة own = مسموحة؛ INSERT عابر = RLS؛ UPDATE/DELETE عابر = 0؛ UPDATE(tenant_id)/DELETE roles/leads/tenants = كائني؛ تدقيق عابر = RLS؛ SELECT/UPDATE/DELETE تدقيق = كائني. داخل PHPUnit أيضًا: FK مركّب يمنع ربط عضوية/دور tenant آخر (23503)، RETURNING على عمود غير ممنوح = كائني، فاعل معلّق لا يكتب إسنادات/تدقيق، بلا context = RLS.

**M. LARAVEL E2E (service-level تحت guard حقيقي).** createRole/updateRoleGrants/archiveRole/assignRole/grantPermission/revokePermission/disable/reactivate = 9 أحداث تدقيق بالضبط (عبر `pg_stat_xact_user_tables`)؛ رفض: تكرار الإسناد (atomic، بلا تغيير إصدار وبلا تدقيق)، تعديل الدور الذاتي، تعطيل الذات، عمليات على عضوية B، عمليات القارئ دون role.manage/member.manage — صفر تدقيق للمرفوض. Leads: ASSIGNED يرى المسند فقط ولا يعيد الإسناد ويُجبر على self-assignment عند الإنشاء؛ SELF يرى ما أنشأه فقط؛ admin B لا يرى/يعدّل/يؤرشف/يسند leads A؛ admin A يسند ويؤرشف. createStaffMember = F07 (characterization test).

**N. READ REGRESSION.** `PostgresRlsIsolationTest` 9/9 (220 assertions، كان 165) مرتين؛ probe قراءة 59/59 كما في RM02 (بعد تصحيح العدد).

**O. NOT_EXECUTED.** createStaffMember عبر Laravel (F07)؛ مسارات HTTP kernel كاملة (session cookie + middleware) — مُثبتة على مستوى guard/service؛ runtime/full suites (أهداف B10B ثابتة، RefreshDatabase)؛ أي تشغيل على DEV/TEST القديمة.

**P. SECURITY REVIEW.** لا BYPASSRLS/SUPERUSER/GRANT ALL/PUBLIC؛ password_hash غير مقروء (حتى `SELECT *` مرفوض)؛ التدقيق append-only بالـACL والـtrigger؛ tenant_id ثابت بالـACL؛ DELETE محصور في role_permissions ومحكوم بـRLS+RBAC+invariant. لم تُمنح قراءة لجدول provider (F08). F06 متبقٍّ ومعلن.

**Q. FILES.** جديد (untracked في API): migration 037، `TenantRuntimeWriteContractTest.php`. معدّل (tracked): `PostgresRlsIsolationTest.php`. خارج Git: `tools/dev-db/acceptance/rm02-tool.php`، docs الجذر، README/TARGET_MANIFEST، `.private/reports/*`. هذا التقرير untracked. تحتاج نسخًا احتياطيًا يديرها المالك.

**R. RISK REGISTER.**

| ID | الأولوية | النوع | الوصف |
|---|---|---|---|
| F07 | **P1** | FACT | `createStaffMember` يفشل 42501 بسبب `->exists()` على tenant_staff_users (يتطلب password_hash). يحتاج تعديل سطر في الخدمة — خارج التفويض. |
| F06 | P1 تحت اختراق DB / P2 عام | FACT (P12) | GUC مزوّر على اتصال runtime يكتب في tenant آخر للجداول tenant-scoped. لا مسار HTTP. |
| F08 | P3 | INFERENCE + FACT جزئي | triggers تقرأ `provider_control_operations` في فرع provider؛ مسار NULL مستقر (30 تكرارًا/جلسة) لكنه يعتمد على custom plans. اتصالات per-request تقلل الخطر. |
| F09 | P3 | FACT | منح SELECT إضافية (metadata في memberships/assignments) سببها `exists()`؛ يمكن تضييقها بعد إصلاح الكود. |
| F10 | P3 | FACT | `createLead` يقبل عضوية معلّقة من نفس tenant كـassigned (FK يمنع tenant آخر). |
| OLD-TEST / CRED / PWSH | P2/P2/P3 | FACT | كما في RM02. |

**S. GATES.** G0 **PASS** · G1 **PASS** (المصفوفة كاملة؛ F07/F08 مصنفة) · G2 **PASS** مع متبقٍّ معلن (F06 للكتابة) · G3 **PASS** (037 على RM02، ACL دقيقة للدخولين، لا صلاحيات زائدة، القراءة سليمة) · G4 **PASS** للسيناريوهات المختبرة (ما عدا إنشاء الموظف عبر الخدمة: NOT_PROVEN) · G5 **PASS** للمستهدف (15/15 ×2، 79/79 ×2، guard) مع runtime/full NOT_EXECUTED. **Overall: PARTIAL / NO-GO لـCustomers** (F07 P1 مفتوح).

**T. NEXT SINGLE STEP.** REMEDIATION-04 (يتطلب تفويض تعديل كود أعمال محدود): استبدال `->exists()` بفحص على عمود `id` في `TenantStaffAccountService::createStaffMember` (و`denyOwnRoleEdit`/`assignLead`)، وحذف أعمدة provenance المضبوطة NULL من إدراجات الخدمات، ثم migration أمامية لتضييق المنح الزائدة (F09)، واختبار createStaffMember واختبارات HTTP kernel على RM02. STOP إن احتاج تغيير policies أو منح password_hash.

**U. NEXT-TOOL HANDOFF.** لا تعِد `create-db`/`migrate`/`apply-migration` (ترفض). للتحقق: من `daleel-crm-api/` شغّل `php ../tools/dev-db/acceptance/rm02-tool.php verify` ثم `probe` ثم `test all` (Herd PHP 8.4). ممنوع: DEV/TEST القديمة/scratch، host 5432، `Run-AcceptanceTests.ps1`/`Run-Migrations.ps1` (الأخير سيرفض الآن لوجود 37 ملفًا)، أي reset. migration 037 **لم تُطبّق** على DEV.

**V. COPY-READY SUMMARY (لـChatGPT).**
1. نُفّذ REMEDIATION-03 في 2026-10-24 ضمن التفويض، على RM02 فقط (OID 21227).
2. كُتبت مراجعة PRE-WRITE (05:47:11 Cairo، بصمة 87c4b7aa) قبل أي كتابة، وتنبأت بالـtripwires بدقة.
3. migration جديدة واحدة: 2026_10_24_000037_grant_tenant_runtime_phase2_write_contract (18 GRANT بأعمدة محددة، guard fail-closed، forward-only).
4. لا تعديل لأي policy أو trigger أو الـ36 migration؛ 94 policies و15 triggers كما هي؛ بنية schema = DEV.
5. ACL الـruntime يطابق 026+037 عمودًا بعمود؛ DELETE جدولي على role_permissions فقط؛ لا تحديث لأي tenant_id.
6. password_hash: INSERT فقط، لا قراءة (حتى SELECT * مرفوض).
7. التدقيق insert-only مع فاعل مربوط بـRLS؛ لا SELECT/UPDATE/DELETE.
8. probe خام: 79/79 مرتين (59 قراءة + 20 كتابة).
9. TenantRuntimeWriteContractTest جديد: 6/6، 221 assertions.
10. PostgresRlsIsolationTest بعد تحديث tripwires: 9/9، 220 assertions.
11. المجموع: 15/15، 441 assertions، exit 0، مرتين، بلا drift.
12. خدمات Laravel للأدوار/العضويات/التدقيق/Leads تعمل تحت مبدأ غير مالك؛ 9 أحداث تدقيق لـ9 عمليات؛ صفر للمرفوض.
13. Leads: ALL_TENANT/ASSIGNED/SELF مثبتة، وشركة B لا ترى ولا تعدّل leads A.
14. F07 (P1): createStaffMember يفشل لأن ->exists() يحتاج SELECT(password_hash) — يحتاج تعديل كود أعمال (خارج التفويض).
15. F06: GUC مزوّر على اتصال DB مخترق يستطيع الآن الكتابة في شركة أخرى (جداول tenant-scoped)؛ لا مسار HTTP؛ غير مغلق.
16. F08 (P3): triggers تعتمد على custom plans في فرع provider؛ مستقرة في 30 تكرارًا.
17. تصحيح: خط القراءة في RM02 كان 59 فحصًا لا 64.
18. DEV وTEST القديمة وscratch بلا تغيير ولا تحمل منح 037.
19. لا Customers، لا commit/push؛ ملفات جديدة untracked.
20. G0–G5 PASS ضمن نطاقها؛ Overall PARTIAL / NO-GO بسبب F07.
21. التالي: REMEDIATION-04 — إصلاح exists() + تضييق المنح + اختبارات createStaffMember وHTTP kernel على RM02.

## REMEDIATION-04 — Staff Creation Recovery, Privilege Narrowing & HTTP Kernel Acceptance

**التاريخ المرجعي:** 2026-10-24، Africa/Cairo. **الأدوار:** Backend + PostgreSQL/RLS + QA Security + Docs. **التفويض:** تكليف المالك REMEDIATION-04 (إصلاح F07 محدود، مراجعة exists/provenance، تقييم تضييق F09 عبر migration أمامية واحدة، اختبارات HTTP Kernel، إعادة اختبار، مراجعة انتقال). لا Customers، لا commit، لا كتابة خارج RM02.

### REMEDIATION-04 / PRE-WRITE CONTRACT & IMPACT REVIEW

**وقت الحفظ:** 2026-10-24 (Africa/Cairo) — يسبق أي تعديل كود أعمال أو DML أو GRANT/REVOKE أو migration. البصمة مسجّلة بعد الحفظ في `.private/reports/remediation-04-hashes-before.txt`.

#### G0 — هوية الهدف وخط الأساس (قراءة فقط)

| Evidence ID | الدليل | النتيجة |
|---|---|---|
| DF01-RM04-001 | Git ×4 | API HEAD `d6870839…` بلا تغيير؛ `M tests/Feature/Tenancy/PostgresRlsIsolationTest.php`؛ غير متتبع: migration 037، `TenantRuntimeWriteContractTest.php`، `docs/audits/`. الواجهات `6fb01b88`/`9fa43bef`/`a802e44b` نظيفة. **لا drift عن نهاية RM03.** |
| DF01-RM04-002 | `rm02-tool.php preflight` | الحاوية `d6ce6f4c1e92…`/المشروع/volume/IP 172.19.0.2/المنفذ 55437 مطابقة للقفل؛ cluster `7699972247235194919`؛ RM02 OID **21227**؛ scratch مطابقة؛ **0 جلسات متزامنة**. |
| DF01-RM04-003 | `rm02-tool.php verify` | 37 migrations، 36 tables، 18 FORCE RLS، **94 policies و15 triggers**، ACL = 026+037 عمودًا بعمود، بصمة fixtures مطابقة لنهاية RM03 (2 tenants، 4 staff، 3 roles، 14 role_permissions، leads=0، staff_security_events=0). |
| DF01-RM04-004 | عدادات read-only | DEV: 36 migrations، 0 صفوف، 94 policies، `has_any_column_privilege(runtime,'leads','SELECT')=false`. Old TEST: 36 migrations، 39 users، 18 tenants، 94 policies، نفس النتيجة. **لا أثر لـ037 على أي منهما.** |
| DF01-RM04-005 | المصدر | 37 ملف migration؛ **لا يوجد 038** ولا أي اسم متصادم. |

#### G1 — مصفوفة call-site: الـSQL الفعلي وACL وسبب النجاح/الفشل

تم استخراج الـSQL من Laravel 13 فعليًا (لا افتراض): `Builder::exists()` تستدعي `Grammar::compileExists()` التي تُغلّف `compileSelect()` كما هو — فإن لم تُحدَّد أعمدة أصدرت `select exists(select * from …)`، وإن حُدِّدت أصدرت `select exists(select "col" from …)`.

| Call site | الـSQL الفعلي الآن | التنفيذ الحي كـ`daleel_b10b_tenant_runtime` | السبب | التصنيف |
|---|---|---|---|---|
| `TenantStaffAccountService::createStaffMember` (:52–53) | `select exists(select * from "tenant_staff_users" where "tenant_id" = ? and "canonical_email" = ?)` | **DENIED 42501 (permission denied)** | `SELECT *` يلزمه SELECT على **كل** الأعمدة ومنها `password_hash` الممنوع عمدًا | **F07 — MISSING_COLUMN_SCOPE_IN_QUERY (إصلاح في الكود)** |
| نفس الموضع — مرشح | `select exists(select "id" from "tenant_staff_users" …)` | **ALLOWED** (رجّع false) | `id` ممنوح بـ026 | الحل المعتمد |
| نفس الموضع — مرشح بديل | `select "id" from … limit 1` (`value('id')`) | ALLOWED (رجّع NULL) | — | بديل مرفوض: يغيّر الدلالة إلى جلب قيمة |
| `TenantStaffRoleMutationService::denyOwnRoleEdit` (:197–199) | `select exists(select * from "tenant_staff_membership_roles" …)` | **ALLOWED** | ينجح **فقط** لأن 037 منح SELECT على كل أعمدة metadata لهذا الجدول | **F09 — سبب المنح الزائدة** |
| نفس الموضع — مرشح | `select exists(select "role_id" from … )` | ALLOWED | `role_id` ممنوح بـ026 | يحرّر 7 أعمدة للتضييق |
| `LeadService::assignLead` (:154–155) | `select exists(select * from "tenant_staff_memberships" …)` | **ALLOWED** | ينجح فقط بفضل منح 037 الإضافية | **F09 — سبب المنح الزائدة** |
| نفس الموضع — مرشح | `select exists(select "id" from … )` | ALLOWED (رجّع true) | `id` ممنوح بـ026 | يحرّر 5 أعمدة للتضييق |

**جرد كامل لمستهلكي الأعمدة المرشحة** (grep على `app/` و`tests/` باستثناء مسار Provider): لا يوجد أي قارئ آخر لأعمدة `tenant_staff_memberships(joined_at, created_by_membership_id, created_by_provider_operation_id, created_at, updated_at)` ولا لأعمدة `tenant_staff_membership_roles(id, assigned_by_membership_id, assigned_by_provider_operation_id, assigned_at, revoked_by_membership_id, created_at, updated_at)` تحت مبدأ runtime. كل المسارات الأخرى تستخدم أعمدة 026 فقط: `TenantStaffContextGuard` (id, tenant_id, staff_user_id, status, authorization_version)، `TenantStaffAuthorizationService::effectiveGrants` (assignment.role_id + tenant_id/membership_id/revoked_at)، `TenantStaffAdminInvariant` (joins على tenant_id/status/role_id/membership_id/revoked_at/scope)، `listStaff` (m.id, m.status)، `targetMembershipForUpdate` (id, status)، `staffUserFor` (staff_user_id)، `incrementMembershipVersion` (UPDATE)، `revokeRole/revokePermission` (WHERE على أعمدة 026 + UPDATE). الموديلان `TenantStaffMembership`/`TenantStaffMembershipRole` غير مستخدمين في أي مسار (لا مرجع خارج تعريفهما) فلا يصدران `SELECT *`. سياسات RLS للجدولين تشير إلى `tenant_staff_memberships(actor: tenant_id, staff_user_id, status, id)` وكلها 026.
`leads`: الخدمة تستخدم `->get()`/`->first()` = `SELECT *` فعليًا ⇒ **تبقى منح SELECT الـ18 كما هي** (ليست زائدة). `roles.version` لازمة لـ`roleForUpdate` ⇒ تبقى.

**إدراجات provenance (الفحص الحي لـinformation_schema):** `tenant_staff_memberships.created_by_provider_operation_id` و`tenant_staff_membership_roles.assigned_by_provider_operation_id` و`tenant_staff_security_events.provider_operation_id` كلها `nullable=YES` و`default=NULL` ⇒ **إغفال العمود مكافئ تمامًا لتمرير NULL صريحة**. القيود تبقى محققة: `tenant_staff_membership_creator_check` (num_nonnulls = 1 عبر `created_by_membership_id`)، trigger `tenant_staff_membership_creator_valid` (فرع provider يقصر على NULL)، `tsmr_assignment_actor_check`، وسياسة tsse (`provider_operation_id IS NULL`). **لا تُلمس** `occurred_at` (مصدر الوقت تطبيقي ومختلف دلاليًا عن `CURRENT_TIMESTAMP`) ولا `metadata` ولا `request_id` ولا أي provenance غير فارغة.

**هل تحتاج سياسة RLS صلاحية عمود على الصف الهدف؟ لا.** الدليل من RM03: مبدأ runtime يُدرج في `tenant_staff_security_events` بنجاح بينما **لا يملك أي SELECT على هذا الجدول**، وسياسته تشير إلى ثلاثة من أعمدته (`tenant_id`, `actor_membership_id`, `provider_operation_id`). إذن تقييم WITH CHECK لا يخضع لفحص صلاحية الأعمدة، ويمكن سحب INSERT عن عمود يذكره التعبير. (ثقة عالية مستندة إلى رصد حي؛ إن ظهر خلاف ذلك بعد 038 يُعالَج بـmigration أمامية 039 ويُسجّل.)

#### G2 — الإصلاح المحدود المعتمد (كود الأعمال)

1. `TenantStaffAccountService::createStaffMember`: إضافة `->select('id')` قبل `->exists()` فقط. لا تغيير لتطبيع البريد، ولا للتحقق، ولا لـArgon2id، ولا لرسالة `ValidationException`، ولا لإنشاء العضوية/التدقيق/الإسناد.
2. `TenantStaffRoleMutationService::denyOwnRoleEdit`: إضافة `->select('role_id')`.
3. `LeadService::assignLead`: إضافة `->select('id')`.
4. حذف `'created_by_provider_operation_id' => null` و`'assigned_by_provider_operation_id' => null` و`'provider_operation_id' => null` من الإدراجات الثلاثة (تكافؤ مثبت أعلاه).
لا تغيير آخر في أي ملف كود أعمال، ولا في RLS/schema/routes/openapi/الواجهات.

#### G3 — خطة F09 وmigration 038 (مشروطة)

المرشحون للسحب الدقيق بعد الإصلاح أعلاه (15 منحة عمودية): SELECT على `tenant_staff_memberships(joined_at, created_by_membership_id, created_by_provider_operation_id, created_at, updated_at)`، SELECT على `tenant_staff_membership_roles(id, assigned_by_membership_id, assigned_by_provider_operation_id, assigned_at, revoked_by_membership_id, created_at, updated_at)`، وINSERT على الأعمدة الثلاثة للـprovenance. **لا سحب لأي منحة من 026** (تُحمى بقائمة صريحة في الـmigration) ولا سحب جدولي/دوري واسع.
الاسم: `2026_10_24_000038_narrow_tenant_runtime_select_grants.php`، forward-only، `down()` يرمي، مع preconditions fail-closed: وجود `daleel_tenant_runtime` بخصائص NOLOGIN/NOSUPERUSER/NOBYPASSRLS/NOCREATEDB/NOCREATEROLE وبلا ملكية/CREATE، وتطبيق 037 مسبقًا، وأن كل عمود مرشح ممنوح فعلًا الآن وغير مذكور في قائمة 026.
**بوابة الإنشاء:** تُنشأ 038 فقط بعد أن يثبت «مراجع استعلامات» (DB::listen على `pgsql_tenant_runtime` خلال كل الاختبارات) أن أي استعلام لا يذكر أي عمود مرشح. إن ذُكر عمود ⇒ يُستثنى من السحب أو تُلغى 038 ويُسجّل NOT_APPLICABLE.
**عند فشل 038:** تُترك RM02 كما هي، لا rollback مدمر ولا تعديل صامت، ويُسجّل السبب؛ التصحيح يكون بـmigration أمامية لاحقة بعد مراجعة.

#### G4 — خطة HTTP Kernel (ما هو ممكن فعليًا)

سلسلة الـmiddleware الحقيقية لمسارات `/company/*` (من `routes/api.php` + أولويات `bootstrap/app.php`): `ResolveTenantHost` → `RejectCompanyContextSelectors` → `RequireAllowedSpaOrigin` → `TenantStaffRequestContext` → `auth:tenant_staff` → `ValidateTenantStaffSession`.
المتطلبات المثبتة بالقراءة: `TENANT_STAFF_AUTH_ENABLED=true` + `APP_ENV` في (local, testing) لتمرير `ResolveTenantHost`؛ ترويسة `Origin` من `config('cors.allowed_origins')` (الافتراضي `http://localhost:3001`)؛ ترويسة `Host` = `rm02-a.acceptance.localhost`؛ وجلسة تحوي `identity.tenant_staff` (tenant_id, hostname, user_id, membership_id, auth_version, authorization_version, authenticated_at) **بالإضافة إلى** مفتاح SessionGuard الحقيقي (`Auth::guard('tenant_staff')->getName()` ⇒ معرّف الموظف) حتى يسلك الحارس مسار `TenantStaffUserProvider::retrieveById` الحقيقي على `pgsql_tenant_runtime` (نموذج `TenantStaffUser` يحدد الاتصال والأعمدة السبع صراحةً).
**لن يُستخدم** `actingAs()` ولا mock ولا تعطيل middleware ولا route اختبارية ولا تحويل الاتصال الافتراضي إلى owner في مسار الطلب.
**NOT_EXECUTED مسبقًا ومبرَّر:** `POST /api/v1/auth/login` الحقيقي — بصمات fixtures الحالية `$argon2id$rm02-synthetic-fixture-not-a-credential` ليست Argon2id صالحة، وتصحيحها يتطلب كتابة دائمة على fixtures (UPDATE على `password_hash` بمبدأ مميّز) وهو ما يمنعه شرط «لا كتابة دائمة»؛ يُقترح لمرحلة لاحقة.
السيناريوهات المخططة: مسار مسموح لـtenant A؛ نفس الجلسة على Host B ⇒ رفض بلا كشف؛ Host غير معرّف ⇒ `RESOURCE_NOT_FOUND`؛ `X-Forwarded-Host` مزوّر ⇒ يُتجاهل (لا proxy موثوق)؛ إصدار تفويض قديم/عضوية معلّقة ⇒ 401 بظرف خطأ آمن؛ بلا جلسة ⇒ 401؛ بلا Origin ⇒ 403؛ `X-Tenant-ID`/`tenant_id` على مسار context ⇒ `TENANT_SELECTOR_NOT_ALLOWED`؛ RBAC ناقص ⇒ 403 `AUTHORIZATION_DENIED`؛ عزل leads عبر HTTP بين A وB؛ التحقق من عدم ظهور SQLSTATE/stack في أي ظرف؛ وفحص أن GUC يُمسح بعد الطلب (الاتصال نفسه يعود بلا سياق).

#### G5/G6/G7 — خطة الاختبار والمخاطر

التسلسل: `php -l` + reflection ⇒ اختبار characterization لـF07 (قبل/بعد) ⇒ اختبارات الخدمات ⇒ HTTP Kernel ⇒ مراجع الاستعلامات لـF09 ⇒ (مشروط) 038 ⇒ `verify`/`probe`/`test all` مرتين ⇒ مقارنة بصمة fixtures قبل/بعد ⇒ negative guards. خط الأساس للمقارنة: probe 79/79 و`test all` 15/15 (441 assertions)؛ ستزيد الأعداد بالاختبارات الجديدة فتُسجّل القيم الفعلية لا 15/15.
**المخاطر وآلية التوقف:** (أ) أي كتابة دائمة غير مقصودة أو نمو fixtures ⇒ STOP. (ب) فشل إدراج بعد 038 ⇒ لا re-grant صامت؛ توثيق + 039 لاحقًا. (ج) F06 يبقى مفتوحًا ولا يُعلن مغلقًا. (د) F08 لا يُعالج (لا SELECT على جدول provider ولا SECURITY DEFINER). (هـ) F10 يُختبر توصيفيًا فقط بلا تغيير قاعدة العمل. (و) `Run-Migrations.ps1` يتوقع 36 ملفًا وسيرفض — لن يُشغَّل. (ز) الأهداف المحمية DEV/Old TEST/scratch قراءة فقط.
**rollback الآمن:** كل DML اختباري داخل معاملة تُلغى؛ لا rollback لقاعدة RM02 نفسها؛ لا DROP/RESET.
**الملفات المخطط تعديلها:** `TenantStaffAccountService.php`، `TenantStaffRoleMutationService.php`، `LeadService.php`، `TenantStaffAuditWriter.php` (حذف عمود واحد)، اختبار جديد `TenantStaffHttpKernelAcceptanceTest.php`، تعديل `TenantRuntimeWriteContractTest.php` (F07 صار يمر + مراجع استعلامات + F10)، `rm02-tool.php` (عقد 038 + suite جديد)، migration 038 إن ثبتت، والتوثيق.

### REMEDIATION-04 — سجل التنفيذ (بعد حفظ المراجعة أعلاه)

| Evidence ID | الوقت (Cairo) | الإجراء | النتيجة |
|---|---|---|---|
| DF01-RM04-006 | 06:31:07 | حفظ PRE-WRITE والتحقق | القسم موجود مرة واحدة؛ بصمة التقرير عند الحفظ `c45881cf…9068` مسجّلة في ledger ما قبل الكتابة؛ لم تكن أي كتابة قد وقعت. |
| DF01-RM04-007 | ~06:35 | G2: تعديل 4 ملفات خدمة | `createStaffMember` أضيف `->select('id')`؛ `denyOwnRoleEdit` أضيف `->select('role_id')`؛ `assignLead` أضيف `->select('id')`؛ حُذفت `created_by_provider_operation_id`/`assigned_by_provider_operation_id`/`provider_operation_id` من الإدراجات الثلاثة. `php -l` نظيف للأربعة. لا تغيير آخر في أي سلوك أو رسالة خطأ. |
| DF01-RM04-008 | ~06:37 | `test write` بعد الإصلاح | **F07 انتهى**: `createStaffMember` ينجح تحت `daleel_b10b_tenant_runtime`؛ 9/9 اختبارات و275 assertion، exit 0. أثناء الوصول إليها صُحِّح خطآن في **بناء الاختبار** (قراءة صفوف غير مُلتزمة عبر اتصال المالك، و`leads` تقرأ `SELECT *` شرعًا) — لا علاقة لهما بالمنتج. |
| DF01-RM04-009 | ~06:37 | F09 proof (`DB::listen` على اتصال runtime) | سجّل مراجع الاستعلامات لكل مسارات الخدمات (>20 قراءة): **لا استعلام يذكر أي عمود مرشح**؛ الاستعلام الوحيد بصيغة `select *` هو على `leads` (مبرَّر بعقد 037). |
| DF01-RM04-010 | ~06:38 | إثبات تكافؤ provenance | `information_schema`: الأعمدة الثلاثة `nullable=YES` و`default=NULL`. تجربة محكومة بـROLLBACK على اتصال الإعداد المميّز: الإدراج بإغفال العمود والإدراج بـNULL صريحة **يخزّنان القيم ذاتها بالضبط** (`[null, actor_membership, null, null]`). |
| DF01-RM04-011 | ~06:38 | F10 characterization | ما زال يتكرر: `createLead` يقبل عضوية **معلّقة** من نفس الشركة كـassignee (يعتمد على FK المركّب فقط)، بينما `assignLead` يفحص ACTIVE ويرفض. لم يُعدّل أي قاعدة عمل. |
| DF01-RM04-012 | ~06:40–06:43 | G4: HTTP Kernel | 11/11 اختبار و252 assertion، exit 0، بلا انحراف fixtures. أثناء البناء ظهرت ثلاث أخطاء **في الاختبار** صُحِّحت: أسماء حقول `display_name`/`initial_password`، `deleteJson($uri,$data,$headers)` (كانت الترويسات تُمرَّر كـbody فيرفضها حاجز Origin بـ`PERMISSION_DENIED`)، وتوقّع 400 لحالة أصلًا 422. |
| DF01-RM04-013 | ~06:41 | F13 (قيد منهجي، ليس عيب منتج) | أي طلب يفشل في المصادقة ينفّذ `Auth::logout()`، وبما أن عملية الاختبار تشارك نسخة التطبيق فإن `SessionGuard::$loggedOut` يبقى مفعّلًا فيُفشل كل طلب لاحق في نفس دالة الاختبار. أُعيد تنظيم الاختبارات: طلب مسموح واحد لكل دالة، والرفض مجمَّع. |
| DF01-RM04-014 | ~06:45 | G3: تطبيق migration 038 | شروط التطبيق تحققت (038 هو الملف المعلّق الوحيد، 37 مطبقة، لا جلسات). `artisan migrate` exit 0 ⇒ migrations=38. لقطات ACL في `.private/reports/remediation-04-acl-{before,after}.json`. |
| DF01-RM04-015 | ~06:45 | فرق ACL قبل/بعد 038 | **سُحبت 15 منحة عمودية بالضبط ولم تُضف أي منحة (0 gained)**: SELECT على `tenant_staff_memberships(joined_at, created_by_membership_id, created_by_provider_operation_id, created_at, updated_at)` و`tenant_staff_membership_roles(id, assigned_by_membership_id, assigned_by_provider_operation_id, assigned_at, revoked_by_membership_id, created_at, updated_at)`، وINSERT على الأعمدة الثلاثة للـprovenance. لا تغيير جدولي/دوري. |
| DF01-RM04-016 | ~06:46 | `verify` بعد 038 | 38 migrations، 36 tables، 18 FORCE RLS، **94 policies و15 triggers بلا تغيير**، بنية schema (بلا ACL) = DEV، وACL تطابق عقد 026+037+038 عمودًا بعمود على 36 جدولًا؛ DELETE جدولي على `role_permissions` فقط. |
| DF01-RM04-017 | ~06:47 | F12 (أثر مقصود مكتشف بالتشغيل) | سحب `SELECT` عن `tenant_staff_membership_roles.id` يمنع أيضًا `UPDATE … WHERE id = ?` (PostgreSQL يحتاج SELECT لأعمدة WHERE). الخدمة لا تفعل ذلك (تنقض بـ`tenant_id+membership_id+role_id`)، فالمنتج سليم؛ عُدِّلت عبارة الاختبار الخام لتطابق شكل الخدمة، وأُضيف تأكيد صريح للسلوك. |
| DF01-RM04-018 | ~06:48 | تصحيحان آخران في الاختبار بعد 038 | عبارة تدقيق خام كانت تسمّي `provider_operation_id` (صار محظورًا بالـACL) ⇒ أُزيل العمود وأُضيف تأكيد `objectDenied` لمحاولة انتحال provenance؛ وتأكيدات ACL الجديدة احتاجت معاملة مفتوحة لـSAVEPOINT. |
| DF01-RM04-019 | 03:47:57Z / 03:48:18Z / 03:48:51Z | `test all` ×3 | **29 اختبارًا / 29 ناجحة / 765 assertion / 0 errors / 0 failures / 0 skipped / exit 0** في كل مرة (9 RLS + 9 write-contract + 11 HTTP). stderr فارغ. بصمة fixtures قبل = بعد في كل تشغيل. |
| DF01-RM04-020 | ~06:49 | `probe` ×2 بعد 038 | **79/79 PASS / 0 FAIL** مرتين (phase=38). P13 صار `42501:permission`: انتحال provenance عبر عملية provider محجوب الآن على مستوى ACL قبل الـtrigger. P12 بلا تغيير (F06 قائم). |
| DF01-RM04-021 | ~06:49 | `guard-selftest` | رفض الأسماء المحمية ×3 قبل أي شبكة، وقفل OID خاطئ يفشل مغلقًا في `setUp`، وبلا انحراف fixtures. |
| DF01-RM04-022 | ~06:50 | الأهداف المحمية + ledger + Git | DEV وOld TEST: 36 migrations، 94 policies، **لا منح 037/038** (`has_any_column_privilege(leads)=false`، `joined_at=false`)، وعدّاد الصفوف كما كان (0/0 و39/18). scratch مطابقة. بصمة الـ**37 migration التاريخية لم تتغير**؛ المتغيرات: 4 خدمات + اختبار معدّل + 2 اختبار/migration جديدان + الأداة + التقرير. |

### REMEDIATION-04 — التقرير النهائي (A–X)

**A. EXECUTIVE SUMMARY.** أُغلق F07: إنشاء الموظفين يعمل الآن تحت مبدأ غير مالك دون أي قراءة لـ`password_hash`، بتغيير جراحي في ثلاثة فحوص وجود وحذف ثلاثة أعمدة provenance فارغة. ثبت بـ`DB::listen` أن منح 037 الزائدة لم تعد مستخدمة، فسُحبت 15 منحة عمودية بـmigration 038 على RM02 وحدها دون أي مساس بعقد 026 أو بأي policy/trigger. بُنيت مجموعة HTTP Kernel حقيقية (11 اختبارًا) تمر عبر كل الـmiddleware والحارس والمزوّد الحقيقي. **المجموعة المستهدفة: 29/29 و765 assertion، exit 0، ثلاث مرات، وprobe 79/79 مرتين، بلا أي انحراف في fixtures.** **القرار: PASS_SCOPED — ويبقى Customers NO-GO** لأن F06 خطر باقٍ معلن، وتسجيل الدخول الحقيقي ومسارات HTTP الكاملة الأخرى NOT_EXECUTED، والقرار النهائي للمالك.

**B. SCOPE & AUTHORIZATION.** نُفّذ داخل التفويض: إصلاح F07، مراجعة exists/provenance، تقييم وتطبيق F09 عبر migration أمامية واحدة على RM02، اختبارات HTTP، إعادة الاختبار، التوثيق. **لم يُنفَّذ أي محظور:** لا كتابة على DEV/Old TEST/Scratch/Production، لا إنشاء/حذف قاعدة أو دور أو حاوية، لا TRUNCATE/RESET/RefreshDatabase، لا GRANT ALL/SUPERUSER/BYPASSRLS، لا تعديل policy/trigger/ownership، لا تعديل migrations 001–037، لا تغيير routes/DTO/openapi/الواجهات، لا إصلاح لـF06/F08/F10، لا composer/npm، لا Git write. **Deviations: لا شيء.**

**C. READ-FIRST & GIT.** قُرئت بالترتيب: AGENTS، STATUS، PLAN، DECISIONS (D-1..D-12)، HANDOFF، ARCHITECTURE (جذر)، AGENTS الخاص بالـAPI، RLS_ARCHITECTURE، TENANT_STAFF_*، PROVIDER_*، SECURITY_AUDIT، SECURITY_BASELINE، API_CONVENTIONS، MODULE_CONVENTIONS، ملحقات DEV-FOUNDATION-01 كلها، TARGET_MANIFEST/README، أدوات RM02 واختباراتها، migrations 015/023/024/026/036/037، والخدمات/الحارس/الـmiddleware/الـcontrollers/الـroutes/config. **Git قبل:** API `d6870839…` + `M PostgresRlsIsolationTest.php` + 2 untracked. **بعد:** نفس HEAD، `M` لأربع خدمات + `M PostgresRlsIsolationTest.php`، وuntracked: migration 037، migration 038، `TenantRuntimeWriteContractTest.php`، `TenantStaffHttpKernelAcceptanceTest.php`، `docs/audits/`. الواجهات الثلاث `6fb01b88`/`9fa43bef`/`a802e44b` نظيفة قبل وبعد. **لا commit.**

**D. TARGET & PROTECTED RESOURCES.** RM02 = `daleel_crm_rm02_isolated` OID **21227** على 127.0.0.1:55437 داخل `daleel-pg-acceptance` (`d6ce6f4c1e92…`، cluster `7699972247235194919`، volume `daleel_acceptance_pg_data`)، مقفلة بـ`rm02-lock.json`. DEV (16412) وOld TEST (16413) وscratch: قراءة فقط، أعدادها ومنحها كما كانت، **وبلا 037/038**. لم يُستخدم منفذ المضيف 5432.

**E. PRE-WRITE EVIDENCE.** القسم «REMEDIATION-04 / PRE-WRITE CONTRACT & IMPACT REVIEW» حُفظ 2026-10-24 06:31:07 Cairo ببصمة `c45881cf…9068`، قبل أول تعديل كود (~06:35) وقبل migration 038 (~06:45). تنبّأ بالتصنيفات والنتائج التي تحققت لاحقًا (بما فيها أن B/C يعملان فقط بفضل منح 037).

**F. F07/F09 MATRIX.** جدول G1 أعلاه: الـSQL الفعلي قبل/بعد، ACL لكل عمود، وسبب كل نجاح/فشل. الخلاصة: `exists()` بلا أعمدة ⇒ `EXISTS(SELECT *)` ⇒ يلزمه SELECT على كل الأعمدة؛ تحديد عمود ممنوح يحل المشكلة ويحرّر 12 منحة SELECT.

**G. SOURCE DIFF (أدنى تغيير).** `TenantStaffAccountService::createStaffMember` (+`->select('id')`، −`created_by_provider_operation_id`)؛ `TenantStaffRoleMutationService::denyOwnRoleEdit` (+`->select('role_id')`) و`assignRole` (−`assigned_by_provider_operation_id`)؛ `LeadService::assignLead` (+`->select('id')`)؛ `TenantStaffAuditWriter::insert` (−`provider_operation_id`). بلا تغيير في canonical email، أو Argon2id، أو الحالة الأولية، أو إنشاء العضوية، أو مفردات التدقيق، أو invariant آخر مدير، أو الإصدارات التفاؤلية، أو الذرّية، أو RBAC/RLS، أو رسائل الأخطاء.

**H. CREATE STAFF — النتيجة.** تحت `daleel_b10b_tenant_runtime`: الإنشاء ينجح؛ البريد يُطبَّع (`RM04-New@Proof.invalid` ⇒ `rm04-new@proof.invalid`) مع الحفاظ على `display_email`؛ العضوية ACTIVE بإصدار 1 وتنتمي للشركة A؛ **حدث تدقيق واحد بالضبط**؛ `password_hash` مكتوب (أثبته CHECK `tenant_staff_password_argon2id_check`) وغير مقروء (`SELECT password_hash` ⇒ 42501)؛ يمكن إسناد دور للموظف الجديد فورًا؛ البريد المكرر ⇒ `ValidationException` بلا أي صف أو حدث تدقيق؛ شركة B لا ترى الموظف الجديد ولا تستطيع تعطيله؛ قارئ بلا `member.manage` يُرفض.

**I. ROLE/LEAD EXISTS & F10.** `denyOwnRoleEdit` و`assignLead` يعملان بعمود واحد ممنوح، وسلوكهما لم يتغير (ما زال يمنع تعديل الدور الذاتي ويشترط عضوية ACTIVE). **F10 يتكرر**: `createLead` يقبل عضوية معلّقة كـassignee (اختبار توصيفي)، بينما `assignLead` يرفضها — التفاوت محصور في الإنشاء، والإصلاح خارج هذا التفويض.

**J. PROVENANCE / TRIGGER / F08.** التكافؤ مثبت كتالوجيًا وتجريبيًا (DF01-RM04-010): الإغفال = NULL، والقيود/المحفزات تبقى محققة (`num_nonnulls(...)=1`، فرع provider في `tenant_staff_membership_creator_valid` يقصر على NULL، `tsmr_assignment_actor_check`، وسياسة tsse `provider_operation_id IS NULL`). **F08 لم يُعالَج** (لا SELECT على جدول provider ولا SECURITY DEFINER)؛ ومع ذلك صار انتحال provenance محجوبًا بالـACL بعد 038 (P13)، وهو تقليل أثر لا إغلاق للسبب.

**K. MIGRATION 038.** أُنشئت وطُبّقت: `2026_10_24_000038_narrow_tenant_runtime_select_grants.php`، forward-only و`down()` يرمي، مع أربع بوابات fail-closed: خصائص `daleel_tenant_runtime` (NOLOGIN/NOSUPERUSER/NOBYPASSRLS/بلا ملكية/بلا CREATE)، وتطبيق 037 مسبقًا، وأن كل عمود مرشح ممنوح فعلًا، وأن قائمة السحب **لا تتقاطع** مع عقد 026 (قائمة صريحة داخل الـmigration) + تحقق بعد السحب أن منح 026 سليمة. 12 `REVOKE SELECT (columns)` و3 `REVOKE INSERT (columns)`، بلا أي REVOKE جدولي/دوري.

**L. EFFECTIVE ACL BEFORE/AFTER.** قبل: SELECT أعمدة على 9 جداول. بعد: نفس 9 جداول لكن `tenant_staff_memberships` و`tenant_staff_membership_roles` عادتا إلى مجموعة 026 بالضبط؛ الكتابة على 8 جداول؛ DELETE جدولي على `role_permissions` فقط؛ صفر منحة مضافة. الوراثة مؤكدة حيًّا للدخولين `dl_truntime` و`daleel_b10b_tenant_runtime`. لا SELECT على `password_hash` أو `users` أو `tenant_memberships` أو جداول provider أو التدقيق.

**M. RAW A/B & FIXTURES.** probe 79/79 ×2 (59 قراءة + 20 كتابة): كتابة own مسموحة، INSERT عابر = RLS، UPDATE/DELETE عابر = 0 صفوف، `tenant_id`/DELETE/تدقيق = رفض كائني. كل DML اختباري داخل معاملات ملغاة؛ **بصمة RM02 متطابقة قبل/بعد كل تشغيل** (2 tenants، 4 staff، 3 roles، 14 role_permissions، leads=0، audit=0).

**N. SERVICE TESTS / AUDIT / RBAC / ATOMICITY.** `TenantRuntimeWriteContractTest` 9/9: ACL عمودية للدخولين، A/B خام، استقرار المحفزات (30 تكرارًا)، خدمات الأدوار/العضويات (9 أحداث لـ9 عمليات، صفر للمرفوض، إصدار التفويض يتراجع عند الفشل المكرر)، نطاقات Leads، F07، F09، تكافؤ provenance، F10.

**O. HTTP KERNEL.** **منفَّذ فعليًا** (11/11، 252 assertion) عبر الـroutes الحقيقية والـmiddleware الحقيقي والحارس والمزوّد الحقيقيين، بلا `actingAs` وبلا mock وبلا تعطيل middleware وبلا route اختبارية: قراءات مسموحة لـcontext/authorization/roles/staff/leads؛ **مسح GUC والمعاملة بعد كل طلب**؛ ترويسات التوجيه (`X-Forwarded-Host`/`X-Forwarded-Server`/`Forwarded`) **تُتجاهل** (`getTrustedProxies()=[]`)؛ جلسة A على host B ورموز tenant مزوّرة وhost غير معرّف ⇒ رفض بلا كشف؛ ستة سيناريوهات لسلامة الجلسة (بلا جلسة، إصداران قديمان، عضوية معلّقة، عضوية غير مطابقة، عمر مطلق منتهٍ) ⇒ 401؛ Origin غير مسموح/غائب ⇒ 403؛ `X-Tenant-ID` ⇒ 400 `TENANT_SELECTOR_NOT_ALLOWED` و`tenant_id` كحقل ⇒ 422؛ RBAC لكل endpoint (قراءة وكتابة) ⇒ 403 `AUTHORIZATION_DENIED` مع منح مباشر (`member.view`) مسموح؛ كتابات A الحقيقية (lead/role/staff) تنتج صفوفًا في A فقط مع 3 أحداث تدقيق؛ خمسة أفعال عابرة من B على lead لـA ⇒ 403 والصف لم يتغير؛ ظرف الأخطاء آمن (لا SQLSTATE/stack/`permission denied`/`row-level security`/`password_hash`) ومعه `request_id`. **NOT_EXECUTED (مبرَّر):** `POST /auth/login` الحقيقي — بصمات fixtures ليست Argon2id صالحة وتصحيحها يتطلب كتابة دائمة؛ كذلك CSRF الحقيقي (Laravel يتجاوزه في `APP_ENV=testing`)، وتدفق `sanctum/csrf-cookie`، والـthrottling، ومسارات `/super/*`. **ملاحظة منهجية:** كتابات HTTP الناجحة نُفِّذت داخل معاملة خارجية على نفس اتصال runtime فأصبح commit الطلب تحرير savepoint — لذلك سلوك الـcommit على المستوى الأعلى أُثبت للقراءات فقط.

**P. REGRESSION vs RM03.** خط RM03: probe 79/79 و`test all` 15/15 (441 assertion). الآن: probe **79/79** (نفسه) و`test all` **29/29 (765 assertion)** — الزيادة 14 اختبارًا و324 assertion من اختبارات RM04 الجديدة؛ لا اختبار سابق فقد تغطيته: الاختبارات الثلاثة التي عُدِّلت تأكيداتها (داخل write-contract) عُدِّلت لتطابق العقد الجديد بعد 038 مع إضافة تأكيدات أقوى (رفض كائني للأعمدة المسحوبة، ورفض انتحال provenance). 0 skipped في كل التشغيلات.

**Q. F06 — حد الثقة.** مثبت للـHTTP: الـtenant من Host فقط (ترويسات التوجيه مُتجاهلة — مثبت حيًّا)، الجلسة مربوطة بالـhost والإصدارات (ستة سيناريوهات)، GUC يُضبط من الخادم فقط ويُمسح بعد الطلب (مثبت حيًّا)، لا مدخل API يصل إلى `set_config`. **المتبقي (FACT):** اتصال DB runtime مخترق مع GUC مزوّر يستطيع القراءة **والكتابة** في جداول tenant-scoped لشركة أخرى (P12: `INSERT roles` في B نجح)؛ الجداول المرتبطة بالفاعل (tsmr/tspg/tsse) تحتاج معرّف فاعل حقيقي من الشركة الأخرى. **F06 لم يُغلق** ولا يُعدّ RLS ضمانًا ضد اتصال مخترق. الشدة: P1 تحت اختراق قاعدة البيانات، P2 عمومًا.

**R. RISK REGISTER.**

| ID | الأولوية | النوع | الحالة |
|---|---|---|---|
| F07 | — | FACT | **RESOLVED** ومثبت تحت مبدأ غير مالك وعبر HTTP. |
| F09 | — | FACT | **RESOLVED**: 15 منحة مسحوبة بـ038، مع إثبات عدم الاستخدام قبل السحب. |
| F06 | P1 (اختراق DB) / P2 | FACT | **مفتوح**؛ لا مسار HTTP؛ يحتاج تعديلًا معماريًا (ربط الفاعل في سياسات الجداول tenant-only أو إشرافًا على مستوى الاتصال) بتفويض مستقل. |
| F08 | P3 | INFERENCE + FACT جزئي | **مفتوح**: فرع provider في المحفزات يعتمد على خطة الاستعلام؛ مستقر في 30 تكرارًا؛ أثره تراجع بعد 038 (ACL يمنع تسمية العمود). |
| F10 | P3 | FACT | **مفتوح**: `createLead` يقبل عضوية معلّقة؛ موصَّف باختبار؛ إصلاحه قرار مالك. |
| F12 | P3 | FACT (مقصود) | سحب `SELECT` عن `tenant_staff_membership_roles.id` يمنع `UPDATE … WHERE id`؛ المنتج لا يعتمد عليه؛ على أي كود مستقبلي أن ينقض بـ`(tenant_id, membership_id, role_id)`. |
| F13 | P3 | FACT (منهجي) | `Auth::logout()` في طلب مرفوض يُفسد الحارس لبقية دالة الاختبار في نفس العملية؛ قيد على بناء اختبارات HTTP، لا عيب منتج. |
| CRED | P2 | FACT | توصية تدوير اعتمادات acceptance المحلية (رصد RM02)؛ لم تُغيَّر. |
| OLD-TEST / PWSH | P2 / P3 | FACT | كما في RM02/RM03 بلا تغيير. |

**S. CHANGES (ملفات/DB/وثائق).** **DB:** RM02 فقط — migration 038 (15 سحب منحة)؛ لا بيانات دائمة أُضيفت أو حُذفت. **كود (tracked، معدّل):** 4 خدمات + `PostgresRlsIsolationTest.php`. **كود (untracked، جديد):** migration 037، migration 038، `TenantRuntimeWriteContractTest.php`، `TenantStaffHttpKernelAcceptanceTest.php`، `docs/audits/`. **خارج Git:** `tools/dev-db/acceptance/rm02-tool.php` (أمر `apply-migration` معمّم + suite `http` + عقد ACL لكل مرحلة + `TENANT_STAFF_AUTH_ENABLED` في بيئة الاختبار)، README، TARGET_MANIFEST، docs الجذر، و`.private/reports/*`. **حفظ المعرفة:** ملفات الجذر و`tools/dev-db/` خارج مستودعات Git؛ تحتاج نسخًا احتياطيًا يديره المالك — commit في API **لا** يحفظها.

**T. GATES.** G0 **PASS** · G1 **PASS** · G2 **PASS** (F07) · G3 **PASS** (038 مطبقة ومثبتة، بلا تراجع صلاحيات) · G4 **PASS** للمنفَّذ مع NOT_EXECUTED موثق (login/CSRF/throttle/super) · G5 **PASS** (29/29 ×3، 79/79 ×2، بلا drift) · G6 **PASS** (مراجعة صادقة؛ لا P0 جديد) · G7 **PASS**. **Overall: PASS_SCOPED — Customers NO-GO.**

**U. DELTA/IMPACT vs RM03.** تغيّر: ثلاثة فحوص وجود صارت عمودية؛ ثلاثة أعمدة provenance لم تعد تُسمّى؛ ACL الـruntime أضيق بـ15 منحة؛ مجموعة HTTP جديدة؛ الأعداد 15/441 ⇒ 29/765. لم يتغيّر: أي policy أو trigger أو FORCE RLS (94/15)، migrations 001–037 (بصمة مطابقة)، عقد 026، routes/DTO/openapi، الواجهات الثلاث، DECISIONS، DEV/Old TEST/scratch، بنية schema مقابل DEV. قابلية إعادة الإنتاج: بيئة نظيفة تحتاج 38 migration + `roles-pre/post` + fixtures؛ 037/038 يجب تطبيقهما معًا بالترتيب (038 ترفض بغياب 037).

**V. NEXT SINGLE STEP (مقترح، غير منفَّذ).** REMEDIATION-05: تسجيل دخول حقيقي من طرف إلى طرف على RM02 — يتطلب قرار المالك بكتابة دائمة واحدة: ضبط بصمة Argon2id صالحة لموظفي fixtures الاصطناعيين (أو إضافة موظف fixture مخصص للدخول)، ثم اختبار `POST /auth/login` + `sanctum/csrf-cookie` + CSRF الحقيقي + الحدود (throttling) + دوران الجلسة + `logout`. **شروط STOP:** أي حاجة لتعديل routes أو إضعاف CSRF/الحدود، أو كتابة على DEV/Old TEST/scratch، أو نمو fixtures غير محدود، أو منح أوسع.

**W. NEXT-TOOL HANDOFF.** اقرأ أولًا HANDOFF ثم هذا الملحق. **لا تعِد** `create-db`/`migrate`/`apply-migration` (ترفض بالبوابات). **الأوامر الآمنة** من `daleel-crm-api/` بـHerd PHP 8.4: `php ../tools/dev-db/acceptance/rm02-tool.php verify` ثم `probe` ثم `test all` (أو `test rls|write|http`) وعند الحاجة `guard-selftest`. **ممنوع:** DEV/Old TEST/scratch، منفذ المضيف 5432، `Run-Migrations.ps1` (يتوقع 36 ملفًا وسيرفض)، `Run-AcceptanceTests.ps1`، أي reset/drop، بدء Customers. **غير منجز:** login/CSRF/throttle الحقيقية، F06، F08، F10، تطبيق 037/038 على DEV، قرار التخلص من fixtures Old TEST وRM02.

**X. COPY-READY SUMMARY.**
1. نُفّذ REMEDIATION-04 في 2026-10-24 ضمن التفويض، والكتابة على RM02 فقط (OID 21227).
2. PRE-WRITE حُفظ 06:31:07 ببصمة c45881cf قبل أي تعديل، وتنبّأ بالنتائج.
3. **F07 أُغلق**: سبب الفشل أن `exists()` في Laravel يُترجم `EXISTS(SELECT *)` فيطلب قراءة `password_hash`.
4. الإصلاح: `->select('id')` / `->select('role_id')` في ثلاثة مواضع فقط، بلا أي تغيير سلوكي آخر.
5. حُذفت ثلاثة أعمدة provenance كانت تُمرَّر NULL صريحة، بعد إثبات التكافؤ كتالوجيًا وتجريبيًا.
6. إنشاء الموظف يعمل الآن تحت مبدأ غير مالك: تطبيع بريد، عضوية ACTIVE، حدث تدقيق واحد، ولا قراءة للبصمة.
7. البريد المكرر يُرفض بالتحقق ولا يترك صفوفًا ولا أحداث تدقيق؛ شركة B لا ترى الموظف الجديد.
8. **F09 أُغلق**: `DB::listen` أثبت أن لا استعلام يقرأ الأعمدة الزائدة؛ `select *` الوحيد على `leads` ومبرَّر.
9. migration **038** سحبت 15 منحة عمودية (12 SELECT + 3 INSERT) ولم تضف شيئًا؛ بوابات fail-closed تحمي عقد 026.
10. لا تغيير لأي policy أو trigger أو ownership أو الـ37 migration السابقة؛ 94 policies و15 triggers كما هي.
11. DELETE جدولي ما زال على `role_permissions` فقط؛ لا تحديث لأي `tenant_id`؛ التدقيق إدراج فقط.
12. **HTTP Kernel منفَّذ حقيقيًا**: 11 اختبارًا و252 assertion عبر الـmiddleware والحارس الحقيقيين بلا mock.
13. ترويسات `X-Forwarded-Host`/`Forwarded` **مُتجاهلة** (لا proxy موثوق) — مثبت حيًّا.
14. جلسة شركة على host شركة أخرى، وإصدار تفويض قديم، وعضوية معلّقة، وعمر جلسة منتهٍ ⇒ 401 بلا كشف.
15. Origin غير مسموح ⇒ 403؛ `X-Tenant-ID` ⇒ 400؛ `tenant_id` كحقل ⇒ 422؛ أظرف الأخطاء بلا SQLSTATE/stack.
16. RBAC مُطبَّق لكل endpoint؛ منح مباشر (`member.view`) يعمل عبر HTTP؛ خمسة أفعال عابرة من B مرفوضة والصف لم يتغير.
17. GUC والمعاملة يُمسحان بعد كل طلب — مثبت حيًّا على اتصال runtime.
18. **المجموعة المستهدفة: 29/29، 765 assertion، 0 skipped، exit 0 — ثلاث مرات**؛ probe 79/79 مرتين؛ بلا أي انحراف fixtures.
19. تصحيحات هذه الجولة كانت كلها في **بناء الاختبارات** (أسماء حقول، توقيع `deleteJson`، قراءة صفوف غير مُلتزمة، رموز حالة) لا في المنتج.
20. F13 (منهجي): طلب مرفوض يُنفّذ logout فيُفسد الحارس لبقية دالة الاختبار — أُعيد تنظيم الاختبارات وفقًا لذلك.
21. F12 (مقصود): بعد سحب `SELECT` عن `tsmr.id` لا يصح `UPDATE … WHERE id`؛ المنتج ينقض بالمفتاح المركّب.
22. **F06 ما زال مفتوحًا**: اتصال DB مخترق بـGUC مزوّر يستطيع الكتابة في شركة أخرى؛ لا مسار HTTP؛ لا يُعلن مغلقًا.
23. F08 و F10 لم يُعالجا (خارج التفويض)؛ F10 موصَّف باختبار، وانتحال provenance صار محجوبًا بالـACL.
24. DEV وOld TEST وscratch بلا تغيير ولا تحملان منح 037/038؛ منفذ المضيف 5432 لم يُستخدم.
25. **NOT_EXECUTED**: `POST /auth/login` الحقيقي وCSRF/throttle وsuper و تطبيق 037/038 على DEV.
26. Git: HEAD بلا تغيير، 5 ملفات معدّلة و5 مسارات غير متتبعة، **لا commit**؛ ملفات الجذر وأدوات القبول خارج Git وتحتاج حفظًا مستقلًا.
27. البوابات G0–G7 كلها PASS ضمن نطاقها؛ **القرار: PASS_SCOPED وCustomers NO-GO** بانتظار مراجعة المالك.
28. التالي المقترح: REMEDIATION-05 لتسجيل دخول حقيقي (يتطلب قرار مالك بكتابة بصمة Argon2id واحدة على fixtures).

---

# REMEDIATION-05 / PRE-WRITE AUTH CONTRACT & SESSION SAFETY REVIEW

> هذا القسم مكتوب على القرص **قبل** أي تعديل كود أو أي كتابة على قاعدة البيانات في جولة REMEDIATION-05.
> توقيت الحفظ وبصمة SHA-256 مسجّلان في سجل الأدلة بعد الحفظ مباشرة. لا يُسجَّل هنا أي سر أو بصمة كلمة مرور أو Cookie أو Session ID.

## A. هدف الجولة وخط الأساس

الهدف: إثبات رحلة مصادقة حقيقية لموظف Tenant عبر HTTP wire فعلي — طلب CSRF cookie، ثم POST login حقيقي، ثم جلسة محفوظة في عميل مستقل، ثم طلب authenticated لاحق، ثم logout وإبطال — مع فصل صريح بين ما يُثبت في HTTP Kernel (PHPUnit) وما لا يُثبت إلا على خادم HTTP حقيقي خارج `APP_ENV=testing`.

خط الأساس المقارن هو ملحق REMEDIATION-04 في هذا الملف نفسه:
- `test all` = 29/29 اختبار، 765 assertion، صفر errors/failures/skips، ثلاث تشغيلات.
- `probe` = 79/79 مرتين على phase 38.
- RM02: 38 migration، 36 جدول، 18 FORCE RLS، 94 policy، 15 trigger، fixtures: 2 tenants / 4 staff / 3 roles / 14 role_permissions / leads=0 / tenant_staff_security_events=0.
- F07 و F09 مغلقان؛ **F06 و F08 و F10 مفتوحة**؛ F12 و F13 قيود منهجية موثقة.
- NOT_EXECUTED في RM04: `POST /auth/login` الحقيقي، CSRF الحقيقي، throttling، HTTP wire، `/super/*` عبر HTTP.

## B. معرّفات الموارد وأقفال الهدف وحالة Git (G0، قراءة فقط)

تم التحقق من كل ما يلي قبل أي كتابة:

| المورد | القيمة المرصودة | المصدر |
|---|---|---|
| container | `daleel-pg-acceptance` / `d6ce6f4c1e92f8e381ed2830125d697bcee269b01078e6c7402b4ae2f6402908` | `rm02-tool.php preflight` |
| compose project / volume | `daleel-crm-acceptance` / `daleel_acceptance_pg_data` | preflight |
| container IP / منافذ منشورة | `172.19.0.2` / `127.0.0.1:55433`، `127.0.0.1:55437` (loopback فقط) | `docker ps` |
| cluster system identifier | `7699972247235194919` | preflight |
| RM02 | `daleel_crm_rm02_isolated` OID **21227**، owner `daleel_b10b_owner`، `127.0.0.1:55437` | preflight + verify |
| DEV | `daleel_acceptance_dev` OID 16412، 36 migration، بلا منح 037/038 | قراءة تجميعية |
| Old TEST | `daleel_crm_b10b_disposable` OID 16413، 36 migration، 18 tenants، 39 صفًا في `users` القديم، 1 security audit event | قراءة تجميعية |
| scratch | `daleel-pg-scratch` على 55432، حاوية ومجلد منفصلان | preflight (PROTECTED SCRATCH VERIFIED UNCHANGED) |
| جلسات متزامنة | `OTHER_CLIENT_SESSIONS=0` على الثلاث قواعد | `pg_stat_activity` |

حالة Git قبل الجولة (مطابقة تمامًا لخط أساس RM04، بلا انحراف):
- `daleel-crm-api` HEAD `d6870839f38b1f05786288071dbe0bb7719d5386`، فرع `phase-0-stabilize-baseline`؛ معدّل متتبع: 4 خدمات + `tests/Feature/Tenancy/PostgresRlsIsolationTest.php`؛ غير متتبع: migrations `…000037`/`…000038`، `TenantRuntimeWriteContractTest.php`، `TenantStaffHttpKernelAcceptanceTest.php`، `docs/audits/`.
- `daleel-crm` HEAD `6fb01b8838de52de621dab4691a5cdd5710c29f6` — نظيف.
- `daleel-crm-admin` HEAD `9fa43befadaaa5d4583f8de6bf7a06c60e891bef` — نظيف.
- `daleel-crm-super-admin` HEAD `a802e44b8a269071bcb46fcaa675aafb43b12a87` — نظيف.

سجل بصمات خط الأساس (75 سطرًا، بلا أسرار): `tools/dev-db/acceptance/.private/reports/remediation-05-hashes-before.txt`.

جرد التشغيل: Herd PHP 8.4.27 (NTS, VC++ 2022 x64)، `laravel/framework v13.34.0`، `laravel/sanctum v4.3.3`. ملف `.env` الحي يحمل `APP_ENV=local`، `SESSION_DRIVER=redis`، `CACHE_STORE=redis`، `QUEUE_CONNECTION=redis`، `MAIL_MAILER=log` — وبالتالي **لا يمكن** استخدام `.env` كما هو لخادم الاختبار (Redis غير مضمون التشغيل، ولا يجوز مشاركة store مع بيئة أخرى)؛ العزل سيكون بـ `SESSION_DRIVER=file` و `CACHE_STORE=file` ومسارات تخزين خاصة بعملية الاختبار فقط.

## C. مصفوفة عقد المصادقة والجلسة (Contract Matrix)

المسارات الفعلية من `route:list` الحي (ليست مفترضة):

| المسار | Middleware الفعلي بالترتيب |
|---|---|
| `GET sanctum/csrf-cookie` | مجموعة `web` = EncryptCookies, AddQueuedCookiesToResponse, StartSession, ShareErrorsFromSession, PreventRequestForgery, SubstituteBindings |
| `POST api/v1/auth/login` | api, ResolveTenantHost, RequireAllowedSpaOrigin, TenantStaffRequestContext |
| `GET api/v1/auth/me` | api, ResolveTenantHost, RequireAllowedSpaOrigin, TenantStaffRequestContext, Authenticate:tenant_staff, ValidateTenantStaffSession |
| `POST api/v1/auth/logout` | نفس `me` |
| `GET api/v1/company/context` | api, ResolveTenantHost, RejectCompanyContextSelectors, RequireAllowedSpaOrigin, TenantStaffRequestContext, Authenticate:tenant_staff, ValidateTenantStaffSession |

مجموعة `api` الحيّة = `Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful` ثم `SubstituteBindings` (مستخرجة بـ reflection من الـKernel الحي، لا من التوثيق).

| البند | النتيجة الحية | التصنيف |
|---|---|---|
| **CSRF في الـwire** | `EnsureFrontendRequestsAreStateful::frontendMiddleware()` يركّب EncryptCookies, AddQueuedCookiesToResponse, StartSession, `config('sanctum.middleware.validate_csrf_token')`, AuthenticateSession. و `config/sanctum.php` يعيّن `validate_csrf_token => Illuminate\Foundation\Http\Middleware\ValidateCsrfToken::class` وهو في Laravel 13 **موروث من** `PreventRequestForgery`. | VERIFIED_SOURCE |
| **سبب فشل RM04 في إثبات CSRF** | `PreventRequestForgery::handle()` السطر 99 يستدعي `runningUnitTests()`، وتعريفه السطر 130: `$this->app->runningInConsole() && $this->app->runningUnitTests()`. داخل PHPUnit الشرطان صحيحان ⇒ **يُتجاوز CSRF كليًا**. على خادم HTTP حقيقي `runningInConsole()` = false ⇒ يُنفَّذ فعلًا. | VERIFIED_SOURCE (هذا هو مبرر الجولة) |
| **stateful detection** | `fromFrontend()` يقرأ Referer ثم Origin، ويطابق مع `config('sanctum.stateful')` = افتراضيًا `localhost:3000,localhost:3001,localhost:3002,localhost:8000`. إذن Origin `http://localhost:3001` ⇒ stateful ⇒ CSRF + session. | VERIFIED_SOURCE |
| **بوابة Origin الخاصة بالمنتج** | `RequireAllowedSpaOrigin` يرفض بـ `abort(403)` أي طلب لا يحمل Origin ضمن `config('cors.allowed_origins')` حصرًا (مقارنة `in_array` صارمة). هذه بوابة server-side مستقلة تمامًا عن CORS. | VERIFIED_SOURCE |
| **CORS** | `config/cors.php`: `paths=[api/*, sanctum/csrf-cookie]`، `supports_credentials=true`، origins افتراضيًا `http://localhost:3000..3002`، وفلترة ترفض `*` وأي origin بمسار/استعلام/اعتماد مضمّن. | VERIFIED_SOURCE |
| **بوابة البيئة** | `ResolveTenantHost` يرفض بـ `TenantAccessException::objectNotFound()` إن لم يكن `identity.tenant_auth_client_enabled === true` **و** `app.env ∈ {local, testing}`. إذن `APP_ENV=local` مسار منتج مشروع، لا إضعاف. | VERIFIED_SOURCE |
| **Trusted proxies** | لا `trustProxies()` ولا `TrustProxies` في `bootstrap/app.php` ولا في `app/` ⇒ `X-Forwarded-Host` مُهمَل تمامًا. | VERIFIED_SOURCE |
| **أدوار DB في مسار login** | `TenantStaffCredentialLookup` يستخدم اتصال `pgsql_tenant_auth` فقط، ويستدعي `public.lookup_tenant_staff_credentials(hostname, base_domain, environment_scope, canonical_email)`. الدالة SECURITY DEFINER، `search_path=pg_catalog,pg_temp`، وACL التنفيذ محصور في `daleel_tenant_auth_lookup` و `daleel_tenant_auth_client` فقط. إذن `password_hash` لا يُقرأ بـSELECT مباشر من أي runtime. | VERIFIED_LIVE (`pg_get_functiondef` + `proacl`) |
| **سياق RLS** | `TenantStaffRequestContext` يفتح معاملة حقيقية على `pgsql_tenant_runtime`، يصفّر `app.context_mode`/`app.tenant_id`/`app.user_id` بـ `set_config(...,true)`، ثم **يَعمل commit في نهاية الطلب الناجح** و `rollBack()` على أي استثناء. و `TenantStaffContextGuard::bindAndRevalidate` يرفض العمل إن كان `transactionLevel() < 1`. | VERIFIED_SOURCE |
| **تحقق كلمة المرور** | `TenantStaffLoginService::authenticate` يشترط `str_starts_with($hash, '$argon2id$')` **و** `Hash::driver('argon2id')->check(...)`. و `config/hashing.php` يضبط `driver=argon2id` افتراضيًا و `argon.memory=65536, time=4, threads=1`. | VERIFIED_SOURCE |
| **منع إحصاء الحسابات** | عند عدم وجود المستخدم يُستخدم `config('identity.dummy_password_hash')` (بصمة Argon2id ثابتة في الكود) فيُنفَّذ تحقق وهمي بنفس الكلفة ⇒ لا تمييز زمني واضح بين بريد موجود وغير موجود، والرسالة واحدة. | VERIFIED_SOURCE |
| **تدوير الجلسة** | بعد النجاح: `Auth::guard('tenant_staff')->login()` ثم `$request->session()->regenerate()` ثم `put('identity.tenant_staff', [...authenticated_at...])`. | VERIFIED_SOURCE |
| **Logout** | `Auth::guard()->logout()` + `forget('identity.tenant_staff')` + `session()->invalidate()` + `regenerateToken()`. | VERIFIED_SOURCE |
| **إعادة التحقق في كل طلب** | `TenantStaffRequestContext` يعيد تحقيق السياق من الجلسة عبر `activateFromSession` ويقارن `tenant_id` و `hostname` بـ `hash_equals`، ويتحقق من `tenants.status=ACTIVE` و `tenant_staff_users.status=ACTIVE` و `auth_version` و `memberships.status=ACTIVE` و `authorization_version` — وإلا `AuthenticationException` + تصفير GUC + مسح الجلسة. | VERIFIED_SOURCE |
| **عمر الجلسة المطلق** | `ValidateTenantStaffSession` يرفض إذا `now - authenticated_at >= identity.absolute_session_lifetime` (افتراضي 28800 ثانية) أو إذا `authenticated_at` في المستقبل. | VERIFIED_SOURCE |
| **Cookies** | `config/session.php`: `domain=null` (host-only)، `path=/`، `http_only=true`، `same_site=lax`، `lifetime=120` دقيقة، و `secure = (APP_ENV==='local' ? env(SESSION_SECURE_COOKIE,false) : true)`. أي أن السماح بـ `Secure=false` على loopback **موجود أصلًا في إعداد المنتج** ولا يتطلب أي تعديل. ملاحظة: `EnsureFrontendRequestsAreStateful::configureSecureCookieSessions()` يفرض `http_only=true` و `same_site=lax` في زمن التشغيل. | VERIFIED_SOURCE |
| **Throttling على login** | **موجود، لكن ليس كـroute middleware.** لا `throttle:` على `api/v1/auth/*` إطلاقًا (`throttle:api` موجود على `/super/*` فقط). الحماية داخل الخدمة: `TenantStaffRateLimiter` بمفتاحين — `sha256(tenant_id|email|ip)` بسقف `identity.login.max_failures` = 5، و `sha256(ip)` بسقف `ip_max_failures` = 100، بتحلل `decay_seconds` = 900 ثانية؛ والنجاح يستدعي `clearIdentityFailures`. | VERIFIED_SOURCE |
| **رموز الأخطاء الفعلية** | من `ApiErrorResponse`: بيانات خاطئة ⇒ **401 AUTH_INVALID_CREDENTIALS**؛ CSRF ⇒ **419 AUTH_CSRF_INVALID** (من `TokenMismatchException`)؛ تجاوز الحد ⇒ **429 AUTH_RATE_LIMITED**؛ جلسة منتهية ⇒ **401 AUTH_SESSION_EXPIRED**؛ غير مصادق ⇒ 401 AUTH_UNAUTHENTICATED؛ Origin مرفوض ⇒ 403 PERMISSION_DENIED. | VERIFIED_SOURCE |
| **كتابات دائمة في مسار login** | `AuthSecurityEvents::emit()` يكتب إلى `Log::channel('structured')` **فقط**، وقناة `structured` في `config/logging.php` تكتب إلى `php://stderr` بصيغة JSON. **لا صفوف قاعدة بيانات** تُنشأ بسبب login أو فشله: لا `last_login`، ولا `tenant_staff_security_events`. استعلامات `bindAndRevalidate` كلها SELECT. | VERIFIED_SOURCE |
| **أثر تشغيلي متوقع** | (1) ملفات جلسات محلية في مجلد معزول، (2) ملفات cache لعدّادات RateLimiter، (3) stderr الخادم المؤقت. كلها ملفات أنشأتها هذه الجولة، معزولة، وقابلة للحصر — وليست بيانات أعمال. | VERIFIED_SOURCE |

**فجوات معمارية مرصودة في المراجعة (لا تُعالَج برمجيًا في هذه الجولة):**
1. `SANCTUM_STATEFUL_DOMAINS` و `CORS_ALLOWED_ORIGINS` يحملان `localhost:300x` بينما الـAPI يُخدَم على `{slug}.{BASE_DOMAIN}`. هذا يعني أن طلب SPA حقيقي من متصفح هو **cross-site** (مضيف مختلف) وcookie الجلسة بـ `SameSite=lax` **لن يُرسَل** مع POST cross-site. هذا gap توافق متصفح يجب أن يُقرَّر معماريًا (نطاق أب مشترك أو `SameSite=None; Secure`)، ولن أعدّل سياسة المنتج لإخفائه.
2. لا توجد حماية throttling على مستوى الـroute لـlogin؛ الحماية الموجودة على مستوى الخدمة ومفتاحها يتضمن الـIP والبريد معًا بسقف 5، وسقف IP وحده 100 — فعّال ضد التخمين الموجّه لحساب واحد، وأرخى بكثير ضد رشّ كلمات مرور على حسابات كثيرة من IP واحد.

## D. هوية fixture المرشحة وسبب اختيارها

قراءة مقيدة على RM02 أظهرت أربع هويات موظفين اصطناعية فقط، جميعها ببريد `@proof.invalid` (نطاق محجوز لا يُحَلّ):

| البريد | tenant | host | user.status | membership.status |
|---|---|---|---|---|
| `rm02-admin-a@proof.invalid` | rm02-a | rm02-a.acceptance.localhost | ACTIVE | **ACTIVE** |
| `rm02-reader-a@proof.invalid` | rm02-a | rm02-a.acceptance.localhost | ACTIVE | ACTIVE |
| `rm02-suspended-a@proof.invalid` | rm02-a | rm02-a.acceptance.localhost | ACTIVE | SUSPENDED |
| `rm02-admin-b@proof.invalid` | rm02-b | rm02-b.acceptance.localhost | ACTIVE | ACTIVE |

**المختار: `rm02-admin-a@proof.invalid` وحده** — عضوية ACTIVE، ودور admin بنطاق ALL_TENANT يسمح بإثبات `me` و `company/context` و `company/leads` بعد الدخول، وينتمي إلى Host A فيمكن إثبات عزل A/B مقابل Host B. ومستخدم B يبقى بلا اعتماد صالح، وهو ما يجعل اختبار «جلسة A على Host B» نظيفًا.

إثبات أن الهدف داخل RM02 وأنه الوحيد: التحديث سيُنفَّذ باتصال مُعرَّف بـ OID 21227 و system identifier `7699972247235194919`، وبـ predicate يطابق `tenant_id` + `id` + القيمة السابقة للـhash المقروءة محليًا؛ مع فحص `rowCount() === 1` قبل الـCOMMIT.

## E. هل التحديث ضروري فعلًا؟ (مبدأ أقل تغيير)

نعم، وهذا مُثبت لا مفترض:
- القيد `tenant_staff_password_argon2id_check` على `tenant_staff_users` هو `CHECK (password_hash ~~ '$argon2id$%')`، لذا **لا يمكن** أن تكون الـfixtures قد خزّنت نصًّا عاديًا. القيم الحالية فعلًا تبدأ بـ `$argon2id$`.
- لكن القيم الأربع **متطابقة** (بصمة md5 مختصرة واحدة) وطولها 49 بايتًا فقط، في حين أن بصمة Argon2id حقيقية بإعدادات `m=65536,t=4,p=1` تقارب 96 بايتًا.
- فحص محلي بـPHP على القيمة الحية (دون طباعتها): `password_get_info()` يعيد `algoName = argon2id`، و `password_verify()` يعيد **false** لكل المدخلات المجرّبة، و `password_needs_rehash(..., PASSWORD_ARGON2ID)` يعيد **1**.

النتيجة: القيمة الحالية placeholder صالح نحويًا وغير وظيفي؛ تمرّ على `str_starts_with` ثم تفشل في `Hash::check` حتمًا. ⇒ **لا يوجد اعتماد صالح قائم يمكن استخدامه**، ولا يمكن إثبات login حقيقي بدون كتابة واحدة. ولن يُنشأ مستخدم أو tenant أو عضوية جديدة.

**حفظ التغطية الأمنية القائمة:** بحث في `tests/Feature/Tenancy` و `tests/Feature/Identity` أظهر أن كل الاختبارات التي تذكر `password_hash` تتحقق من **الصلاحيات** (`has_column_privilege`, `objectDenied`) أو من عدم تسريب الاسم في الاستجابات — ولا اختبار واحد يعتمد على أن بصمة الـfixture غير قابلة للتحقق. وفوق ذلك تبقى ثلاث هويات (reader-a، suspended-a، admin-b) على القيمة غير الوظيفية، فتغطية «اعتماد غير صالح» محفوظة بالكامل.

## F. أمان كلمة مرور التجربة

- تُولَّد بـ `random_bytes(32)` بترميز base64url داخل العملية.
- تُحفَظ في ملف واحد خارج Git تحت `tools/dev-db/acceptance/.private/` (والمجلد محمي بـ `.gitignore` محلي وخارج المستودعات الأربعة أصلًا)، مع تضييق ACL على المستخدم الحالي بـ `icacls`.
- تُمرَّر إلى العملية الفرعية عبر **متغير بيئة للعملية الفرعية فقط**، لا عبر `argv` ولا عبر URL ولا في سجل الأوامر.
- البصمة تُحسَب بـ `Hash::make()` من بيئة Laravel الحية ليطابق الناتج سائق argon2id المعتمد، ثم يُتحقَّق منها بـ `Hash::check` قبل الـCOMMIT.
- لا تُطبع القيمة ولا البصمة ولا أي Cookie/Session ID/CSRF token في stdout أو JUnit أو هذا التقرير.

## G. التحديث الواحد المسموح

- الاتصال: RM02 فقط، مبدأ fixture-admin، بعد `preflight` جديد وتحقق OID + system identifier.
- SQL واحدة داخل معاملة ذرية:
  `UPDATE tenant_staff_users SET password_hash = :new, updated_at = now() WHERE tenant_id = :tenant AND id = :user AND canonical_email = :email AND password_hash = :old_value_read_locally`
- التوقع: `rowCount() === 1` بالضبط. أي قيمة أخرى ⇒ ROLLBACK و STOP.
- بعد التحديث وقبل الـCOMMIT: إعادة قراءة البصمة والتحقق بـ `Hash::check(password, hash)` = true، وتحقق أن عدد الصفوف المتأثرة في الجدول = 1 وأن `canonical_email`/`status`/`auth_version` لم تتغير.
- لا تُحدَّث `auth_version` (تغييرها يُبطل الجلسات ويغيّر العقد)، ولا أي عمود آخر عدا `password_hash` و `updated_at`.

## H. سياسة البصمة (Fingerprint policy)

- الحقل **الوحيد** المسموح اختلافه بين قبل/بعد هو `password_hash` (و `updated_at` التابع له) لصف واحد.
- كل العدّادات تبقى متطابقة: `fixture_tenants=2`، `all_tenants=2`، `hostnames=2`، `registry_domains=1`، `staff_users=4`، `staff_memberships=4`، `roles=3`، `admin_role_permissions=14`، `template_permissions=7`، `staff_role_assignments=4`، `staff_direct_grants=2`، `provider_users=1`، `provider_operations=2`، `global_users=0`، `legacy_memberships=0`، **`leads=0`**، `security_audit_events=0`، **`staff_security_events=0`**.
- سيُضاف إلى `rm02-tool.php` **توقّع صريح واحد** باسم `auth_fixture_credential_configured` يرصد حالة هذا الصف بالذات (هل بصمته هي placeholder المشترك أم اعتماد مهيّأ)، مع إبقاء بقية الـfingerprint وفحوص الهوية وعدّادات الصفوف صارمة كما هي. **لن** يُستثنى `password_hash` من المقارنة عالميًا، ولن يُعطَّل فاحص الانحراف.

## I. خطة HTTP wire

- خادم مؤقت على `127.0.0.1` ومنفذ loopback غير مستخدم (يُتحقق من شغله قبل الربط)، عبر router الإطار الرسمي `vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php` ومجلد `public/`. لا ربط على `0.0.0.0`، ولا حاوية جديدة، ولا منفذ المضيف 5432، ولا تثبيت أي حزمة.
- بيئة العملية: اتصالات RM02 السبعة فقط (مُشتقة من `rm02Env`)، `APP_ENV=local` (لتفعيل CSRF الحقيقي وهي بيئة يسمح بها `ResolveTenantHost` أصلًا)، `APP_DEBUG=false`، `TENANT_STAFF_AUTH_ENABLED=true`، `SESSION_DRIVER=file` و `CACHE_STORE=file` بمسارات معزولة داخل `.private`، `QUEUE_CONNECTION=sync`، `MAIL_MAILER=log`، `SESSION_SECURE_COOKIE=false` (مدعوم أصلًا في `config/session.php` لبيئة local)، بلا أي تكامل خارجي.
- **لا تعديل** على `config/session.php` أو `config/cors.php` أو `config/sanctum.php` أو الـroutes أو الـcontrollers.
- العميل: عملية PHP مستقلة تستخدم cURL مع cookie jar على القرص (داخل `.private`)، وOrigin مسموح من `cors.allowed_origins`، و `CURLOPT_RESOLVE` لتحويل `rm02-a.acceptance.localhost` و `rm02-b.acceptance.localhost` إلى `127.0.0.1` محليًا — **بلا أي استعلام DNS خارجي وبلا أي اتصال خارج 127.0.0.1**.
- التغطية: csrf-cookie ⇒ login ناجح ⇒ `me` في طلب لاحق مستقل ⇒ تدوير معرّف الجلسة (ببصمات مقارنة لا تكشف القيمة) ⇒ logout ⇒ إعادة استخدام نفس الـcookie ⇒ رفض؛ وسلبيات: كلمة مرور خاطئة، CSRF ناقص، CSRF مزوّر، Origin غير مسموح، Origin غائب، Host B بجلسة A، `X-Forwarded-Host` مزوّر، selector مثل `X-Tenant-ID`، وثبات عدم تسريب SQLSTATE/stack/hash.
- لا `actingAs` ولا `withSession` ولا `Session::put` ولا mock guard ولا تعطيل middleware.

## J. خطة إثبات الـCOMMIT

- **AUTH session persist**: يُثبت باستمرار الجلسة بين طلبات HTTP مستقلة. هذا دليل على الجلسة لا على commit بيانات الأعمال.
- **إثبات أن مسار الطلب يعمل COMMIT فعليًا على مستوى أعلى**: يُقاس عبر عدّاد `pg_stat_database.xact_commit` لقاعدة RM02 قبل/بعد سلسلة الطلبات، من اتصال منفصل. هذا دليل تجميعي لا يكتب أي صف.
- **BUSINESS commit**: كل عملية كتابة أعمال متاحة للـruntime (`POST /company/leads`، `POST /company/roles`، منح/سحب صلاحية) تُنتج — بحكم العقد — صفًا دائمًا في `leads` أو `roles`، **و** صفًا في `tenant_staff_security_events` وهو جدول append-only محمي بـ `tenant_staff_security_event_no_update` ولا يملك الـruntime عليه حق DELETE. ولا يملك الـruntime حق DELETE على `leads` أيضًا (الأرشفة ناعمة). ⇒ **لا توجد عملية أعمال شرعية قابلة للتراجع** دون كسر `leads=0` و `staff_security_events=0`، ودون حذف سجل تدقيق append-only وهو محظور. القرار المسبق: **`BUSINESS_COMMIT_NOT_PROVEN`** مع ذكر السبب، ولن تُنفَّذ كتابة أعمال؛ أي إثبات لها يحتاج تفويض مالك منفصل أو قاعدة disposable جديدة.

## K. شروط STOP، والملفات المنوي تعديلها والمحظورة

**STOP فوري إذا:** اختلفت هوية RM02 أو OID أو system identifier أو القفل؛ أو ظهرت جلسة متزامنة؛ أو كان `rowCount() !== 1`؛ أو لزم تعديل schema/ACL/policy/trigger/ownership أو migration 001–038؛ أو لزم تعديل route/controller/config للمنتج لإنجاح اختبار؛ أو لزم إضعاف CSRF أو `APP_ENV=testing` في اختبار يُدّعى أنه يثبت CSRF؛ أو ظهر أثر DB إضافي غير مصرح به؛ أو لزمت كتابة على DEV/Old TEST/scratch؛ أو لزم اتصال خارجي أو تثبيت حزمة؛ أو غاب ملف الاعتماد بعد تغيير البصمة.

**منوي تعديله:** `tools/dev-db/acceptance/rm02-tool.php` (أوامر جديدة + توقّع البصمة الواحد)، ملفات عميل/خادم wire جديدة داخل `tools/dev-db/acceptance/`، اختبارات جديدة في `daleel-crm-api/tests/Feature/Identity|Tenancy/`، و `docs/audits/DEV-FOUNDATION-01.md` و `docs/STATUS.md` و `docs/PLAN.md` و `docs/HANDOFF.md` و `tools/dev-db/acceptance/README.md` و `TARGET_MANIFEST.md`.

**محظور تعديله:** migrations 001–038، `config/*` للمنتج، `routes/api.php`، `bootstrap/app.php`، أي controller/middleware/service في مسار المصادقة، `docs/DECISIONS.md` (لا قرار معماري جديد من المالك)، `rm02-fixtures.sql` (لا تُحدَّث قيمة الـplaceholder فيه كي لا يُخزَّن اعتماد في ملف متتبَّع)، وأي شيء في المستودعات الأمامية الثلاثة.

**خط الأساس قبل التجربة:** `verify` أظهر 38 migration، 36 جدول، 18 FORCE RLS، 94 policy، 15 trigger، `TENANT_RUNTIME_ACL matches migrations 026+037+038 exactly`، و `structure_parity_with_dev=true`، وبصمة fixtures كاملة كما في القسم H.

---

# REMEDIATION-05 / EVIDENCE LEDGER & FINAL REPORT (A–Z)

## سجل الأدلة

| المعرّف | الحالة | الدليل |
|---|---|---|
| DF01-RM05-001 | FACT | هوية الحاوية والـvolume والـproject والـIP ومنافذ loopback فقط، من `preflight`؛ `PROTECTED SCRATCH VERIFIED UNCHANGED`. |
| DF01-RM05-002 | FACT | `cluster system_identifier=7699972247235194919`، RM02 `oid=21227` owner `daleel_b10b_owner`، `OTHER_CLIENT_SESSIONS=0`. |
| DF01-RM05-003 | FACT | `verify`: 38 migration، 36 جدول، 18 FORCE RLS، 94 policy، 15 trigger، `TENANT_RUNTIME_ACL matches migrations 026+037+038 exactly`، `structure_parity_with_dev=true`. |
| DF01-RM05-004 | FACT | DEV: 36 migration، 0 tenant، 0 staff، ولا منح INSERT لـ`daleel_tenant_runtime`. Old TEST: 36 migration، 18 tenant، 39 صفًا في `users`، 1 security audit event. قبل وبعد الجولة، متطابقة. |
| DF01-RM05-005 | FACT | Git قبل وبعد: API HEAD `d6870839…` بلا تغيير، 5 ملفات معدّلة و5 مسارات غير متتبعة (نفس RM04 حرفيًا)، **لا شيء staged**، والواجهات الثلاث نظيفة على نفس الـHEADs. |
| DF01-RM05-006 | FACT | مجموعة `api` الحيّة = `EnsureFrontendRequestsAreStateful` + `SubstituteBindings` (reflection على الـKernel الحي). |
| DF01-RM05-007 | FACT | `PreventRequestForgery::handle()` يتجاوز التحقق عند `runningInConsole() && runningUnitTests()` ⇒ CSRF لا يمكن إثباته داخل PHPUnit، وهذا سبب الجولة. |
| DF01-RM05-008 | FACT | `lookup_tenant_staff_credentials` دالة `SECURITY DEFINER` بـ`search_path=pg_catalog,pg_temp`، وACL تنفيذها محصور في `daleel_tenant_auth_lookup` و`daleel_tenant_auth_client` فقط. |
| DF01-RM05-009 | FACT | `AuthSecurityEvents::emit` يكتب إلى قناة `structured` وهي `php://stderr`؛ لا كتابة DB في مسار login. |
| DF01-RM05-010 | FACT | البصمة السابقة للـfixtures: `password_get_info` ⇒ `argon2id`، لكن الطول 49 بايتًا و`password_verify` = false لكل مدخل و`password_needs_rehash` = 1 ⇒ placeholder غير وظيفي، والقيم الأربع متطابقة. |
| DF01-RM05-011 | FACT | PRE-WRITE محفوظ على القرص قبل أي تعديل: **2026-10-24 10:36:48 +03:00 (Africa/Cairo)**، SHA-256 للملف بعد الحفظ `d762b29599e38f0ee572bfe05f21faeeb6f1f4f49fc24713d241f83ac5a7a605`. |
| DF01-RM05-012 | FACT | `auth-fixture`: `CANDIDATE email=rm02-admin-a@proof.invalid user_status=ACTIVE membership_status=ACTIVE auth_version=1 shared_placeholder=true`. |
| DF01-RM05-013 | FACT | `HASH_DERIVED algo=argon2id len=97 memory_cost=65536 time_cost=4 threads=1 needs_rehash=0` من هاشر المنتج نفسه. |
| DF01-RM05-014 | FACT | `COMMITTED one authorised UPDATE … table=tenant_staff_users column=password_hash rows=1; CHECK=1 algo=argon2id` — صف واحد، بعد تحقق `rowCount()===1` وثبات `canonical_email`/`status`/`auth_version` داخل المعاملة. |
| DF01-RM05-015 | FACT | البصمة بعد التهيئة: كل العدّادات متطابقة، و`auth_fixture_credential_configured` 0⇒1 و`shared_placeholder_rows` 4⇒3؛ `PASS FINGERPRINT_AFTER_MATCHES_ONE_ALLOWED_FIELD`. |
| DF01-RM05-016 | FACT | إعادة تشغيل `auth-fixture` ⇒ `NO-OP … no row was written` + `PASS NO_FIXTURE_DRIFT`، exit 0. وسكربت الـfixtures نفسه يعيد `RM02_FIXTURES_ALREADY_PRESENT; RETURN` فلا يلمس البصمة الجديدة. |
| DF01-RM05-017 | FACT | `WORKER_IDENTITY_VERIFIED` — كل اتصالات بيئة الخادم تشير إلى `daleel_crm_rm02_isolated` على `127.0.0.1:55437` بأدوار غير مالكة وغير superuser؛ والأداة ترفض التشغيل إذا ظهر `postgres` أو `daleel_b10b_owner` أو المنفذ الداخلي 5432. |
| DF01-RM05-018 | FACT | `SERVER started … bind=127.0.0.1:54901 docroot=public env=local session=file cache=file storage=.private/rm05-storage` ثم `SERVER stopped` للـPID الذي أنشأته الأداة وحده. |
| DF01-RM05-019 | FACT | نتيجة الـwire: **51/51 PASS، 0 FAIL**، في ثلاث تشغيلات متتالية. |
| DF01-RM05-020 | FACT | `COMMIT_COUNTER rm02 xact_commit delta=377` في كل تشغيلة — إثبات تجميعي أن معاملات الطلبات بلغت COMMIT على أعلى مستوى. |
| DF01-RM05-021 | FACT | stderr الخادم سجّل 6 × `TenantStaffLoginSucceeded` و7 × `TenantStaffLoginFailed` — أحداث مصادقة حقيقية من الخدمة نفسها. |
| DF01-RM05-022 | FACT | مسح تسريب: كلمة مرور القبول غير موجودة في أي ملف تقرير أو سجل داخل `.private/reports` (بحث حرفي، صفر مطابقات)، وكل استجابة فُحصت ضد 10 أنماط تسريب (SQLSTATE، `password_hash`، `permission denied`، `row-level security`، `pg_`، vendor paths، stack traces، `argon2id`). |
| DF01-RM05-023 | FACT | Regression: `probe` **79/79** مرتين، `test all` **29/29 و765 assertion** و0 errors/0 failures/0 skipped مرتين (21.12s و17.06s)، `guard-selftest` 5/5 PASS، وبصمة fixtures ثابتة بعد كل تشغيلة. |
| DF01-RM05-024 | FACT | فرق البصمات بين قبل/بعد الجولة: ملفان تغيّرا فقط (`docs/audits/DEV-FOUNDATION-01.md`، `tools/dev-db/acceptance/rm02-tool.php`) وملفان جديدان خارج Git (`rm05-hash.php`، `rm05-wire.php`). كل الـ38 migration وكل `config/*` و`routes/api.php` و`bootstrap/app.php` وكل ملفات الاختبار و`DECISIONS.md` و`openapi.yaml` و`RLS_ARCHITECTURE.md` و`rm02-fixtures.sql` **متطابقة بايت ببايت**. |
| DF01-RM05-025 | FACT (finding F14) | `ApiErrorResponse::fromException` يبني `response()->json()` ولا ينسخ `HttpExceptionInterface::getHeaders()` ⇒ ترويسة `Retry-After` التي يضبطها `AuthRateLimitedException` تُفقَد؛ رُصد حيًّا: 429 بلا `Retry-After`. |
| DF01-RM05-026 | FACT (finding F15) | إعادة تقديم cookie جلسة Host A إلى Host B لا تُرفَض فقط، بل تُفرِّغ أيضًا سياق الجلسة المقدَّمة نفسها، فتصبح عديمة الفائدة على مضيفها الأصلي (`S8e`). سلوك fail-closed مفيد، لكنه يعني أن أي طلب مرفوض على مسار tenant-staff يُسقط الجلسة — وهو ما يجب على اختبارات لاحقة أن تحسبه. |
| DF01-RM05-027 | INFERENCE | عدم تطابق `SANCTUM_STATEFUL_DOMAINS`/`CORS_ALLOWED_ORIGINS` (`localhost:300x`) مع مضيف الـAPI (`{slug}.{BASE_DOMAIN}`) يجعل طلب المتصفح الحقيقي cross-site، و`SameSite=lax` يمنع إرسال cookie الجلسة مع POST cross-site. مستنتج من مواصفات Cookies وقيم الإعداد المرصودة، **غير مُختبَر بمتصفح**. |
| DF01-RM05-028 | NOT_PROVEN | `BUSINESS_COMMIT_NOT_PROVEN`: لا توجد عملية أعمال شرعية قابلة للتراجع (`leads` بلا DELETE للـruntime، و`tenant_staff_security_events` append-only بـtrigger ولا DELETE)، فأي إثبات يكسر `leads=0`/`staff_security_events=0` نهائيًا. لم تُنفَّذ أي كتابة أعمال. |

---

## A. EXECUTIVE SUMMARY والقرار

**القرار: PASS_SCOPED. وCustomers: NO-GO.**

أُثبتت لأول مرة رحلة مصادقة حقيقية من طرف إلى طرف على سلك HTTP فعلي خارج PHPUnit: طلب `GET /sanctum/csrf-cookie`، ثم `POST /api/v1/auth/login` بكلمة مرور Argon2id صحيحة، ثم جلسة محفوظة في عميل مستقل بذاكرة cookie خاصة، ثم `GET /api/v1/auth/me` و`/company/context` و`/company/leads` و`/company/authorization` في طلبات منفصلة، ثم `POST /api/v1/auth/logout` وإبطال يمنع إعادة التشغيل. 51 تأكيدًا على السلك، ثلاث مرات، بلا فشل واحد.

والأهم أن **CSRF أُثبت حقيقة هذه المرة**: مصدر Laravel 13 يتجاوز `PreventRequestForgery` كليًا عندما `runningInConsole() && runningUnitTests()`، ولهذا لم تستطع RM04 إثباته؛ على خادم `APP_ENV=local` نفّذ الـmiddleware فعلًا، فرُفض طلب بلا رمز وطلب برمز مزوّر بـ**419 `AUTH_CSRF_INVALID`**، ونجح الطلب بالرمز الصحيح.

ثمن ذلك كان **تغييرًا دائمًا واحدًا**: بصمة Argon2id صالحة لصف موظف اصطناعي واحد قائم في RM02 (`rows=1`)، بعد إثبات أن البصمة السابقة placeholder غير وظيفي (`password_verify` = false، الطول 49 بايتًا مقابل 97 للبصمة الحقيقية). كل عدّاد آخر في القاعدة ثابت، والـschema وACL وRLS والـpolicies والـtriggers بلا تغيير، وDEV وOld TEST وscratch بلا أي لمس.

الانحدار كامل بلا فقد تغطية: `probe` 79/79 مرتين، `test all` 29/29 و765 assertion بصفر أخطاء مرتين، `guard-selftest` 5/5.

وما لم يُثبت قيل كما هو: **commit بيانات الأعمال غير مُثبت** (لا توجد عملية أعمال قابلة للتراجع دون كسر `leads=0` أو حذف تدقيق append-only)، و**سلوك المتصفح الحقيقي غير مُختبَر**، و**F06 ما زال مفتوحًا**. وظهرت فجوتان جديدتان: **F14** (429 بلا `Retry-After`) و**F15** (طلب مرفوض يُسقط الجلسة المقدَّمة).

## B. OWNER AUTHORIZATION & DEVIATIONS

التفويض: «ابدأ» بعد مراجعة RM04، ويشمل السماح المشروط بتغيير دائم واحد مضبوط داخل RM02 لتهيئة بصمة Argon2id لموظف fixture قائم.

**انحرافات عن خطة التكليف: لا شيء جوهري.** ثلاثة اختيارات تنفيذية تستحق التسجيل:
1. التكليف اقترح تمرير السر عبر stdin «إن أمكن»؛ استُخدم متغير بيئة للعملية الفرعية وحدها (ليس argv ولا URL ولا سجل أوامر) لأنه الأبسط والأقل عرضة للتسريب في `proc_open` على Windows.
2. التكليف ذكر `.private` كموقع للسر؛ الموقع الفعلي `tools/dev-db/acceptance/.private` لأن هذا هو `.private` الوحيد في النسخة الحية (لا يوجد `.private` في جذر مساحة العمل).
3. **لم تُضَف أي اختبارات PHPUnit جديدة.** أُبقيت مجموعة RM04 كما هي بالضبط ليكون الانحدار مقارنة نظيفة 29/765 مقابل 29/765، ووُضع إثبات login الحقيقي في أداة الـwire خارج PHPUnit — لأن PHPUnit **لا يستطيع** إثبات CSRF بحكم DF01-RM05-007، فإضافة اختبار login إليه كانت ستوهم بتغطية لا يملكها.

لم يُنفَّذ: Customers، Deals/Pipeline، Tasks، Frontend، Production، إصلاح F06/F08/F10، تطبيق 037/038 على DEV، أي commit/push/deploy، أي تدوير لاعتمادات القبول القائمة.

## C. SOURCE CHECKPOINT / REPOS

| المستودع | HEAD قبل = بعد | الحالة |
|---|---|---|
| `daleel-crm-api` | `d6870839f38b1f05786288071dbe0bb7719d5386` (فرع `phase-0-stabilize-baseline`) | 5 ملفات معدّلة متتبعة + 5 مسارات غير متتبعة — **نفس RM04 حرفيًا**، لا إضافة ولا حذف، لا شيء staged |
| `daleel-crm` | `6fb01b8838de52de621dab4691a5cdd5710c29f6` | نظيف |
| `daleel-crm-admin` | `9fa43befadaaa5d4583f8de6bf7a06c60e891bef` | نظيف |
| `daleel-crm-super-admin` | `a802e44b8a269071bcb46fcaa675aafb43b12a87` | نظيف |

ملفات هذه الجولة الجديدة (`rm05-hash.php`، `rm05-wire.php`) تقع في `tools/` وهي **خارج المستودعات الأربعة بالكامل**، فلا تظهر في أي `git status` ولا تحتاج استثناءً.

## D. TARGET IDENTITY & SAFETY LOCKS

`daleel_crm_rm02_isolated`، OID **21227**، owner `daleel_b10b_owner`، `127.0.0.1:55437`، داخل الحاوية `daleel-pg-acceptance` (`d6ce6f4c1e92…`)، volume `daleel_acceptance_pg_data`، cluster `7699972247235194919`. الأقفال النشطة: `target-lock.json` + `rm02-lock.json` + `ACCEPTANCE_RM02_DB_OID` + `ACCEPTANCE_RM02_SYSTEM_ID`. منفذ المضيف 5432 لم يُستخدم إطلاقًا، والأداة ترفض الآن تشغيل خادم HTTP بأي اتصال على المنفذ الداخلي 5432 أو خارج RM02. `guard-selftest` يثبت رفض الاتصال بـDEV وOld TEST وscratch ورفض OID مغشوش قبل أي أثر.

## E. PRE-WRITE EVIDENCE

محفوظ على القرص **قبل** أول تعديل كود وقبل أي كتابة DB: `daleel-crm-api/docs/audits/DEV-FOUNDATION-01.md`، قسم `REMEDIATION-05 / PRE-WRITE AUTH CONTRACT & SESSION SAFETY REVIEW`، الأقسام A–K. توقيت الحفظ **2026-10-24 10:36:48 +03:00 Africa/Cairo**، وSHA-256 للملف عند تلك اللحظة `d762b295…a605`. لم يُسجَّل تشخيص متأخر بتوقيت مزور: التسلسل في هذا الملف هو PRE-WRITE أولًا ثم هذا التقرير.

## F. AUTH CONTRACT MATRIX

المصفوفة الكاملة في قسم C من PRE-WRITE أعلاه. الخلاصة التنفيذية:

| المسار | Middleware الفعلي | مبدأ DB |
|---|---|---|
| `GET /sanctum/csrf-cookie` | مجموعة `web` (StartSession + PreventRequestForgery) | لا شيء |
| `POST /api/v1/auth/login` | `api`(Sanctum stateful ⇒ CSRF) ، ResolveTenantHost، RequireAllowedSpaOrigin، TenantStaffRequestContext | `pgsql_tenant_auth` (`dl_tauth`) للبحث عن الاعتماد عبر دالة SECURITY DEFINER، ثم `pgsql_tenant_runtime` (`daleel_b10b_tenant_runtime`) لإعادة التحقق |
| `GET /api/v1/auth/me` ، `POST /logout` | ما سبق + `auth:tenant_staff` + ValidateTenantStaffSession | `pgsql_tenant_runtime` |
| `GET /api/v1/company/*` | ما سبق + RejectCompanyContextSelectors | `pgsql_tenant_runtime` |

رموز العقد المرصودة حيًّا: 200 نجاح، **401 `AUTH_INVALID_CREDENTIALS`**، **401 `AUTH_UNAUTHENTICATED`**، **419 `AUTH_CSRF_INVALID`**، **403 `PERMISSION_DENIED`** (Origin)، **400 `TENANT_SELECTOR_NOT_ALLOWED`**، **404 `RESOURCE_NOT_FOUND`** (مضيف غير معرَّف)، **429 `AUTH_RATE_LIMITED`**.

## G. FIXTURE CREDENTIAL DECISION

- **الهوية:** `rm02-admin-a@proof.invalid` على `rm02-a.acceptance.localhost` — ACTIVE/ACTIVE، دور admin، وحدها.
- **الضرورة مُثبتة لا مفترضة:** القيد `CHECK (password_hash ~~ '$argon2id$%')` يمنع أصلًا تخزين نص عادي، والقيم الأربع كانت متطابقة بطول 49 بايتًا و`password_verify` = false و`needs_rehash` = 1 (DF01-RM05-010). لا اعتماد صالح قائم.
- **الأثر:** `UPDATE … SET password_hash, updated_at WHERE tenant_id AND id AND canonical_email AND password_hash = <القيمة السابقة>`، معاملة ذرية، `rowCount()=1`، تحقق أن `canonical_email`/`status`/`auth_version` لم تتغير، تحقق `Hash::check` بهاشر المنتج، ثم COMMIT. `auth_version` لم تُلمس.
- **لا plaintext ولا بصمة في أي ملف متتبَّع:** `rm02-fixtures.sql` بقي بايت ببايت كما هو. السر في `tools/dev-db/acceptance/.private/rm05-auth-fixture.json` بـACL مضيَّق بـ`icacls`، خارج Git.
- **Idempotency:** إعادة التشغيل تتحقق من الاعتماد ثم تعلن NO-OP بلا كتابة؛ وغياب ملف الاعتماد مع بصمة مُدوَّرة = STOP لا تدوير جديد.
- **التغطية الأمنية محفوظة:** لا اختبار يعتمد على بصمة غير قابلة للتحقق، وثلاث هويات (reader-a، suspended-a، admin-b) ما زالت تحمل الـplaceholder غير الوظيفي.

## H. DATABASE BEFORE / AFTER

كل العدّادات التالية **متطابقة** قبل الجولة وبعد كل تشغيلة (`auth-fixture`، `wire` ×3، `probe` ×2، `test all` ×2، `guard-selftest`):
`fixture_tenants=2`، `all_tenants=2`، `hostnames=2`، `registry_domains=1`، `staff_users=4`، `staff_memberships=4`، `roles=3`، `admin_role_permissions=14`، `viewer_role_permissions=0`، `template_permissions=7`، `staff_role_assignments=4`، `staff_direct_grants=2`، `provider_users=1`، `provider_operations=2`، `global_users=0`، `legacy_memberships=0`، **`leads=0`**، `security_audit_events=0`، **`staff_security_events=0`**.

التغير الوحيد: `auth_fixture_credential_configured` 0 ⇒ 1 و`shared_placeholder_rows` 4 ⇒ 3. هذان حقلان **مشتقّان بالمقارنة مع صف شقيق لم يُلمَس**، فلا تُقرأ ولا تُخزَّن أي قيمة بصمة في أي تقرير، ويبقى فاحص الانحراف مفعّلًا على الباقي كله: `password_hash` لم يُستثنَ عالميًا من المقارنة، بل صار مرصودًا بدقة أكبر مما كان.

Schema: 38 migration، 36 جدول، 18 FORCE RLS، 94 policy، 15 trigger، `structure_parity_with_dev=true`، وACL يطابق 026+037+038 بالضبط — كله كما في RM04.

أثر الجلسات المحلي: `.private/rm05-storage/framework/sessions` و`…/cache/data` (ملفات جلسات وعدّادات RateLimiter أنشأتها هذه الجولة)، وسجلات الخادم/العميل في `.private/reports/remediation-05-wire-*`. **لم تُلمس** `storage/framework/sessions` و`storage/framework/cache/data` في المستودع (38 و37 ملفًا قبل الجولة، كما هي) لأن `LARAVEL_STORAGE_PATH` حوّل التخزين بالكامل إلى مجلد معزول. لم يُحذف أي ملف سابق.

## I. HTTP WIRE HARNESS

خادم PHP مؤقت على `127.0.0.1:54901` فقط (لا `0.0.0.0`)، docroot `public/`، router الإطار الرسمي `vendor/laravel/framework/.../resources/server.php` — لا حزمة مثبّتة ولا حاوية جديدة ولا تغيير بنيوي. البيئة: `APP_ENV=local`، `APP_DEBUG=false`، `TENANT_STAFF_AUTH_ENABLED=true`، `SESSION_DRIVER=file`، `CACHE_STORE=file`، `SESSION_SECURE_COOKIE=false`، `QUEUE_CONNECTION=sync`، `MAIL_MAILER=log`، `LARAVEL_STORAGE_PATH` معزول، واتصالات RM02 السبعة فقط. أُوقِف الخادم بالـPID الذي أنشأته الأداة وحده.

`APP_ENV=local` ليس إضعافًا: `ResolveTenantHost` يسمح أصلًا بـ`local` و`testing` فقط، و`config/session.php` يسمح أصلًا بـ`Secure=false` في `local`. **لم يُعدَّل أي ملف config أو route أو controller** (DF01-RM05-024).

العميل عملية OS منفصلة بـcURL، بذاكرة cookie خاصة تحترم نطاق المضيف والمسار، وتسمح بإجبار إعادة تقديم cookies مضيف آخر لاختبار السرقة. `CURLOPT_RESOLVE` يحوّل `rm02-a/b.acceptance.localhost` إلى `127.0.0.1` محليًا — لا استعلام DNS خارجي ولا اتصال خارج loopback. Origin `http://localhost:3001` من `config/cors.php`. **لا `actingAs` ولا `withSession` ولا `Session::put` ولا guard مزيّف ولا middleware معطَّل.**

## J. REAL LOGIN

| # | السيناريو | النتيجة |
|---|---|---|
| S6a | `POST /api/v1/auth/login` ببيانات صحيحة على السلك | **200** |
| S6b | الاستجابة تعيد هوية الموظف الصحيحة | البريد مطابق |
| S6c | الاستجابة تحمل `request_id` | نعم |
| S4a | كلمة مرور خاطئة | **401 `AUTH_INVALID_CREDENTIALS`** |
| S4b | فشل الدخول لا يمنح جلسة | `me` ⇒ 401 |
| S5 | بريد غير موجود يجيب **حرفيًا** كالخطأ في كلمة المرور | 401/`AUTH_INVALID_CREDENTIALS` في الحالتين ⇒ لا إحصاء حسابات |
| S10a | دخول جديد بعد logout | 200 (الاعتماد مستقر) |
| S12 | الهوية لم تُقفَل جانبيًا بسبب تجربة الـthrottle | 200 |

الهوية التي فحصت الاعتماد هي `pgsql_tenant_auth` عبر دالة SECURITY DEFINER، وإعادة التحقق في كل طلب عبر `pgsql_tenant_runtime` — وكلاهما غير مالك وغير superuser وNOBYPASSRLS، وقد رفضت الأداة تشغيل الخادم بأي اعتماد مالك أو superuser (DF01-RM05-017).

## K. SANCTUM / CSRF

`GET /sanctum/csrf-cookie` ⇒ **204** ويصدر `XSRF-TOKEN` + cookie الجلسة.

| # | الحالة | النتيجة |
|---|---|---|
| S2a | `POST` login بلا `X-XSRF-TOKEN` | **419 `AUTH_CSRF_INVALID`** |
| S2b | `POST` login برمز مزوّر | **419 `AUTH_CSRF_INVALID`** |
| S6a | `POST` login برمز صحيح | 200 |
| S9a | `POST` logout برمز صحيح وجلسة صالحة | 200 |

**إثبات أن الـmiddleware نُفِّذ فعلًا ولم يُتجاوَز:** `APP_ENV=local` و`runningInConsole()=false` على خادم HTTP، والمسار الذي يتجاوز التحقق (`runningUnitTests()`) غير قابل للتحقق هنا بحكم تعريفه؛ والدليل السلوكي أن نفس الطلب بالضبط يُرفَض بـ419 بلا رمز ويَنجح بـ200 مع الرمز. التصنيف: **VERIFIED_WIRE**. وتبقى نتائج RM04 الـ11 مصنّفة **VERIFIED_KERNEL** ولا تُنسب إليها أي تغطية CSRF.

## L. SESSION

| # | الحالة | النتيجة |
|---|---|---|
| S6d | تدوير معرّف الجلسة عند الدخول (حماية التثبيت) | بصمتان مختلفتان قبل/بعد |
| S7a | طلب لاحق مستقل مصادَق بنفس الجلسة | 200 |
| S7b | سياق RLS يُعاد بناؤه في كل طلب | 200 |
| S9b | تغيّر معرّف الجلسة عند logout | بصمتان مختلفتان |
| S9c | العميل بعد logout غير مصادَق | 401 |
| S9d | إعادة تشغيل cookie ما قبل logout | **401** |
| S10b | الجلسة الجديدة تختلف عن المتقاعدة | نعم |

المقارنات كلها ببصمات `sha256` مملَّحة بملح عشوائي لكل تشغيلة، فلا تُكشف أي قيمة جلسة. انتهاء العمر المطلق (`identity.absolute_session_lifetime` = 28800s) و`authorization_version` موجودان في المصدر ومغطّيان في مجموعة RM04 (`test_session_integrity_versions_and_membership_state_are_revalidated`، 18 assertion)؛ لم تُزوَّر حالة انتهاء على السلك لأن ذلك يحتاج تعديل بيانات fixtures دائمة.

## M. HOST / A-B / ORIGIN / PROXY

| # | الحالة | النتيجة |
|---|---|---|
| S8a | cookies مضيف A مُعاد تقديمها إلى مضيف B | **401 `AUTH_UNAUTHENTICATED`** |
| S8e | ونفس الـcookie يصبح عديم الفائدة على مضيفه الأصلي | 401 (fail-closed، finding F15) |
| S8b | `X-Forwarded-Host: rm02-b…` على طلب إلى A | **200 كـA** ⇒ مُهمَل، لا proxy موثوق |
| S8c | `X-Tenant-ID` على `/company/context` | **400 `TENANT_SELECTOR_NOT_ALLOWED`** قبل أي قراءة tenant |
| S8d | مضيف غير معرَّف `rm02-zzz.acceptance.localhost` | **404 `RESOURCE_NOT_FOUND`** |
| S3a | Origin غير مسموح | **403 `PERMISSION_DENIED`** |
| S3b | Origin غائب | **403 `PERMISSION_DENIED`** |

## N. COOKIE POLICY

مرصود حيًّا من ترويسات `Set-Cookie` الفعلية:

| Cookie | HttpOnly | Domain | SameSite | Secure | Path |
|---|---|---|---|---|---|
| cookie الجلسة | **نعم** | غائب (host-only) | lax | لا (loopback http) | `/` |
| `XSRF-TOKEN` | لا (بالعقد، لتقرأه SPA) | غائب (host-only) | lax | لا (loopback http) | `/` |

CORS: `Access-Control-Allow-Origin: http://localhost:3001` مع `Access-Control-Allow-Credentials: true`.

`Secure=false` أثر بيئة `local` المدعومة أصلًا في `config/session.php`؛ في غير `local` يفرض نفس الملف `secure=true` بلا متغير بيئة يعطّله. **الفرق عن الإنتاج موثَّق ولم تُعدَّل أي ثابتة.**

**تحذير لا يجوز تمريره كنجاح:** عميل HTTP برمجي ليس متصفحًا. سياسات SameSite وCORS الحقيقية غير مُختبَرة، و(DF01-RM05-027) الاستنتاج المعماري أن `localhost:3001` مقابل `{slug}.acceptance.localhost` هو cross-site، فـ`SameSite=lax` سيمنع إرسال cookie الجلسة مع POST من متصفح حقيقي. **Browser E2E = NOT_EXECUTED**، والفجوة تحتاج قرار معماري لا تعديل اختبار.

## O. THROTTLING

موجود فعلًا لكن **ليس كـroute middleware**: لا `throttle:` على `api/v1/auth/*` إطلاقًا؛ الحماية في `TenantStaffRateLimiter` داخل `TenantStaffLoginService` بمفتاحين، `sha256(tenant_id|email|ip)` بسقف 5 و`sha256(ip)` بسقف 100، بتحلل 900 ثانية، والنجاح يمسح مفتاح الهوية.

مرصود حيًّا بعنوان بريد مُستهلَك مخصَّص (لئلا تُقفَل هوية القبول) وبست محاولات فقط:
`401, 401, 401, 401, 401, ` **`429 AUTH_RATE_LIMITED`** — أي أن القيد ينطبق بعد 5 حالات فشل بالضبط كما في العقد. وS12 أثبت أن هوية القبول لم تتأثر.

**F14 (جديد، P3):** الـ429 لا يحمل `Retry-After`. `AuthRateLimitedException` يضبطها، لكن `ApiErrorResponse::fromException` يبني استجابة جديدة ولا ينسخ ترويسات الاستثناء. لم يُعدَّل الكود في هذه الجولة (خارج النطاق المصرَّح به).

**فجوة أمنية مسجَّلة (P2، لم تُصلَح):** المفتاح يضم الـIP والبريد معًا بسقف 5، وسقف IP وحده 100 دون سقف لكل tenant. فعّال ضد تخمين حساب واحد، أرخى بكثير ضد رشّ كلمة مرور واحدة على حسابات كثيرة من IP واحد. لم تُضَف حماية إلى الكود بلا تفويض.

## P. SECURITY

- **الأسرار:** كلمة مرور القبول وُلِّدت بـ`random_bytes(32)`، وتُمرَّر عبر بيئة عملية فرعية فقط، ومحفوظة في `.private` بـACL مضيَّق وخارج Git. بحث حرفي عن القيمة في كل ملفات `.private/reports` ⇒ **صفر مطابقات** (DF01-RM05-022). لا bصمة ولا cookie ولا session id ولا رمز CSRF في أي مخرَج أو JUnit أو هذا التقرير.
- **Argon2id:** مُولَّدة بهاشر المنتج نفسه، `m=65536, t=4, p=1`، طول 97، `needs_rehash=0`، ومُتحقَّقة بـ`Hash::check` قبل الـCOMMIT.
- **هوية RLS:** الخادم لم يملك اعتماد مالك أو superuser لأي اتصال، وهذا مُؤكَّد برفض برمجي لا بالثقة.
- **نظافة السجلات:** كل استجابة فُحصت ضد 10 أنماط تسريب (SQLSTATE، `password_hash`، `permission denied`، `row-level security`، `pg_`، مسارات vendor، stack traces، `argon2id`) ⇒ كلها نظيفة، بما فيها استجابات الأخطاء.
- **F06 ما زال مفتوحًا ولم يُقترَب منه.** نجاح بوابة المضيف وعزل A/B عبر HTTP **لا يساوي** حل F06: F06 يفترض اتصال runtime مخترقًا يزوّر الـGUCs مباشرة، وهو مسار لا يمر بالـHTTP أصلًا. **لا يُعلَن مغلقًا.**
- الاعتمادات المحلية للقبول (التي ظهر أحدها في مخرجات بحث محلي في RM02) ما زالت تحتاج تقييم تدوير مستقل؛ **لم تُدوَّر** في هذه الجولة كما يفرض التكليف.

## Q. COMMIT

- **AUTH session persistence: PROVEN.** جلسة واحدة خدمت عدة طلبات HTTP مستقلة عبر عمليات منفصلة.
- **Top-level COMMIT لمسار الطلب: PROVEN تجميعيًا.** `pg_stat_database.xact_commit` لـRM02 ارتفع بـ**377** في كل تشغيلة wire، من اتصال مراقبة منفصل، بلا كتابة أي صف. وهذا يطابق المصدر: `TenantStaffRequestContext` يفتح معاملة حقيقية ويُنهيها بـ`commit()` عند النجاح و`rollBack()` عند الاستثناء — بخلاف RM04 حيث كانت كتابات الاختبار داخل معاملة خارجية مُلغاة.
- **BUSINESS top-level commit: `BUSINESS_COMMIT_NOT_PROVEN`.** السبب محدد لا عام: كل عملية أعمال متاحة للـruntime تُنتج صفًا دائمًا في `leads`/`roles` **و** صفًا في `tenant_staff_security_events`، وهو جدول append-only بـtrigger `tenant_staff_security_event_no_update` ولا يملك الـruntime عليه DELETE، ولا يملك DELETE على `leads` (الأرشفة ناعمة). فلا طريق لإثباته دون كسر `leads=0`/`staff_security_events=0` نهائيًا أو حذف تدقيق append-only — وكلاهما محظور. **لم تُجرَ أي كتابة أعمال**، ولم يُستخدم rollback خفي مع ادّعاء commit. الإثبات يحتاج تفويض مالك منفصل أو قاعدة disposable جديدة.

## R. TESTS TABLE

| المجموعة | العدد | نجاح | errors | failures | skips | assertions | exit | التشغيلات | المسار |
|---|---|---|---|---|---|---|---|---|---|
| HTTP wire (RM05، خارج PHPUnit) | 51 فحصًا | 51 | 0 | 0 | 0 | 51 | 0 | **3** | `.private/reports/remediation-05-wire-*.client.stdout.log` |
| `test all` (PHPUnit، RM04 regression) | 29 | 29 | 0 | 0 | 0 | **765** | 0 | **2** (21.12s، 17.06s) | `.private/reports/remediation-04-all-20261024T07{4634,4759}Z.junit.xml` |
| raw `probe` | 79 فحصًا | **79** | — | 0 | 0 | — | 0 | **2** | stdout الأداة |
| `guard-selftest` | 5 | 5 | 0 | 0 | 0 | — | 0 | 1 | stdout الأداة |
| `auth-fixture` | — | PASS + NO-OP عند الإعادة | — | — | — | — | 0 | 2 | stdout الأداة |

## S. REGRESSION DELTA vs RM04

| المقياس | RM04 | RM05 | الفرق |
|---|---|---|---|
| `test all` | 29/29، 765 assertion | 29/29، **765 assertion** | **صفر** |
| raw `probe` | 79/79 | **79/79** | **صفر** |
| `guard-selftest` | PASS | PASS | صفر |
| fixture drift | صفر | صفر (باستثناء الحقل الواحد المصرَّح به والموثَّق) | كما هو مخطَّط |
| migrations | 38 | 38 | صفر |
| schema/ACL/RLS/policies/triggers | 36/18/94/15 | 36/18/94/15 | صفر |
| تغطية جديدة | — | +51 فحصًا على السلك | إضافة صافية |

لا تغطية ضائعة: لم يُحذَف ولا يُعدَّل أي اختبار قائم (DF01-RM05-024 يثبت تطابق كل ملفات الاختبار بايت ببايت). وكل اختبارات RM04 أُعيد تشغيلها على نفس أدوار PostgreSQL غير المالكة.

## T. FINDINGS

| # | الحالة | الأولوية | الثقة | الخلاصة |
|---|---|---|---|---|
| **F06** | **OPEN** | P1 (عند اختراق اتصال DB) | عالية | تزوير GUC من اتصال runtime مخترق يتيح عبور حدود tenant على بعض الجداول. **لا مسار HTTP مثبت، ولم يُقترَب منه، ولا يُعلَن مغلقًا.** |
| **F08** | OPEN | P3 | عالية | تقوية trigger. خارج النطاق. |
| **F10** | OPEN | P3 | عالية | عضوية SUSPENDED تُقبَل كمُكلَّف بـlead. مُشخَّص، خارج النطاق. |
| **F12** | بالتصميم | — | عالية | سحب SELECT على `tenant_staff_membership_roles.id` يمنع `UPDATE … WHERE id`؛ المنتج يسحب بـ`(tenant_id, membership_id, role_id)`. |
| **F13** | قيد منهجي | — | عالية | طلب مرفوض يضبط `SessionGuard::$loggedOut` فيُلوِّث طلبات لاحقة في نفس دالة الاختبار. |
| **F14** | **جديد** | P3 | عالية (FACT) | 429 `AUTH_RATE_LIMITED` بلا `Retry-After`؛ `ApiErrorResponse::fromException` يُسقط ترويسات الاستثناء. عميل منظَّم لا يعرف موعد إعادة المحاولة. إصلاح مقترح: نسخ `getHeaders()` عند `HttpExceptionInterface`. |
| **F15** | **جديد** | P3 (سلوك fail-closed) | عالية (FACT) | إعادة تقديم cookie جلسة إلى مضيف آخر تُفرِّغ سياق الجلسة المقدَّمة نفسها. مفيد أمنيًا، لكنه يعني أن أي رفض على مسار tenant-staff يُسقط الجلسة — وهو ما كشفه ترتيب اختبارات هذه الجولة ويجب على أي اختبار لاحق أن يحسبه. |
| **SECURITY_GAP-01** | مسجَّل | P2 | متوسطة (INFERENCE) | لا سقف throttling لكل tenant؛ سقف IP وحده 100 يسمح برشّ كلمة مرور على حسابات كثيرة من IP واحد. |
| **SECURITY_GAP-02** | مسجَّل | P2 | متوسطة (INFERENCE، DF01-RM05-027) | عدم توافق SameSite/cross-site بين origin الـSPA ومضيف الـAPI يجعل رحلة المتصفح الحقيقية مشكوكة. قرار معماري مطلوب. |

لم يُعدَّل أي كود منتج لمعالجة أي من هذه؛ كلها مفتوحة بأدلتها.

## U. SOURCE / TEST / TOOL / DB DIFF

**معدَّل (خارج Git):** `tools/dev-db/acceptance/rm02-tool.php` — ثلاث إضافات: حقلان مشتقّان في `fingerprint()` وتحققهما الصارم في `assertFingerprint()`؛ مبدأ `tenant-runtime` في `rm02Env()`؛ أمران جديدان `auth-fixture` و`wire` بحُرّاس هوية الخادم.

**جديد (خارج Git):** `tools/dev-db/acceptance/rm05-hash.php` (اشتقاق/تحقق Argon2id بهاشر المنتج)، `tools/dev-db/acceptance/rm05-wire.php` (عميل السلك، 51 فحصًا).

**معدَّل (متتبَّع في API):** `docs/audits/DEV-FOUNDATION-01.md` فقط (PRE-WRITE + هذا التقرير)، وهو ضمن `docs/audits/` غير المتتبَّع أصلًا.

**غير معدَّل بالمرة (مُثبت بالبصمات، DF01-RM05-024):** كل الـ38 migration، كل `config/*`، `routes/api.php`، `bootstrap/app.php`، كل middleware/controller/service، كل ملفات الاختبار الخمسة، `docs/DECISIONS.md`، `docs/ARCHITECTURE.md`، `AGENTS.md` (الجذر والAPI)، `docs/RLS_ARCHITECTURE.md`، `docs/openapi.yaml`، `rm02-fixtures.sql`، `verify-connections.php`، والواجهات الثلاث.

**DB:** عملية DML واحدة معتمدة — `UPDATE tenant_staff_users SET password_hash, updated_at` لصف واحد في RM02، `rows=1`. لا DDL، لا GRANT/REVOKE، لا migration، لا تغيير policy/trigger/ownership، ولا كتابة على DEV أو Old TEST أو scratch.

## V. DOCUMENTATION DIFF & KNOWLEDGE PRESERVATION

- `daleel-crm-api/docs/audits/DEV-FOUNDATION-01.md`: أُضيف قسم PRE-WRITE ثم هذا الملحق. **RM01–RM04 محفوظة كما هي، لم يُمسَح ولم يُعَد كتابة أي تاريخ.**
- `docs/STATUS.md`، `docs/PLAN.md`، `docs/HANDOFF.md`، `tools/dev-db/acceptance/README.md`، `TARGET_MANIFEST.md`: checkpoint RM05 وحالة اعتماد الـfixture وشروط التشغيل.
- `docs/DECISIONS.md`: **لم يُعدَّل**. «ابدأ» تفويض تنفيذي لا قرار معماري ولا إذن نشر.
- **خطر فقدان المعرفة (قائم، يحتاج قرار مالك):** وثائق الجذر (`docs/*`) وكل `tools/dev-db/acceptance/` خارج أي مستودع Git، و`docs/audits/` وmigrations 037/038 واختبارات RM03/RM04 غير متتبَّعة داخل API. لم تُضَف إلى Git ولم تُحذف — لكن نسخة احتياطية مستقلة أو قرار تتبُّع صريح مطلوب. السر في `.private` يجب أن يبقى خارج Git دائمًا.

## W. GATES

| البوابة | النتيجة |
|---|---|
| G0 هوية/موارد/حالة/Git | **PASS** — تطابق كامل مع RM04، صفر انحراف |
| G1 مراجعة عقد المصادقة | **PASS** — مصفوفة حيّة من `route:list` وreflection والمصدر |
| G2 PRE-WRITE قبل أي تغيير | **PASS** — محفوظ 10:36:48 +03:00 ببصمة، قبل أول تعديل |
| G3 اعتماد اصطناعي واحد | **PASS** — صف واحد، `rows=1`، idempotent، صفر انحراف آخر |
| G4 HTTP wire حقيقي | **PASS** — 51/51 ×3 |
| G5 CSRF/Origins/Cookies/Throttling | **PASS** مع فجوتين مسجَّلتين (F14، SECURITY_GAP-01/02) |
| G6 Commit وسلبيات | **PARTIAL** — الجلسة وtop-level COMMIT مُثبتان؛ **BUSINESS_COMMIT_NOT_PROVEN** بسبب محدَّد |
| G7 Regression | **PASS** — 29/765 ×2، 79/79 ×2، guard 5/5، بلا فقد تغطية |
| G8 توثيق ومراجعة انتقال | **PASS** |

**القرار الكلي: PASS_SCOPED.**

- **Customers: NO-GO.** يحتاج قرار مالك مستقل في: قبول F06 المتبقي، وSECURITY_GAP-02 (توافق المتصفح)، و`BUSINESS_COMMIT_NOT_PROVEN`، وقرارات التخلّص من Old TEST والاحتفاظ بـfixtures RM02، وقرار تطبيق 037/038 على DEV.
- **Production: NO-GO قطعًا.** لم يُختبَر متصفح، ولا HTTPS/Secure cookies حقيقية، ولا `/super/*` عبر HTTP، ولا full suite، وF06 مفتوح، وSESSION/CACHE drivers الإنتاجية (redis) لم تُختبَر في هذه الرحلة.
- **المرحلة التالية (أي كانت): مشروطة** بمراجعة المالك لهذا التقرير.

## X. KNOWN LIMITS / NOT_EXECUTED

1. **Browser E2E: NOT_EXECUTED.** لا أداة متصفح محلية قابلة للتشغيل بلا تثبيت أو اتصال خارجي. سياسات SameSite/CORS الحقيقية غير مُثبتة؛ SECURITY_GAP-02 استنتاج لا قياس.
2. **BUSINESS_COMMIT_NOT_PROVEN** — السبب في القسم Q؛ يحتاج تفويضًا منفصلًا أو قاعدة disposable.
3. **`/super/*` عبر HTTP: NOT_EXECUTED** (خارج النطاق).
4. **Full suite وlegacy provider suites: NOT_EXECUTED** — فيها `RefreshDatabase`/`DatabaseMigrations` ومسارات حذف مدمِّرة محظورة على هذا الهدف.
5. **انتهاء الجلسة المطلق وتغيّر `authorization_version` على السلك: NOT_EXECUTED** — يحتاج تعديل بيانات fixtures دائمة؛ مغطّى في RM04 على مستوى Kernel.
6. **تطبيق 037/038 على DEV: NOT_EXECUTED** (قرار مالك).
7. **Secure cookies / HTTPS / production session+cache drivers (redis): NOT_EXECUTED** — الاختبار على loopback HTTP بـfile drivers.
8. **F06/F08/F10/F14/F15 وSECURITY_GAP-01/02: لم تُصلَح** عمدًا والتزامًا بالنطاق.
9. **تدوير اعتمادات القبول المحلية: لم يُنفَّذ** — ما زال التوصية قائمة ويحتاج تفويضًا مستقلًا.
10. آثار محلية باقية بالتصميم: `.private/rm05-auth-fixture.json` (سر، بـACL)، `.private/rm05-storage/**` (جلسات وcache الاختبار)، `.private/reports/remediation-05-*` (سجلات)، وبصمة Argon2id واحدة في RM02.

## Y. EXACT SINGLE NEXT RECOMMENDATION

**لا تنفيذ تلقائي. توصية واحدة للمالك:** قبل أي خطوة جديدة، اتخذ القرارات الخمسة المعلَّقة صراحةً — (1) قبول أو رفض بقاء **F06** مفتوحًا قبل Customers؛ (2) القرار المعماري في **SECURITY_GAP-02** (نطاق أب مشترك للـSPA والـAPI أم `SameSite=None; Secure`) لأنه يحدد شكل رحلة الدخول في الإنتاج؛ (3) هل تُطبَّق 037/038 على DEV؛ (4) التخلّص من `daleel_crm_b10b_disposable` والاحتفاظ بـfixtures RM02 والاعتماد الاصطناعي؛ (5) خطة حفظ المعرفة لما هو خارج Git.

وإن أردت خطوة هندسية واحدة تالية، فالأقل خطورة والأعلى قيمة هي إصلاح **F14** (نسخ `getHeaders()` من `HttpExceptionInterface` في `ApiErrorResponse`) مع اختبار واحد — تغيير بسطر واحد في ملف واحد، بلا مساس بـschema أو ACL أو routes. **وهي تحتاج تفويضك؛ لم تُنفَّذ.**

**شروط STOP لأي جولة قادمة:** أي حاجة إلى تعديل migrations أو ACL/policies/triggers/ownership، أو إضعاف CSRF أو تغيير `APP_ENV` لإنجاح اختبار، أو كتابة على DEV/Old TEST/scratch، أو نمو fixtures غير محدود، أو منح أوسع، أو تدوير اعتماد إنتاجي، أو commit/push/deploy، أو بدء Customers.

## Z. HANDOFF FOR NEXT TOOL

1. مساحة العمل `I:\WORK\DALEEL-CRM`؛ الجذر **ليس** مستودع Git؛ أربعة مستودعات مستقلة.
2. API HEAD `d6870839f38b1f05786288071dbe0bb7719d5386` على فرع `phase-0-stabilize-baseline`؛ **لا commit** في RM01–RM05.
3. معدَّل متتبَّع في API: 4 خدمات + `tests/Feature/Tenancy/PostgresRlsIsolationTest.php`. غير متتبَّع: migrations 037/038، `TenantRuntimeWriteContractTest.php`، `TenantStaffHttpKernelAcceptanceTest.php`، `docs/audits/`.
4. الهدف الوحيد المسموح بالكتابة: `daleel_crm_rm02_isolated` OID **21227** على `127.0.0.1:55437`، cluster `7699972247235194919`. **لا تستخدم منفذ المضيف 5432.**
5. محمي بالقراءة فقط: DEV `daleel_acceptance_dev` OID 16412 (55433)، Old TEST `daleel_crm_b10b_disposable` OID 16413 (55437، 18 tenant + 39 صفًا في `users`)، scratch على 55432.
6. PHP: `%USERPROFILE%\.config\herd\bin\php84\php.exe` (8.4.27). **pwsh 7 غير مثبَّت**؛ سكربتات `common.ps1` تنكسر على PowerShell 5.1 — استخدم أدوات PHP.
7. أوامر آمنة للقراءة: `php tools/dev-db/acceptance/rm02-tool.php preflight` و`verify` و`probe` و`guard-selftest`.
8. أوامر الاختبار: `php tools/dev-db/acceptance/rm02-tool.php test all` (29/29، 765 assertion) و`wire` (51/51، يشغّل خادمًا مؤقتًا على 127.0.0.1:54901 ويوقفه).
9. **`auth-fixture` نُفِّذ بالفعل وهو idempotent.** لا تُعِد تدوير البصمة؛ إعادة تشغيله تعلن NO-OP. غياب `.private/rm05-auth-fixture.json` مع بصمة مُدوَّرة = STOP.
10. السر في `tools/dev-db/acceptance/.private/rm05-auth-fixture.json` (خارج Git، ACL مضيَّق). **لا تطبعه ولا تنقله ولا تضعه في argv.**
11. هوية القبول: `rm02-admin-a@proof.invalid` على `rm02-a.acceptance.localhost`. الثلاث الأخرى (`reader-a`، `suspended-a`، `admin-b`) تحمل placeholder غير وظيفي **عن قصد** — لا تُصلحها.
12. CSRF **لا يمكن** إثباته داخل PHPUnit: `PreventRequestForgery` يتجاوز التحقق عند `runningInConsole() && runningUnitTests()`. أي ادّعاء CSRF من مجموعة PHPUnit باطل.
13. `APP_ENV=local` مطلوب لإثبات CSRF، ومسموح أصلًا في `ResolveTenantHost`. **لا تستخدم `APP_ENV=testing` ثم تدّعي إثبات CSRF.**
14. Origin المسموح `http://localhost:3001` من `config/cors.php`؛ `RequireAllowedSpaOrigin` بوابة server-side مستقلة عن CORS وترفض بـ403.
15. رموز العقد: 401 `AUTH_INVALID_CREDENTIALS` / `AUTH_UNAUTHENTICATED`، 419 `AUTH_CSRF_INVALID`، 403 `PERMISSION_DENIED`، 400 `TENANT_SELECTOR_NOT_ALLOWED`، 404 `RESOURCE_NOT_FOUND`، 429 `AUTH_RATE_LIMITED`.
16. throttling للـlogin في `TenantStaffRateLimiter` (خدمة، لا route middleware): 5 لكل (tenant|email|ip)، 100 لكل IP، تحلل 900s. **استخدم بريدًا مُستهلَكًا في أي تجربة throttle** لئلا تُقفل هوية القبول، و**لا تتجاوز ~8 محاولات**.
17. أي طلب مرفوض على مسار tenant-staff **يُفرِّغ الجلسة المقدَّمة** (F15). أعطِ كل سيناريو سلبي جلسة جديدة، وإلا نسبت أثر اختبار إلى آخر.
18. login **لا يكتب أي صف**: الأحداث الأمنية تذهب إلى قناة `structured` ⇒ `php://stderr`.
19. بصمة fixtures الصارمة تضم الآن `auth_fixture_credential_configured` (يجب أن يكون 1) و`shared_placeholder_rows` (يجب أن يكون 3). أي قيمة أخرى = انحراف.
20. `LARAVEL_STORAGE_PATH` يعزل الجلسات والـcache إلى `.private/rm05-storage`؛ استخدمه لئلا تلوّث `storage/` في المستودع.
21. **مفتوح:** F06 (P1، لا تعلنه مغلقًا)، F08، F10 (P3)، F14، F15، SECURITY_GAP-01/02.
22. **غير مُثبت:** business top-level commit، سلوك المتصفح، `/super/*` عبر HTTP، full suite، انتهاء الجلسة المطلق على السلك، 037/038 على DEV.
23. **قائمة المحظور:** DROP/RESET/TRUNCATE/`migrate:fresh`/`db:wipe`؛ حذف tenants أو هويات؛ تعطيل RLS أو trigger؛ GRANT ALL/SUPERUSER/BYPASSRLS؛ تعديل migrations 001–038؛ تعديل `config/*` أو routes أو controllers لإنجاح اختبار؛ إضعاف CSRF؛ كتابة على DEV/Old TEST/scratch؛ منفذ المضيف 5432؛ اتصال خارج 127.0.0.1؛ تثبيت حزم؛ git add/commit/push؛ نشر؛ بدء Customers.
24. وثائق الجذر وكل `tools/dev-db/acceptance/` خارج Git تمامًا ⇒ خطة حفظ مستقلة مطلوبة.
25. اقرأ بالترتيب: `AGENTS.md` ← `docs/STATUS.md` ← `docs/PLAN.md` ← `docs/DECISIONS.md` ← `docs/HANDOFF.md` ← `daleel-crm-api/docs/audits/DEV-FOUNDATION-01.md` (الملحقان RM04 وRM05 أولًا) ← `tools/dev-db/acceptance/TARGET_MANIFEST.md`.
