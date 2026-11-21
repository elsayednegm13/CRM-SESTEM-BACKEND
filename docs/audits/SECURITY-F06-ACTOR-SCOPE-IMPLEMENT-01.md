<div dir="rtl" align="right">

# SECURITY-F06-ACTOR-SCOPE-IMPLEMENT-01

## أ) EXECUTIVE_VERDICT

**PARTIAL.** ثبت حدّ SQL تجريبي لنطاق موظف في جدول `leads` الحقيقي داخل Sandbox مستقلة: منع A4 من منح نفسه `ALL_TENANT` بعد قفل مصدر التفويض، ونجحت سياسات القراءة والكتابة المقيدة وإعادة إسناد A1، مع تكافؤ 23 حالة HTTP تحت كل من `FLAG=OFF/ON`. لا يمثل هذا علاج المنتج أو إغلاق F06. لم تُختبر إدارة الفريق/الأدوار تحت ON بعد سحب امتيازات الكتابة التي تستخدمها خدمتها، وبعض S01–S12 غير مكتمل؛ لذلك **NO-GO للعملاء والإنتاج**. قرار التصميم السابق `PARTIAL_DESIGN` بقي حدًا لا اعتمادًا للنشر.

## ب) W0 والملكية

قبل الكتابة وبعدها بقيت الفروع وHEADs: ROOT `master/c2ee5a3a3e128f86147e06d39cd50ca7ff2cf7d9`؛ API `preserve/rm02-rm05-baseline/e8cee07c2c39df5a1531cbd63168695347202371`؛ WEB `master/6fb01b8838de52de621dab4691a5cdd5710c29f6`؛ ADMIN `master/9fa43befadaaa5d4583f8de6bf7a06c60e891bef`؛ SUPER `master/a802e44b8a269071bcb46fcaa675aafb43b12a87`. `staged=0` في الخمسة. WEB/ADMIN/SUPER نظيفة. كانت ROOT تحمل أربعة tracked `M` ومرفقات مسبقة؛ لم تُمس، ومنها `CLAUDE.md` المعتمد مسبقًا ببصمة SHA-256 `a972f9ef6f3e9959bb86687d7ffa9eae096ce9d78c1d3d515cc66e2191e8487a`. كانت API تحمل ثلاثة tracked `M` وملفات أمن/تقارير سابقة غير متتبعة؛ tracked `M` الرابع الوحيد الجديد هو `LeadService.php`. لا يُستدل بعدد أسطر `git status` وحده لأن مجلد الأدوات يظهر مدخلًا واحدًا مهما زادت ملفاته.

مرجع الاسترجاع `I:\WORK\DALEEL-CRM-RECOVERY\SECURITY-F06-I03-REVIEW-AND-RECOVERY-01-20261026T051638Z-c12a0835`: بصمة manifest قبل/بعد `54842a573b1af75fbbca8399bfff04c4534246ddfe8fb68b759d1a678a85ac92`، والتحقق السابق في هذه الجولة طابق 57/57 من بايتات المصدر. نقطة الحفظ لم تُكتب أو تُستعد؛ وثيقة التصميم الجديدة خارج تغطيتها. لا تعد Backup مستقلًا.

## ج) التنفيذ والموارد

أُنشئت حاويتان اصطناعيتان جديدتان لهذه الجولة فقط لأن المحاولة الأولى انجرفت بياناتها بعد عطل إيقاف HTTP. الأولى `daleel-f06-actor-scope-i01-29d3068e-pg`، معرف نظام `7700869775783759918`، أُوقفت دون حذف؛ تفاصيل الحادث في `ATTEMPT-LEDGER.md`. الثانية المعتمدة للأدلة النهائية `daleel-f06-actor-scope-i01-b5b015ac-pg`، قاعدة `daleel_f06scope01` على `127.0.0.1:55473`، معرف `7700882006031409190`، وشبكة/volume منفصلتان موسومتان بالتحكم `SECURITY-F06-ACTOR-SCOPE-IMPLEMENT-01`. أثبت `initdb` وHBA استخدام `SCRAM-SHA-256` فقط؛ كلمة مرور خاطئة `rc=2` والصحيحة نجحت قبل DDL. ثُبتت 38/38 migrations حقيقية على قاعدة جديدة، بقائمة الأسماء في `migration_evidence.json`. بيانات اعتماد الاختبار وملفات التشغيل خارج المستودع؛ لا بيانات عميل. لم تُلمس الحاويات والقواعد المحمية أو منفذ 5432.

بعد fixture I03 المنسوخة، طبّقت overlays محصورة بهذه Sandbox: `010` مجموعة actor ضيقة وسحب عضوية runtime القديمة، `020` مرساة `session_user` ومنح فعالة، `030` أربع سياسات `RESTRICTIVE` على Leads، `040` دالة إعادة إسناد ضيقة. أعيدت بوابات G2 وSQL والكتالوج بعد آخر عبث اختباري. ثم تأكد label ومعرف النظام وأُوقفت الحاوية النهائية دون حذف container/network/volume؛ خوادم HTTP المحلية أُغلقت بواسطة harness. لا migration 039 ولا provisioner منتج. الأمثلة المرجعية لدور PostgreSQL والسياسات والدوال: [Row security](https://www.postgresql.org/docs/16/ddl-rowsecurity.html)، [CREATE POLICY](https://www.postgresql.org/docs/16/sql-createpolicy.html)، [CREATE FUNCTION](https://www.postgresql.org/docs/16/sql-createfunction.html).

## د) الدلتا المصرح بها

أضيف `tools/security/f06-actor-scope-implement-01/` بما فيه SQL وharness وأدلة JSON ودفتر المحاولات، وهذا التقرير فقط. نُسخت ملفات fixture السابقة إلى المجلد الجديد بلا تعديل الأصل؛ بصماتها SHA-256: `000_provision_roles.sql` = `a5e6349bb217cf5d6506a2f1379e36d60b855a412fd7dcb4d6e136ad9d2db442`؛ `001_fixture_real_schema.sql` = `8506be5ccc338c2c1c394a0292110dffea02e0e3c9af9c450822ae2b72cbf8d8`؛ `002_actor_sql_fixture.sql` = `b512fd9603e0a7bc971a529950426e0c93dbd27c20088e0b1ae3e81da99cdcc0`. 

الاستثناء الوحيد في مصدر API: `app/Modules/Tenancy/Application/LeadService.php::assignLead`، قبل SHA-256 `7c9ade052cb4085fd731f013ecd29d1c5b8d526ecee3ec8d285d4733c915e504` وبعد `8fb31cb295a1bd52cdc79ad35b54c39e08c0fadd82484eb1d949e793cd58a8cc`. فحص SQL أثبت رفض تحديث assignment المباشر `42501` حتى لـA1، فصار نداء الدالة لازمًا لاختبار HTTP الحقيقي. شرط `enabled` و`allow_env` القائم يحصر النداء في تجربة ON المسموح بها؛ فرع `else` يحتفظ بعبارة UPDATE الأصلية حرفيًا. لا توقيع أو route أو عقد API جديد؛ `php -l` و`git diff --check` نجحا. لا تغيير لأي migrations أو FLAG default أو تطبيقات الواجهة أو وثائق ROOT.

## هـ) G1–G7 ومصفوفة S

| البوابة | النتيجة والحد |
|---|---|
| G1 | PASS للـSandbox النهائية: ملكية label/system id، SCRAM من `initdb`، 38/38 migrations وfixtures اصطناعية. |
| G2 | PASS محصور: A4 صنع grant مباشر `leads.manage:ALL_TENANT` على baseline `rc=0` داخل rollback، وبعد overlay رُفض `rc=3/42501`؛ 11/11 محاولات مصدرية رُفضت 42501، والضابط الإداري المستقل نجح. |
| G3 | PASS للشريحة: مجموعة actor موروثة `ADMIN FALSE/INHERIT TRUE/SET FALSE`، أربع سياسات RESTRICTIVE، مرساة session_user، ACL/owner/FORCE/PUBLIC فُحصت. |
| G4 | PASS للحالات المنفذة: 31/31 SQL، مع بصمة Leads كاملة قبل/بعد متطابقة. تغطية unions وحالات catalog المعطلة ليست مكتملة. |
| G5 | PASS محصور: دالة A1 نجحت، A2/A4 وهدف B/موقوف رُفضوا في SQL/الاختبارات السابقة؛ HTTP A1 نجح وA2/A4 رُفضوا. |
| G6 | PARTIAL: 46/46 حالة HTTP و31/31 SQL، لكن S07/S09/S10/S11/S12 ليست كاملة وفق المصفوفة المطلوبة. |
| G7 | PARTIAL: ضوابط الملكية وACL والبصمة مثبتة؛ إدارة الفريق ON، العامل الثابت، replay التاريخي، كلفة الاستعلام، وبعض خلطات grants لم تُثبت. |

النتائج التالية من `sql_scope_evidence.json` و`g2_negative_controls.json` و`http_gate_evidence_20261026T105642.json` و`revocation_evidence.json` و`negative_mutation_evidence.json`. قيم `rc/SQLSTATE` المذكورة تخص SQL؛ HTTP له status منفصل.

| الحالة | المتوقع ← المشاهد؛ الحكم |
|---|---|
| S01 | A1/A2/A4/B1 counts `5/1/1/1` بـ`rc=0`، مع عزل B؛ PASS للحالات المقاسة، IDs/NULL/كل خليط منح غير مكتمل. |
| S02 | صف زميل مخفي عن A4/A2، JOIN وتزوير GUC لشركة B يعيدان `0`، ضوابط موجبة ضمن S01؛ `rc=0`، PASS للحالات المقاسة. |
| S03 | UPDATE/RETURNING داخل النطاق يعيد ID، وخارجه لا يعيده؛ `rc=0`، بصمة كاملة ثابتة بعد rollback؛ PASS للحالات المقاسة. |
| S04 | INSERT مشروع A4 وA1 مع NULL ينجح؛ تزوير creator/assignment/tenant وNULL غير المشروع `rc=3/42501`؛ PASS للحالات المقاسة. |
| S05 | تحديث مباشر لـassignment/creator/tenant/id `rc=3/42501`؛ A1 كذلك ممنوع من assignment المباشر؛ PASS للحالات المقاسة، UPDATE جماعي غير منفذ. |
| S06 | دالة A1 `rc=0`، A2/A4/B target `rc=3/42501`؛ HTTP A1 `200` وA2/A4 `403` ورؤية A4 بعد النقل `200`؛ PASS للحالات المقاسة، تحقق HTTP لهدف B/موقوف غير منفذ. |
| S07 | SQL DELETE لـA1/A4 `rc=3/42501`؛ HTTP archive غير منفذ، لذا PARTIAL. |
| S08 | baseline grant ذاتي `rc=0` ثم بعد القفل `rc=3/42501`، و11/11 محاولات تصعيد `42501` مع بصمة المصدر ثابتة؛ PASS للمسارات المقاسة. |
| S09 | SET ROLE للمجموعة الجديدة والقديمة وA1 `rc=3/42501`؛ catalog يمنع PUBLIC EXECUTE للدوال الخمس وactor ownership=0؛ mapping مفقود وspoof definer غير منفذين، لذا PARTIAL. |
| S10 | تعليق عضوية A4 بعد COMMIT أثناء معاملة READ COMMITTED أعطى `1→0`، والعبارة على اتصال جديد `0`، مع استعادة fixture؛ `rc=0`. revoke grant وعبارة جارية وcredential rotation غير مثبتة، لذا PARTIAL. |
| S11 | 23/23 OFF و23/23 ON، Host `404`، guest `401`، CSRF `419`، login/Leads/assign/403، مقارنة status/IDs/body keys/data keysets والقيم المعتمدة، واستعادة البصمة بعد كل flag؛ PASS لمسار Leads فقط. إدارة الفريق/الأدوار ON وworker ثابت غير منفذين، لذا PARTIAL. |
| S12 | إسقاط سياسة SELECT مؤقتًا كشف صف الزميل، ومنح INSERT المؤقت لمصدر grant أتاح ALL_TENANT، ثم ROLLBACK وإعادة فحص السياسة/ACL/البصمة؛ 2/2 negative controls كشفت الضعف. هذه محاكاة بامتياز admin مع `SET SESSION AUTHORIZATION` داخل المعاملة وليست login actor مستقل؛ SET membership/assignment mutation غير منفذين، لذا PARTIAL. |

## و) حد مصدر السلطة وRLS/ACL

قبل overlay كان A4 يرث كتابة `tenant_staff_permission_grants` ويستطيع زيادة سلطته داخل المعاملة ثم استدعاء resolver؛ لذلك لم تكن RLS التي تقرأ ذلك المصدر كافية. بعد فصل المجموعة لا يملك actors كتابة جداول role/direct/membership/permission ولا CREATE في `public` أو SET ROLE أو UPDATE مباشر لعمود assignment. المسار الإداري المستقل على اعتماد shared bootstrap نجح، لكن `TenantStaffRoleMutationService` و`TenantStaffAccountService` تكتبان عبر `pgsql_tenant_runtime`؛ تحت ON يصبح هذا اعتماد actor الضيق. لذلك **تكافؤ إدارة الفريق/الأدوار ON غير مثبت، وخطر انكساره مستند إلى المصدر**، ولا يجوز توسيع grants القديمة لعلاجه في هذه الشريحة.

السياسات الأربع `AS RESTRICTIVE TO daleel_f06scope_actor_runtime` تُضرب منطقيًا في سياسات tenant الموروثة. `SELECT` يتطلب `view`؛ `INSERT` يتطلب `manage` وcreator مطابقًا وقاعدة assignment؛ `UPDATE` يتحقق من OLD وNEW بنطاق `manage`، بينما ACL يسحب assignment/identity؛ `DELETE` false. الدوال `SECURITY DEFINER` لها `search_path=pg_catalog, public, pg_temp` و`PUBLIC EXECUTE` مسحوب. Leads `FORCE RLS=t`، runtime actor لا يملك أشياء، وACL الفعلي لـA4 في فحص الاختيارات `f|f|f|t|f|f|f|f` (schema CREATE، role DELETE، grant INSERT، lead name UPDATE، assignment UPDATE، DELETE، TRUNCATE، REFERENCES). هذا إثبات لكتالوج الـSandbox فقط، لا لقاعدة منتج. لا ادعاء بمنع FK oracle أو تجاوز من يملك PHP/عدة اعتمادات.

## ز) الحادث والحدود والخطوة التالية

المحاولة الأولى سجلت 46 حالة `ok=true` لكن إيقاف منفذ HTTP أخفق، فلم تُنفذ استعادة صفوف ON؛ تغيرت بصمة Leads من `2d0146eebd62e9263ad6647a0d334ed1` إلى `e56cfe1323f768a5c3db927bf08c1fd8`. لا تُحسب نجاحًا. أصلح harness انتظار إغلاق المنفذ، ثم أُنشئت Sandbox ثانية ببصمة أساس مستقلة `6dae888722a8bbd5a352f4f28d4aab01`، ونجح فيها 46/46 مع استعادة OFF/ON. لا حذف للحادث ولا نسبة له إلى الأساس الجديد.

الدليل الحالي `LIVE_SANDBOX_OBSERVED` للمعرف الثاني فقط؛ التقرير I03 السابق `DOCUMENTED_PRIOR`، والاستنتاج عن إدارة الفريق `SOURCE_REASONED`، والاختبارات الناقصة `NOT_VERIFIED`. إعادة تشغيل suites التاريخية ممنوعة هنا لأنها قد تستهدف TEST/موارد أخرى. لا إثبات `HTTP_SAME_WORKER_REUSE` من `artisan serve`، ولا اختبار performance ممثل. لم تُنشأ نقطة استرجاع جديدة. مراجعة مستقلة للدلتا والأدلة، ثم تفويض استرجاع منفصل إن وافق المالك على الشريحة، هما البوابة التالية؛ لا بدء تلقائي للمنتج.

### أعلام الإغلاق

```text
W0_PRECHECK = PASS
RECOVERY_57_FILE_REFERENCE_UNCHANGED = PASS
ONLY_AUTHORIZED_SOURCE_CHANGES = PASS
FRESH_SANDBOX_OWNERSHIP = PASS
SCRAM_FROM_INITDB = PASS
REAL_MIGRATIONS_38_OF_38 = PASS
ROLE_MEMBERSHIP_SET_FALSE_NO_ALTERNATIVE = PASS_SCOPED_CATALOG
ACTOR_AUTH_SOURCE_MUTATION_REPRODUCED_PRE_FIX = PASS
AUTH_SOURCE_IMMUTABLE_TO_ACTOR_SQL = PASS_SCOPED_SANDBOX
AUTH_SOURCE_NEGATIVE_CONTROLS = PASS_11_OF_11
RESTRICTIVE_RLS_ACTOR_GROUP_APPLIES = PASS_SCOPED_SANDBOX
LEADS_VIEW_SCOPE_SQL = PASS_TESTED_CASES
LEADS_MANAGE_SCOPE_SQL = PASS_TESTED_CASES
ASSIGNED_SELF_UNION = NOT_FULLY_VERIFIED
INSERT_CREATOR_AND_ASSIGNMENT_INVARIANTS = PASS_TESTED_CASES
DIRECT_ASSIGNMENT_UPDATE_DENIED = PASS
DEFINER_REASSIGNMENT_ALL_TENANT = PASS_TESTED_CASES
FORCE_RLS_AND_DEFINER_ACL = PASS_SCOPED_CATALOG
TENANT_SQL_BOUNDARY_AFTER_CHANGES = PASS_TESTED_CASES
SET_ROLE_GROUP_DENIED = PASS
HTTP_LEADS_REAL_SERVICE_FLAG_OFF = PASS_23_OF_23
HTTP_LEADS_REAL_SERVICE_FLAG_ON = PASS_23_OF_23
FLAG_OFF_PARITY = PASS_TESTED_CASES
FLAG_ON_TEAM_ROLE_ADMIN_PARITY = NOT_VERIFIED_SOURCE_RISK
S01_TO_S12_MANIFEST = PARTIAL
NEGATIVE_MUTATION_CONTROLS = PARTIAL_2_OF_2_EXECUTED
DATA_FINGERPRINT_BEFORE_AFTER = PASS_FINAL_SANDBOX; FIRST_ATTEMPT_DRIFT_RECORDED
HTTP_SAME_WORKER_REUSE = NOT_VERIFIED
HISTORICAL_SUITES_REPLAY = NOT_EXECUTED_UNSAFE_TARGET
ACTOR_SCOPE_AT_SQL = PARTIAL_PROVEN_LEADS_CORE_ONLY
PHP_MULTI_CREDENTIAL_COMPROMISE_RISK = OPEN
ROLE_PROVISIONING_PRODUCT = NOT_IMPLEMENTED
T4B_REMEDIATION = NOT_PERFORMED
F16_REMEDIATION = NOT_PERFORMED
F06_PRODUCT_REMEDIATION = NOT_PERFORMED
MIGRATION_039 = NOT_CREATED_NOT_RUN
ROOT_DOCS_PRESERVED = PASS
OTHER_GIT_REPOS_UNCHANGED = PASS
GIT_COMMIT = NOT_EXECUTED
CUSTOMERS = NO_GO
PRODUCTION = NO_GO
NEXT_GATE = INDEPENDENT_DELTA_REVIEW_AND_RECOVERY_AUTHORIZATION_IF_SCOPED_PASS
```

</div>
