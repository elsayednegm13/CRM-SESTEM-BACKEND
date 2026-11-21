<div dir="rtl" align="right">

# SECURITY-F06-TEAM-ROLE-ADMIN-REMEDIATION-01

## أ. EXECUTIVE_VERDICT

`BLOCKED / STOP_SCOPE_AUTH_REQUIRED` عند G2، بعد W0 وG1 بالقراءة. لم تُنفذ معالجة مصدر أو Sandbox. سبب التوقف: لا يوجد في fixture الحالي actor إداري ذو منح `role.manage` أو `member.manage`، ولا يستطيع actor إداري جديد الوصول إلى مسار FLAG ON دون تعديل config/identity resolver خارج القائمة المسموحة. لا تُرفع صلاحية A1 فقط لجعل اختبار الإدارة ينجح. نتيجة المرحلة السابقة لـActor Scope تبقى `PARTIAL` و`F06=OPEN`؛ العملاء والإنتاج `NO_GO`.

## ب. W0 — الأصل وحدود التفويض

| Repo | الفرع / HEAD عند البدء | tracked M السابقة |
|---|---|---|
| ROOT | `master` / `c2ee5a3a3e128f86147e06d39cd50ca7ff2cf7d9` | `CLAUDE.md`, `docs/EVIDENCE-REGISTER.md`, `docs/HANDOFF-CURRENT.md`, `docs/WORK-LEDGER.md` |
| API | `preserve/rm02-rm05-baseline` / `e8cee07c2c39df5a1531cbd63168695347202371` | `TenantStaffContextGuard.php`, `TenantStaffRequestContext.php`, `LeadService.php`, `config/database.php` |
| WEB | `master` / `6fb01b8838de52de621dab4691a5cdd5710c29f6` | لا شيء |
| ADMIN | `master` / `9fa43befadaaa5d4583f8de6bf7a06c60e891bef` | لا شيء |
| SUPER | `master` / `a802e44b8a269071bcb46fcaa675aafb43b12a87` | لا شيء |

لم يوجد staged. مرفقات ROOT غير المتتبعة، وأدوات/تقارير F06 القديمة في API، سابقة لهذه الجولة؛ قائمة `status --porcelain=v1 -uall` فُحصت بمساراتها. `CLAUDE.md` تغيير مالك معتمد وبصمته `a972f9ef6f3e9959bb86687d7ffa9eae096ce9d78c1d3d515cc66e2191e8487a`. بصمة `LeadService.php` الحالية `8fb31cb295a1bd52cdc79ad35b54c39e08c0fadd82484eb1d949e793cd58a8cc`. نقطة الـ90 للقراءة فقط: `I:\WORK\DALEEL-CRM-RECOVERY\SECURITY-F06-ACTOR-SCOPE-REVIEW-AND-RECOVERY-01-20261026T105535Z-c0376e29`؛ manifest SHA-256 `7572547e1a3b8d0beac4abc997600e2cc35652274b779ba8ebe1e4ce7e082b1c` والحمولة `90/90` حسب الفاحص، في هذه الجولة قراءة ملفية فقط. هذا لا يعيد أدلة التشغيل السابقة.

Docker server `29.9.2` وPHP `8.6.0RC3` مع `pdo_pgsql`, `intl`, `fileinfo` متاحان. لم تُحدد بيئة DB جديدة أو port ولم تُنشأ موارد، لأن G2 أوقف التنفيذ قبل G3. لم تُقرأ أسرار `.env`، ولم يُتصل بأي قاعدة أو حاوية. الوثائق التاريخية التي تشير إلى HEAD أقدم ليست دليل drift أمام Git الحالي والتقرير السابق.

## ج. G1 — عقد الإدارة الحي

جميع المسارات أدناه تحت `/api/v1/company`، عبر `ResolveTenantHost`, `RejectCompanyContextSelectors`, `RequireAllowedSpaOrigin`, `TenantStaffRequestContext`, `auth:tenant_staff`, `ValidateTenantStaffSession`. تغييرات HTTP تحتاج جلسة وCSRF؛ التفويض الفعلي في الخدمات، لا في route name. `TenantStaffRequestContext` يفتح معاملة على `pgsql_tenant_runtime`؛ تحت ON يبدّلها إلى LOGIN المربوط بـactor قبلها ثم يعيدها في `finally`. provider/first-admin bootstrap مسار آخر غير مفوض للتعديل هنا.

| العملية الحقيقية | method + path | مفتاح الخدمة وقيدها | الجداول/الأثر تحت OFF؛ المطلوب قبل ON |
|---|---|---|---|
| عرض الأدوار | GET `/roles` | `role.view`، non-scopeable | `roles` قراءة؛ ON يحتاج منح SELECT الضيقة، ولا يوجد actor fixture مأذون |
| إنشاء دور | POST `/roles` | `role.manage`، non-scopeable | INSERT `roles` + audit role event؛ ON يحتاج دالة مقيّدة وهوية admin مثبتة |
| تحديث منح دور | PATCH `/roles/{role}` | `role.manage` + `canDelegate` لكل grant + منع تعديل دور الذات | DELETE/INSERT `role_permissions`، زيادة `roles.version`، invariant، audit؛ منع التصعيد غير المباشر لازم في SQL |
| أرشفة دور | DELETE `/roles/{role}` | `role.manage` + منع دور الذات | UPDATE `roles.status/archived_at/version`، invariant، audit |
| عرض الفريق | GET `/staff` | `member.view`، non-scopeable | قراءة memberships/users؛ لا إدارة |
| إنشاء عضو | POST `/staff` | `member.manage` + factory/فحص البريد، ودور اختياري يخضع `assignRole` | INSERT users/membership، audit، وربما دور؛ لا تلمس password hash بلا تفويض |
| تعليق/تفعيل | POST `/staff/{membership}/disable` أو `/reactivate` | `member.manage` + منع الذات + حالة صحيحة | UPDATE status و`authorization_version + 1`، invariant في التعليق، audit؛ `auth_version` لا يتغير هنا |
| تعيين/سحب دور | POST `/staff/{membership}/roles` أو DELETE `/staff/{membership}/roles/{role}` | `member.manage` + target ≠ actor + role ACTIVE؛ التعيين يتحقق من `canDelegate` لكل role grant | INSERT أو UPDATE `tenant_staff_membership_roles.revoked_at`، زيادة `authorization_version`، invariant، audit |
| منح/سحب مباشر | POST `/staff/{membership}/permissions` أو DELETE `/staff/{membership}/permissions/{permission}` | `member.manage` + target ≠ actor؛ المنح يتحقق من `canDelegate`، السحب من وجود grant نشطة | INSERT أو UPDATE `tenant_staff_permission_grants.revoked_at`، زيادة `authorization_version`، invariant، audit |

Controller يرجع 201 للإنشاء/التعيين/المنح و200 لبقية mutation الناجحة، مع `data.status` أو `data.id` و`meta.request_id`. أخطاء auth/validation/SQL لم تُقَس HTTP هنا، فلا تُنسب لها status رقمية في هذه الجولة. جميع العمليات تستخدم `pgsql_tenant_runtime`، وكذلك `TenantStaffAuthorizationService::effectiveGrants`, `TenantStaffAdminInvariant`, و`TenantStaffAuditWriter`؛ لذلك ضيق ACL تحت ON سيؤثر على مسار الإدارة كله. `role.manage`, `role.view`, `member.manage`, `member.view` كلها non-scopeable وdelegable بحسب migration 007؛ `company.administer` نطاق `ALL_TENANT` وغير delegable. `EffectivePermissions` يجمع role/direct grants ويُسقط snapshot فاسدة؛ `canDelegate` يمنع `company.administer` وTEAM/NONE وscope لا يملكه الإداري، لكنه حكم Laravel وحده لا يكفي لحماية SQL حر.

المصدر القديم لـroles/grants/memberships/users عليه FORCE RLS وسياسات سياق TENANT، وmigration 037 يمنح `daleel_tenant_runtime` بعض كتابة الأعمدة، بينما overlay `010_actor_runtime_acl.sql` يفصل LOGINs الأربعة عن هذه المجموعة ويمنحهم قراءة/Leads فقط. Overlay `020_scope_functions.sql` يشتق الهوية من `session_user` وmapping محمي، و`030`/`040` يحميان Leads ويتيحان إعادة إسناد A1 المقيدة. لا توجد دالة Admin في هذه الشريحة. مجرد تبديل HTTP إلى actor LOGIN لا يمنح إذن تعديل مصدر السلطة، وهذا مقصود.

## د. G2 — قرار صلاحية التنفيذ

Fixture `001_fixture_real_schema.sql:68–76` يمنح A1 وB1 `leads.view/manage:ALL_TENANT`، وA2 `SELF`، وA4 `ASSIGNED` فقط. ليس فيه grants إدارة مباشرة أو دور شركة إداري. ملف `config/f06_actor_sql.php:28–35` يربط كلمات مرور ON الاصطناعية بأسماء A1/A2/B1/A4 فقط؛ و`ActorSqlIdentityResolver::passwordFor` يعيد null لأي اسم غير موجود، و`ActorConnectionFactory::switchTo` يرفض null بلا fallback. `TrustedActorBootstrapVerifier` يحتاج mapping موثوقًا متطابقًا مع LOGIN. لذلك لا يمكن إثبات العملية الإدارية الموجبة المطلوبة عبر HTTP ON بالاعتماد الحالي.

أصغر شريحة مرشحة بعد حل الهوية: grant/revoke مباشر إلى **عضو آخر** مع `member.manage` حقيقي، `canDelegate` مطابق لـ`EffectivePermissions`، زيادة version مرة لكل فعل، invariant، audit ذري، ودالة SQL definer محدودة لا تمنح actor كتابة مباشرة. لكنها لم تُنفذ: اختبارها الآن سيستلزم إدخال actor إداري جديد إلى config/lookup أو رفع صلاحية A1 لأجل الاختبار، وكلاهما يخالف بوابة G2 الحالية. إضافة definer وحدها لا تُثبت admin؛ shared bootstrap ليس دليل تفويض بديلًا. لا تختار عمليات أخرى وتدعي تكافؤ جميع الإدارة.

التفويض الأدنى المطلوب لاستئناف التنفيذ: اعتماد هوية Admin صناعية موثوقة في Sandbox جديدة، مع اسم LOGIN وخريطة وcredential resolver صريحة عبر تعديل config/identity surface محدد، أو إثبات وجود actor حالي ذي grants إدارة شرعية من مسار provisioning موثوق. يجب مراجعة حدود definer/audit/invariant/RLS بعد ذلك قبل أي Sandbox. لا تستخدم grant ذاتيًا أو إعادة `daleel_tenant_runtime` للأدوار.

## هـ. G3–G6 — لم تبدأ

`G3` لم تُنشئ PostgreSQL Sandbox ولم تطبق migrations؛ لا system identifier/port/label جديد. `G4` لا SQL نفذ ولا `rc/SQLSTATE/rowcount/catalog/negative mutation` من هذه الجولة. `G5` لا HTTP OFF/ON نفذ، ولا إثبات لتكافؤ إدارة الفريق أو إعادة اختبار Leads. `G6` لم يُعد S01–S12؛ نتائج Actor Scope السابقة تبقى `DOCUMENTED_PRIOR`. لم تُفحص race/revocation/worker reuse في runtime الآن. أي رقم 38/38 أو 31/31 أو 23/23 في التقارير السابقة يخص Sandbox سابقة، لا هذه المرحلة.

## ز. Delta/Impact وقرار التسليم

الملفان الجديدان فقط: هذا التقرير و`tools/security/f06-team-role-admin-remediation-01/ATTEMPT-LEDGER.md`. لم يُعدّل ملف تطبيق أو migration أو config أو fixture قديم، ولم تُجرَ Git writes أو cleanup. لا حاوية/volume/network/server جديد. ROOT/WEB/ADMIN/SUPER لم تُكتب؛ وثائق handoff العامة تحتاج تحديثًا في تفويض لاحق يسمح بها. لم تُنشأ checkpoint جديدة؛ حفظ هذه الدلتا، إن أصبح مطلوبًا، يحتاج تفويض مراجعة واسترجاع مستقلًا.

`ADMIN_OPERATIONS_SCOPED_AT_SQL=BLOCKED_NOT_EXECUTED`; `TEAM_ROLE_ADMIN_FLAG_ON=BLOCKED_NOT_TESTED`; `F06=OPEN`; `CUSTOMERS=NO_GO`; `PRODUCTION=NO_GO`. البوابة التالية: تفويض محدود لهوية admin التجريبية ومسار ربطها، ثم مراجعة G2 جديدة قبل تشغيل أي DB.

## ح. Evidence index والأعلام

- `routes/api.php:64–89` ومسارات Controller حقيقية؛ `TenantStaffRoleMutationService.php` و`TenantStaffAccountService.php` لعقود mutation.
- `database/migrations/2026_10_06_000007_insert_rbac_reference_data.php:12–29` لمفاتيح الإدارة؛ `tools/security/f06-actor-scope-implement-01/001_fixture_real_schema.sql:61–82` للـfixture؛ `config/f06_actor_sql.php:28–35` و`ActorSqlIdentityResolver.php` لحد الهوية ON.
- SHA-256 قبل/بعد لملفي الخدمة: `51fc64b745e58c3daf03679a0b21e1899fdf5454ebe8e9116c05768649003a32` و`80b1e2a0a390d93b78c83543db49038d0c958b0532d271f40c89c0dcda68dc7e`. SHA fixture `8506be5ccc338c2c1c394a0292110dffea02e0e3c9af9c450822ae2b72cbf8d8`، SHA config `4212c1e811a3105a047836fda22d8cfb2d4f4aed9d54728e8e67fd9c9e5fb2c8`.

```text
W0_PRECHECK = PASS_SOURCE_AND_TOOL_AVAILABILITY
FIVE_REPO_BASELINE = VERIFIED_EXPECTED_HEADS_STATUS
OWNER_APPROVED_CLAUDE_UNTOUCHED = YES_SHA256_MATCH
RECOVERY_90_MANIFEST_SHA_MATCH = YES_PAYLOAD_90_OF_90
REAL_MIGRATIONS_APPLIED = NOT_EXECUTED
ACTOR_SQL_AUTH_SOURCE_DIRECT_WRITES_DENIED = DOCUMENTED_PRIOR_NOT_RETESTED
ADMIN_SQL_FUNCTION_AUTHZ_BOUNDARY = NOT_IMPLEMENTED
ADMIN_SQL_POSITIVE = NOT_EXECUTED
ADMIN_SQL_NEGATIVE = NOT_EXECUTED
SELF_GRANT_INDIRECT_ESCALATION = NOT_TESTED_THIS_ROUND
ADMIN_ROLE_MEMBERSHIP_SCOPE = BLOCKED_NO_AUTHORIZED_ADMIN_ACTOR
AUTH_VERSION_AND_AUTHORIZATION_VERSION_PARITY = NOT_TESTED_THIS_ROUND
FLAG_OFF_ADMIN_HTTP = NOT_EXECUTED
FLAG_ON_ADMIN_HTTP = NOT_EXECUTED
FLAG_ON_TEAM_ROLE_ADMIN_PARITY = BLOCKED_NOT_VERIFIED
LEADS_ON_REGRESSION = NOT_EXECUTED
SET_ROLE_AND_GUC_CROSS_TENANT = DOCUMENTED_PRIOR_NOT_RETESTED
FUNCTION_OWNER_SEARCH_PATH_PUBLIC_EXECUTE_CATALOG = DOCUMENTED_PRIOR_NOT_RETESTED
NEGATIVE_MUTATION_CONTROLS = NOT_EXECUTED
SQLSTATE_ROWCOUNT_AND_FINGERPRINT = NOT_EXECUTED
HTTP_SAME_WORKER_REUSE = NOT_VERIFIED
HISTORICAL_TESTS_REPLAY = NOT_EXECUTED
ACTOR_SCOPE_AT_SQL = PARTIAL_DOCUMENTED_PRIOR
PHP_MULTI_CREDENTIAL_COMPROMISE = OPEN
ROLE_PROVISIONING_PRODUCT = NOT_IMPLEMENTED
MIGRATION_039 = NOT_CREATED_NOT_RUN
T4B = OPEN
F16 = OPEN
GIT_WRITE = NONE
NEW_CHECKPOINT = NOT_CREATED
CUSTOMERS = NO_GO
PRODUCTION = NO_GO
EXECUTIVE_VERDICT = BLOCKED_STOP_SCOPE_AUTH_REQUIRED
NEXT_GATE = OWNER_SCOPED_SYNTHETIC_ADMIN_IDENTITY_MAPPING_AND_G2_REVIEW
```

</div>
