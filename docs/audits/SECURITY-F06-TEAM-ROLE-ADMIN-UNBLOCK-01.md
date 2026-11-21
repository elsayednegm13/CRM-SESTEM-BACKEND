# SECURITY-F06-TEAM-ROLE-ADMIN-UNBLOCK-01

التاريخ: 2026-10-26. الدور: Backend engineer وQA/Security reviewer. هذه تجربة محلية على PostgreSQL16 جديدة ببيانات اصطناعية فقط. **EXECUTIVE_VERDICT=PASS_SCOPED_FOR_A5_DIRECT_GRANT_REVOKE** لمسار `leads.view:SELF` المباشر إلى A4، مع بقاء F06 والمنتج والعملاء والإنتاج OPEN/NO_GO. مسارات إدارة الأدوار وبقية دورة العضوية لم تدخل هذا الحكم.

## البوابات وحدود الإثبات

| البوابة | الحكم | دليل الجولة الحالية |
|---|---|---|
| W0 | PASS | HEADs والحالة قبل/بعد، SHA، لا staged/commit، لا لمس موارد قديمة |
| G1/G2 مصدر وهوية | PASS_SOURCE_SCOPED | mapping A5 سطر واحد؛ `config_preflight.php` يثبت null عند غياب الاعتماد أو اسم مجهول، واستقلال A1؛ اختيار `TenantStaffRoleMutationService` من route/controller/service |
| G3 Sandbox | PASS | حاوية جديدة، system identifier مستقل، SCRAM، تشغيل provision مرتين، migrations حقيقية 38/38، fixtures صناعية |
| G4 A5 | PASS | claim/read موجب؛ 11/11 كتابة authority أو SET ROLE مرفوضة `rc=3/SQLSTATE=42501`؛ fingerprint ثابت |
| G5 SQL | PASS | definer موجب GRANT/REVOKE داخل rollback، 6/6 سلبي، owner/search_path/no PUBLIC EXECUTE، fingerprint ثابت |
| G6 HTTP | PASS_SCOPED | Laravel حقيقي OFF ثم ON على baseline متطابق: POST 201 وDELETE 200، version 1→2→3 وaudit 0→1→2، 11 حالات 403 مع guest/cross Host 401 وmissing CSRF 419 في كل وضع؛ baseline يعود حرفيًا بينهما وبعدهما |
| G7 Leads | PASS_SCOPED | S01–S07/S09: 31/31، fingerprint Leads ثابت؛ تحكمان عكسيان داخل rollback اكتشفا ضعف policy/ACL، ثم عادت السياسة والامتياز والبصمة |
| G8 | NO_PRODUCT_GO | مراجعة دلتا مستقلة مطلوبة؛ لا migration 039 ولا checkpoint جديد |

إثبات G6 هو اتصال HTTPS loopback إلى TLS proxy ثم `artisan serve` مع Host وOrigin وCSRF وملفات cookie منفصلة، `TenantStaffRequestContext` وcontroller والخدمة والدالة SQL عند ON. تأكدت استجابة `data.status` من `GRANTED` و`REVOKED`، وعدد grant النشط، ونسخة A4، وترتيب event type. فُحصت حقول audit أيضًا: tenant A وactor A5 وtarget staff A4 و`SUCCESS` و`request_id=NULL` و`metadata={}` وغياب target role؛ وصف grant يحمل A5 في granted_by/revoked_by وتوقيتَي المنح والسحب. UUID والوقت متغيران بطبيعتهما؛ المقارنة طبّعت قيمهما فقط، ولم تطبّع status أو business state أو audit/version. لا يوجد إثبات same-worker HTTP.

## مصدر العقد والتعديل

`routes/api.php:88–89` يوجه POST/DELETE إلى `TenantStaffRoleManagementController.php:61–84`. الخدمة `TenantStaffRoleMutationService.php:141–238` تتحقق من `member.manage`، ومنع الذات، و`canDelegate` عند المنح، ثم mutation/version/invariant/audit داخل transaction. POST يعيد 201/`GRANTED` وDELETE يعيد 200/`REVOKED`. duplicate/repeat revoke رفض 403؛ لم يُعامل كعملية idempotent. A4 ACTIVE وله `leads.view:ASSIGNED` من fixture؛ إضافة `SELF` ثم إلغاؤها observable. A5 له RBAC صناعي `member.manage`, `member.view`, `role.manage`, `role.view`, `leads.view:SELF`، وليس `company.administer`. A0 عضوية صناعية خاملة بلا LOGIN تحمل `company.administer:ALL_TENANT` كمرساة invariant، وليست actor HTTP/SQL. لم تُرفع grants A1/A2/A4/B1.

المنتج المعدل: `config/f06_actor_sql.php` أضيف إليه سطر `daleel_f06team01_actor_a5 => env('F06_ACTOR_PW_A5')` فقط؛ `TenantStaffRoleMutationService.php` أضيفت فيه فروع ON المحدودة داخل `grantPermission` و`revokePermission` فقط. OFF بقي في ذيل الميثودين. ON يستدعي `public.f06team01_direct_permission` ثم invariant؛ الدالة نفسها تؤدي INSERT/REVOKE و`authorization_version += 1` وaudit، فلا كتابة مزدوجة. الاستثناءات 42501/23505 تصنف إلى AuthorizationDenied ضمن الفرع المناسب. لا تعديل route/controller/LeadService/migrations/API contract. `php -l` للملفين و`git diff --check` PASS. الدالة overlay محلية في Sandbox فقط؛ تشغيل ON على بيئة لا تحتويها ليس جاهزًا للمنتج.

الدالة `SECURITY DEFINER` مملوكة لدور NOLOGIN `daleel_f06team01_admin_executor` مع `search_path=pg_catalog, public, pg_temp`، وPUBLIC EXECUTE مغلق. تستمد actor من `session_user` وخريطة SQL محمية وعضوية/RBAC LIVE، لا من GUC أو معرف client. تحصر action وpermission/scope وتمنع الذات والهدف غير النشط أو خارج tenant؛ row lock وversion/audit في معاملة واحدة. ACL الجدول لا يسمح بحساب A5 بتعديل authority مباشرة؛ FORCE RLS بقي فعّالًا. G5 أثبت GRANT/REVOKE ورفض A4، الذات، `company.administer`, tenant B، suspended وALL_TENANT بـ42501. G4 أثبت منع SET ROLE للمجموعة الضيقة والقديمة وA1.

## Sandbox والحفظ

حاوية `daleel-f06-team01-bbff4ef6-pg`، label `control=SECURITY-F06-TEAM-ROLE-ADMIN-UNBLOCK-01` و`purpose=synthetic-only`، network `daleel-f06-team01-bbff4ef6-net`، volume `daleel_f06_team01_bbff4ef6_pg_data`، PostgreSQL16، bind `127.0.0.1:55480` فقط. `system_identifier=7700986034630172718`، مختلف عن IDs المحمية. HBA SCRAM من initdb، wrong password `rc=2`، good password PASS؛ provision مرتين، migrations 38/38. بيئة secrets/raw wire خارج المستودع في `%LOCALAPPDATA%\Temp\f06-team01-bbff4ef6-tnl6ls6y`؛ لا تُدرج هنا. لم تُستخدم قاعدة 5432 أو protected 55432/55437/55439 أو موارد POC/I01–I03/ActorScope. لا بيانات عميل ولا SQL dump.

بعد البوابات طابقنا اسم الحاوية وlabel وsystem identifier ثم نفذنا `docker stop` لها وحدها؛ بقي container/volume/network محفوظًا دون حذف. خوادم Laravel/TLS المؤقتة أُوقفت عند انتهاء harness.

محاولتان في harness احتاجتا تصحيحًا: حذف fixture بعد OFF اصطدم بتريغر منع حذف grant، ثم فحص audit استخدم `created_at` بدل `occurred_at`. سجل `ATTEMPT-LEDGER.md` يحتفظ بالتسلسل. في كل مرة أُعيدت صفوف الجولة الصناعية وحدها بمعاملة superuser داخل الحاوية المملوكة، عُطّلت تريغرات USER المحددة مؤقتًا ثم فُعّلت، وتطابقت بصمة authority الأصلية `d1ea25751eff723bc3c2bfe7f6dbd6a1` وحالة التريغرات. الجولة النهائية المستقلة أعادت البصمة نفسها بعد OFF وبعد ON. هذا reset خاص بالـfixture وليس سلوك المنتج.

## السلبيات والانحدار والفجوات

HTTP OFF/ON رفض الذات، nondelegable `company.administer`, توسعة scope إلى ALL_TENANT، target B، target suspended، repeat grant/revoke، وA1/A2/A4/B1 بلا `member.manage`، كل حالة 403 بلا تغيير grant/version/audit. Guest على GET staff وعبور جلسة A5 إلى Host B أعادا 401؛ POST بلا CSRF أعاد 419، أيضًا بلا mutation. نقص `F06_ACTOR_PW_A5` عند ON منع mutation وبقيت بصمة authority ثابتة، لكن عاد **HTTP 500**؛ A1 استمر في قراءة Leads بـ200 باعتماده المستقل. `A5_MISSING_CREDENTIAL_FAIL_CLOSED=PASS_SECURITY/FAIL_UX`. لا قبول إنتاجي لهذا الشكل.

G7 الحالي أعاد 31/31 SQL: A1 ALL_TENANT، A2 SELF، A4 ASSIGNED، B1 tenant B، منع SQL direct assignment وتزوير tenant GUC، نجاح definer المشروع A1 ورفض A2/A4/tenant B، ورفض SET ROLE. `UPDATE 0` و`SELECT 0` مصنفان فصلًا عن `42501/rc=3`. mutation controls داخل rollback أثبتا أن حذف policy أو منح INSERT غير المشروع يكشفان leakage؛ أعيدت policy/ACL والفingerprint. A5 يملك `leads.view:SELF` للتفويض فقط؛ لم يُمنح `leads.manage`، ولا يُستنتج منه إدارة Leads. لم نثبت multi-connection revocation أو HTTP same-worker. لم تُشغّل الحزمة التاريخية على DB محمية؛ `HISTORICAL_TESTS_REPLAY=BLOCKED_UNSAFE_TEST_TARGET`.

## Git والدلتا

ROOT `master/c2ee5a3a3e128f86147e06d39cd50ca7ff2cf7d9`؛ API `preserve/rm02-rm05-baseline/e8cee07c2c39df5a1531cbd63168695347202371`؛ WEB `master/6fb01b8838de52de621dab4691a5cdd5710c29f6`؛ ADMIN `master/9fa43befadaaa5d4583f8de6bf7a06c60e891bef`؛ SUPER `master/a802e44b8a269071bcb46fcaa675aafb43b12a87`. Staged=0، لا Git write. ROOT tracked M السابقة: `CLAUDE.md`, `docs/EVIDENCE-REGISTER.md`, `docs/HANDOFF-CURRENT.md`, `docs/WORK-LEDGER.md`؛ API tracked M السابقة: `config/database.php`, `TenantStaffContextGuard.php`, `TenantStaffRequestContext.php`, `LeadService.php`. API tracked M جديدة: `TenantStaffRoleMutationService.php`. Config وtools/report غير متتبعة ضمن API، إلى جانب untracked الأقدم الموجودة قبل الجولة. WEB/ADMIN/SUPER نظيفة. مرفقات root غير متتبعة سابقة لا تخص التعديل.

SHA ثابت `CLAUDE.md=a972f9ef6f3e9959bb86687d7ffa9eae096ce9d78c1d3d515cc66e2191e8487a`، `LeadService.php=8fb31cb295a1bd52cdc79ad35b54c39e08c0fadd82484eb1d949e793cd58a8cc`؛ config قبل `4212c1e811a3105a047836fda22d8cfb2d4f4aed9d54728e8e67fd9c9e5fb2c8` وبعد `30aa43295aec9f0768021a2f48277294f850bcc5f80b08b0cce2ba2cd55f4140`؛ service قبل من HEAD النظيف `51fc64b745e58c3daf03679a0b21e1899fdf5454ebe8e9116c05768649003a32` وبعد `cf9fee89cd70768c6236c9e55feccae202992b075b492157dbd1ac90ea31f65e`. Manifest90 SHA ثابت `7572547e1a3b8d0beac4abc997600e2cc35652274b779ba8ebe1e4ce7e082b1c`؛ payload 90/90 من W0. ملفات overlays ActorScope المنسوخة محفوظة داخل مجلد الأدوات الجديد، والأصل لم يعدل. لا checkpoint جديد.

## أعلام القرار

| العلم | القيمة |
|---|---|
| W0_FIVE_REPO_BASELINE / OWNER_APPROVED_CLAUDE_UNTOUCHED / RECOVERY_90_MANIFEST_UNCHANGED | PASS |
| A5_CREDENTIAL_MAPPING_SINGLE_LINE / G2_SOURCE_AUTH_GATE | PASS_SOURCE_SCOPED |
| A5_MISSING_CREDENTIAL_FAIL_CLOSED | PASS_SECURITY; HTTP_500_UX_GAP |
| SANDBOX_FRESH_SYSTEM_ID / SCRAM_FROM_INITDB / REAL_MIGRATIONS_38_OF_38 | PASS |
| A5_TRUSTED_MAPPING_AND_ACTIVE_MEMBER / A5_ADMIN_RBAC_SOURCE_AND_CATALOG | PASS_SANDBOX |
| ACTOR_DIRECT_AUTHORITY_WRITE_DENIED / ACTOR_SET_ROLE_FALSE_AND_NO_OLD_RUNTIME_MEMBERSHIP | PASS |
| SQL_ADMIN_GRANT_POSITIVE_AND_NEGATIVE / SQL_ADMIN_REVOKE_POSITIVE_AND_NEGATIVE | PASS_SANDBOX |
| SELF_GRANT_AND_INDIRECT_ESCALATION_DENIED / CAN_DELEGATE_SCOPE_RESTRICTION | PASS_SCOPED |
| AUDIT_ATOMIC_WITH_AUTH_VERSION_INCREMENT / INVARIANT_PRESERVED / FUNCTION_OWNER_SEARCH_PATH_PUBLIC_EXECUTE | PASS_SCOPED |
| HTTP_ADMIN_REAL_WIRE_OFF_ON_PARITY / DATA_FINGERPRINT_BEFORE_AFTER | PASS_SCOPED |
| HTTP_ROLE_ADMIN_FULL_PARITY | NOT_VERIFIED |
| LEADS_ACTOR_SCOPE_REGRESSION / TENANT_SQL_BOUNDARY_AFTER_ADMIN / NEGATIVE_MUTATION_CONTROLS | PASS_SCOPED |
| HTTP_SAME_WORKER_REUSE | NOT_VERIFIED |
| HISTORICAL_TESTS_REPLAY | BLOCKED_UNSAFE_TEST_TARGET |
| SOURCE_GIT_WRITES / MIGRATION_039 / RECOVERY_CHECKPOINT_CREATED | NONE / NOT_CREATED |
| F06_PRODUCT_REMEDIATION / PHP_MULTI_CREDENTIAL_COMPROMISE_RISK / T4B_REMEDIATION / F16_REMEDIATION | OPEN / OPEN / OPEN / OPEN |
| CUSTOMERS / PRODUCTION | NO_GO / NO_GO |
| EXECUTIVE_VERDICT | PASS_SCOPED_FOR_A5_DIRECT_GRANT_REVOKE |
| NEXT_GATE | Independent delta review؛ قرار منفصل بشأن 500 والفجوات ثم تفويض حفظ جديد إن لزم |

دليل الجولة: `tools/security/f06-team-role-admin-unblock-01/{ATTEMPT-LEDGER.md,g4_actor_evidence.json,g5_sql_evidence.json,http_admin_evidence.json,sql_scope_evidence.json,negative_mutation_evidence.json,DELTA-SHA256.tsv}`. `VERIFIED_RUNTIME` يخص هذه الملفات على Sandbox الحالية. نتائج ActorScope التاريخية `DOCUMENTED_PRIOR` فقط. مراجعة full team-role parity وsame-worker واختبارات الإنتاج `NOT_VERIFIED`. قرار الانتقال: مراجعة مستقلة للدلتا قبل أي recovery أو مرحلة تالية؛ لا تشغيل تلقائي.
