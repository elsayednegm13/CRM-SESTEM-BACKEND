# DB-VERIFY-01 — Engineering Verification & Cross-Tool Handoff

- الجلسة: 2026-10-23، Africa/Cairo (UTC+03:00)، نافذة الأدلة نحو 22:39–22:48.
- الأداة: Codex. الأدوار: QA/Security reviewer + Docs/handoff keeper.
- الحالة: **BLOCKED — NO-GO** لأي عمل يعتمد على صلاحيات/مخطط قاعدة التشغيل، ولتجاوز هذه البوابة إلى Customers.
- التفويض: قراءة المصدر وmetadata المحلية بعد إثبات الهوية، وكتابة هذا التقرير وSTATUS/PLAN/HANDOFF فقط. لا إصلاح ولا اختبارات كاتبة ولا migrations ولا branch/commit/push/deploy.
- التقرير ليس قبولًا أمنيًا شاملًا أو إثبات CRUD end-to-end.

## النتيجة الحاسمة

الحاوية المرئية `daleel-pg-scratch` تعمل بصورة `postgres:16` وتربط `127.0.0.1:55432` بالمنفذ الداخلي `5432`. لكنها لا تحتوي قاعدة `daleel_dev` التي تحددها أدوات المشروع. محاولة اتصال واحدة داخل الحاوية انتهت قبل تنفيذ أي SELECT:

```text
psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: FATAL:  database "daleel_dev" does not exist
```

توقف SQL عند هذا الحد حسب شرط STOP في التكليف. لم نخمن قاعدة بديلة ولم نتصل بقاعدة postgres للاستكشاف. لا دليل على خلو الحاوية من بيانات مهمة، ولا على نسختها الفعلية أو أدوارها أو منحها. اسم scratch والصورة والمنفذ لا يثبتون وحدهم أنها Disposable. لا يعني هذا الخطأ أن تطبيق CRM معطل؛ قد تستخدم الجلسة السابقة قاعدة أخرى غير المحددة في الأدوات.

## Baseline وNo-repeat gate

الجذر الحقيقي `I:\WORK\DALEEL-CRM` بلا `.git`. المستودعات الأربعة كانت نظيفة قبل العمل:

| المستودع | الفرع | HEAD |
|---|---|---|
| daleel-crm-api | phase-0-stabilize-baseline | d6870839f38b1f05786288071dbe0bb7719d5386 |
| daleel-crm | master | 6fb01b8838de52de621dab4691a5cdd5710c29f6 |
| daleel-crm-admin | master | 9fa43befadaaa5d4583f8de6bf7a06c60e891bef |
| daleel-crm-super-admin | master | a802e44b8a269071bcb46fcaa675aafb43b12a87 |

API HEAD يطابق المرجع d687083؛ آخر العناوين: Leads، إغلاق audit تعريف الأدوار، Staff/role CRUD. لم يظهر تقرير DB-VERIFY-01 أو ARCH-01 عند البحث في `docs` و`daleel-crm-api/docs`؛ لا ندعي البحث في كل أرشيف خارجي.

نسخ وثائق الجذر قبل التحديث (LastWriteTime UTC): STATUS 18:45:57، PLAN 18:46:04، HANDOFF 18:56:01، DECISIONS 16:18:31، كلها 2026-10-23. بصماتها ومقارنة الحفظ أدناه.

| التصنيف | المحتوى |
|---|---|
| منجز سابقًا | Phase 0 baseline، Phase 1، Staff/Roles وLeads من Phase 2 بحسب السجل الحالي؛ لم نعد تنفيذها |
| Known Deferred Gap | 33 skipped للبيئة/الأدوار، 9 حالات harness، OpenAPI متقادم؛ 82 Passed/124 تاريخي فقط؛ Leads CRUD غير audited بقرار مقصود |
| جديد يحتاج تحقق | اختلاف اسم قاعدة الهدف؛ كتالوج الأدوار والمنح الفعلية؛ مطابقة 36 migration؛ فرضية فجوة grants التشغيل |
| خارج النطاق | Customers، إصلاح code/SQL/env، إنشاء بيئة Acceptance، frontend wiring، تحديث API contract، نشر أو commit |

## سجل الأدلة والخطوات

التوقيت محلي Africa/Cairo، دقة النافذة بالدقائق وليست timestamps مختلقة لكل أمر. PASS هنا للخطوة المحددة فقط.

| ID | الوقت 2026-10-23 | الخطوة/الأمر المختصر | النتيجة والحالة | تكرار سابق |
|---|---|---|---|---|
| DBV-001 | 22:39–22:42 | Get-Location؛ قراءة AGENTS ثم STATUS/PLAN/DECISIONS/ARCHITECTURE/HANDOFF ثم مستندات API المطلوبة وأدوات dev-db بالترتيب | PASS baseline؛ حفظ التاريخ، لا إعادة تنفيذ | تحديث للسياق فقط |
| DBV-002 | 22:42 | git status --short / branch --show-current / log -3 لكل repo؛ بحث DB-VERIFY-01 | PASS؛ الأربعة نظيفة، المرجع مطابق، لا تقرير سابق في نطاق البحث | تحقق HEAD جديد |
| DBV-003 | 22:42–22:43 | docker ps -a --filter name=daleel-pg؛ inspect مفلتر للاسم/الصورة/الحالة/ports/Compose labels فقط | PASS mapping؛ running، health غير مهيأ، Compose project/service فارغان | تحقق snapshot حالي |
| DBV-004 | 22:43 | psql -X -w -U postgres -d daleel_dev داخل الحاوية؛ PGOPTIONS=-c default_transaction_read_only=on | BLOCKED؛ exit 1، قاعدة غير موجودة؛ صفر SELECT منفذ | جديد |
| DBV-005 | 22:43–22:46 | قراءة config/database.php والخدمات وroutes وcontexts | PASS static mapping فقط؛ هوية دور التطبيق الفعلية UNKNOWN | إعادة تحقق مصدر HEAD |
| DBV-006 | 22:43–22:46 | قراءة migrations 033/036 ومقاطع RLS 023–026؛ بحث GRANT وALTER DEFAULT PRIVILEGES | PASS مصدر فقط؛ صلاحيات حية ومطابقة migrations UNKNOWN | فرضية grants سابقة غير محسومة |
| DBV-007 | 22:44–22:46 | جرد tests ومحددات runtime/fixture/port، دون تشغيل | PASS جرد؛ التنفيذ NOT_RUN، A/B NOT_EXECUTED | Known Deferred Gap |
| DBV-008 | إغلاق الجلسة | مقارنة الوثائق وgit status/diff بعد الكتابة | تحقق محصور بالتوثيق؛ التفاصيل في سجل الإغلاق أدناه | جديد |

STEP A مكتمل ضمن النطاق. STEP B محجوب عند اسم DB. STEP C بالكامل BLOCKED؛ لا inventory ولا ownership ولا ACL. STEP D/E مراجعة مصدر جزئية فقط، التنفيذ والكتالوج BLOCKED. STEP F جرد وخطة فقط، اختبارات NOT_RUN.

أمر DBV-004 طلب SELECT لهوية الاتصال/الإصدار وpg_database وpg_stat_user_tables (أسماء وتقديرات أعداد فقط)، لكن فشل فتح القاعدة منعها جميعًا. لم تُقرأ صفوف أعمال أو أسرار. المنفذ 5432 في رسالة الخطأ socket داخل الحاوية، وليس listener المضيف المحظور.

Compose الرسمي يسمي الحاوية `daleel-pg`، لا `daleel-pg-scratch`. غياب Compose labels يدعم أنها ليست الحاوية المدارة بهذا التعريف، لكنه لا يثبت تاريخ إنشائها أو disposable provenance. لا تعديل لمحاولة فرض التطابق.

## Schema وmigration drift

المصدر يحتوي **36 ملف migration**. سجل migrations الحي لم يُقرأ؛ applied/missing/extra وكل schema drift = UNKNOWN. لا استنتاج أن 36 مطبقة من عدد الملفات.

المصدر 036: UUID PK، tenant FK وFK مركبان للعضو المنشئ والمسند إليه، ثلاثة indexes تبدأ بـtenant_id، CHECKs للاسم والبريد والمرحلة والاهتمام والحالة، ENABLE+FORCE RLS وسياسات SELECT/INSERT/UPDATE/DELETE، REVOKE PUBLIC. المصدر 033: plans/plan_limits global بلا RLS عمدًا؛ subscription/overrides مع FORCE وسياسات tenant SELECT وprovider scoped، unique active subscription وtenant/key overrides. وجودها في الحاوية غير مثبت.

## مصفوفة العقود والمنح

S=SELECT، I=INSERT، U=UPDATE، D=DELETE. كل الأدوار المذكورة **mapping في api-env.example.sh فقط**؛ effective login وmembership وinheritance في التطبيق الحي UNKNOWN. لا مساواة بين group وlogin. الحقوق أدناه متطلبات المصدر الأساسية وليست مصفوفة صلاحيات حية مكتملة.

| resource/table | connection config | effective DB role | operation/service | needed rights | granted rights | RLS FORCE / tenant policy (source فقط) | evidence | verdict |
|---|---|---|---|---|---|---|---|---|
| leads | pgsql_tenant_runtime / TENANT_RUNTIME_DB_* | UNKNOWN؛ مثال dl_truntime | LeadService list/create/edit/archive | S/I/U؛ archive UPDATE؛ لا يحتاج D في مسار الخدمة الحالي | live UNKNOWN؛ لا GRANT في 036/bootstrap | FORCE؛ TENANT + tenant_id، 4 عمليات | DBV-005/006 | UNKNOWN live |
| tenant_staff_users | pgsql_tenant_runtime | UNKNOWN؛ مثال dl_truntime | Staff create/list | S/I؛ تغطية أعمدة العرض والإنشاء | live UNKNOWN؛ 026 يمنح S لأعمدة محددة فقط | FORCE؛ tenant/actor | DBV-005/006 | فجوة مصدر محتملة |
| tenant_staff_memberships | pgsql_tenant_runtime | UNKNOWN | Staff create/disable/reactivate وlocks | S/I/U | live UNKNOWN؛ 026 S محدود | FORCE؛ tenant/actor | DBV-005/006 | UNKNOWN |
| roles | pgsql_tenant_runtime | UNKNOWN | create/edit/archive وlock | S/I/U ومنها version | live UNKNOWN؛ 026 S لا يشمل version | FORCE؛ tenant scope | DBV-005/006 | فجوة مصدر محتملة |
| role_permissions | pgsql_tenant_runtime | UNKNOWN | replace grants | S/I/D | live UNKNOWN؛ 026 S محدود | FORCE؛ tenant scope | DBV-005/006 | UNKNOWN |
| tenant_staff_membership_roles | pgsql_tenant_runtime | UNKNOWN | assign/revoke | S/I/U | live UNKNOWN؛ 026 S محدود | FORCE؛ actor scope | DBV-005/006 | UNKNOWN |
| tenant_staff_permission_grants | pgsql_tenant_runtime | UNKNOWN | grant/revoke | S/I/U | live UNKNOWN؛ 026 S محدود | FORCE؛ actor scope | DBV-005/006 | UNKNOWN |
| permissions | pgsql_tenant_runtime | UNKNOWN | authorization/delegation catalog | S على الأعمدة المستخدمة | live UNKNOWN؛ 026 column S | global | DBV-005/006 | UNKNOWN |
| tenant_staff_security_events | pgsql_tenant_runtime | UNKNOWN | TenantStaffAuditWriter | I | live UNKNOWN | FORCE؛ tenant/actor؛ append-only source contract | DBV-005/006 | UNKNOWN |
| plans / plan_limits | pgsql_provider / PROVIDER_DB_* | UNKNOWN؛ مثال dl_provider | PlanCatalogService list/create/edit/upsert | S/I/U | live UNKNOWN؛ لا grants لهما في bootstrap/033 | global بلا RLS عمدًا | DBV-005/006 | فجوة مصدر محتملة |
| tenant_subscriptions | pgsql_provider | UNKNOWN | assign/cancel/get | S/I/U | live UNKNOWN | FORCE؛ provider capability + target tenant؛ tenant S | DBV-005/006 | UNKNOWN |
| tenant_limit_overrides | pgsql_provider | UNKNOWN | upsert/remove/get | S/I/U/D | live UNKNOWN | FORCE؛ provider capability + target tenant؛ tenant S | DBV-005/006 | UNKNOWN |
| security_audit_events | pgsql_provider | UNKNOWN | provider mutation audit | I | bootstrap I إلى dl_provider؛ live UNKNOWN | FORCE حسب العقد؛ provider insert | DBV-005/006 | لا دليل تنفيذ |
| provider_users / provider_user_capabilities / provider_capabilities | pgsql_provider | UNKNOWN | team/auth/authorization | حسب الخدمة S/I/U؛ capabilities assignment D | bootstrap: users S/I/U؛ assignments S/I/D؛ catalog S؛ live UNKNOWN | بلا RLS عمدًا، ACL + capability/step-up | DBV-001/005 | UNKNOWN |
| sequences | حسب الاتصال والـdefaults | UNKNOWN | generated IDs عند وجود sequence | USAGE/SELECT بحسب الاستخدام | bootstrap USAGE/SELECT all sequences إلى dl_provider؛ live UNKNOWN | N/A | DBV-001 | inventory مطلوب |
| hostname registry / auth lookup | pgsql_hostname_resolver / pgsql_tenant_auth | UNKNOWN؛ أمثلة dl_host / dl_tauth | host lookup / credential function | scoped read / EXECUTE فقط | source groups منفصلة؛ live UNKNOWN | سياسات host exact/function boundary | DBV-001/005/006 | UNKNOWN live |
| provider control resources | pgsql_provider_control / PROVIDER_CONTROL_DB_* | UNKNOWN؛ مثال dl_provider_ctl | provisioning/lifecycle | column/function/operation-specific؛ inventory مؤجل | membership المثال: registry_writer + first_admin_writer؛ live UNKNOWN | policies مقيدة بالعملية | DBV-001/005 | BLOCKED full reconciliation |

لا has_table_privilege أو has_column_privilege أو has_schema_privilege نُفذت. لا role flags أو owners أو schema CREATE أو default ACL أو function EXECUTE جرى إثباتها. فرضية grants لا تزال مصدرية؛ إثبات configuration drift يتطلب العثور على منح حية إضافية أولًا. bootstrap يمزج إنشاء roles قبل migrations مع GRANTs لجداول بعد إنشائها؛ هذا خطر ترتيب إعادة تجهيز بالمصدر، وليس تجربة فاشلة نفذناها.

## RLS وتغطية A/B

- Static: host مشتق من Request::getHost عبر ResolveTenantHost/TenantHostResolver؛ شركة session يجب أن تطابق host. TenantStaffRequestContext يفتح transaction على pgsql_tenant_runtime ويصفر GUCs؛ TenantStaffContextGuard يربط TENANT/tenant/user ويعيد فحص الحالة والإصدارات. الخدمات المختارة تستخدم named connection.
- Static: LeadService يضيف tenant WHERE وASSIGNED/SELF checks؛ سياسات 036 tenant فقط، ليست بديل RBAC. غياب TENANT/context المطابق لا يحقق predicate في تعريف المصدر؛ fail-closed الفعلي لم يُختبر.
- Static: ProviderDatabaseContext يستخدم pgsql_provider ويصفر context ويدعم target tenant؛ provider realm مستقل. globals لا تُصنف خلل RLS لمجرد غيابها.
- Live catalog: owner/non-owner، rolbypassrls، rolsuper، rolinherit، memberships، ENABLE/FORCE والسياسات جميعها UNKNOWN.
- Runtime A/B وno-context وpool reuse: **NOT_EXECUTED**؛ لا fixture ولا SET ROLE ولا تبديل GUC أُجري.
- default connection: config يرجع إلى pgsql وport 5432 عند غياب env؛ لم نستخدمه. بعض مسارات SecurityAuditWriter القديمة تستخدم default، بينما staff/provider writers المختارة مسماة. صلاحية default الفعلية غير معروفة؛ استخدام migration-owner فيها خطر مشروط وليس bypass مثبتًا في هذا التطبيق.

## Test readiness

الاختبارات المنفذة بهذه الجلسة: **0**. لا artisan ولا test suite ولا migration. فحص اتصال واحد فشل قبل SQL، وليس اختبار قبول.

| مجموعة | المتطلبات | الحالة |
|---|---|---|
| PostgresRlsIsolationTest / SecurityAuditRuntimeRoleTest / ProviderRuntimeRoleTest / ProviderConcurrencyTest | RLS_TEST_RUNTIME_* / AUDIT_TEST_RUNTIME_* / PROVIDER_TEST_RUNTIME_*، owner مقابل non-owner fixtures | NOT_RUN |
| TenantStaffAuthenticationPostgresTest / TenantStaffRlsContextTest / TenantStaffAuthorizationTest | target وfixture identities المخصصة | NOT_RUN |
| TenantIsolationTest / TenantRbacTest | قاعدة اختبار مع fixtures/RefreshDatabase حسب harness | NOT_RUN |
| ProviderDirectProvisioningTest / ProviderProvisionEditReasonHistoryTest | target pinned وserver port داخلي 5432 | NOT_RUN |
| Eng03DisposableFixtureTest / Eng06CompanyContextAuthorizationTest | HTTP + DNS + /fixture secret files | NOT_RUN |

82 passed / 33 skipped / 9 غير ناجحة من 124 أرقام تاريخية في STATUS وليست نتائج اليوم. حتى تفسير skipped ليس موحدًا تمامًا: TenantIsolationTest يحتوي skip مقصودًا لمسار legacy الملغى؛ لذا لا وعد بأن env وحده سيجعل كل 33 تعمل. بناء acceptance runner مستقل يحتاج تفويضًا لاحقًا؛ لا تخفيف للـguards.

## Risk register وImpact

| ID | أولوية/ثقة | الدليل | الأثر والتصرف |
|---|---|---|---|
| R1 | P1، عالية لاختلاف الهدف | DBV-003/004؛ compose/api-env | daleel_dev غير موجودة؛ لا يمكن اعتماد schema/grants؛ تحديد قاعدة disposable الصحيحة قبل SQL |
| R2 | P1، عالية للمصدر فقط؛ live UNKNOWN | DBV-005/006؛ migration 026:229–236، migrations 033/036، bootstrap، خدمات CRUD | إعادة تجهيز البيئة قد تفتقد حقوق CRUD/column reads؛ طابق الكتالوج قبل أي إصلاح |
| R3 | P2، عالية | DBV-001؛ STATUS وLOCAL_DEVELOPMENT وPROVIDER_SECURITY ووثائق staff التاريخية مقابل routes | نصوص no business tables/no CRUD قد تضلل الجلسة التالية؛ هذا checkpoint يتقدم عليها دون محوها |
| R4 | P2، عالية للمصدر | bootstrap-roles.sql وتعليمات تشغيله قبل migrations | grants إلى جداول غير منشأة بعد قد تعوق إعادة إنتاج نظيفة؛ خطة provisioning منفصلة لاحقًا |

لا P0 مثبت. لا أثر runtime متوقع من هذه التغييرات لأنها توثيق فقط؛ الخطر المتبقي أن تُفهم المراجعة المصدرية كقبول DB. جميع توصيات العلاج غير ملزمة ولم تتحول إلى ADR.

## Change ledger — المصادر والكتابات

مصادر قرئت لقرار مادي (قراءة كاملة أو المقاطع المحددة/البحث، وليست دعوى تدقيق شامل لكل سطر):

- الجذر: AGENTS.md؛ docs/STATUS.md، PLAN.md، DECISIONS.md، ARCHITECTURE.md، HANDOFF.md: حدود التفويض، baseline، مراحل وقرارات D-1…D-11.
- API: AGENTS.md؛ docs/LOCAL_DEVELOPMENT.md، RLS_ARCHITECTURE.md، SECURITY_BASELINE.md، PROVIDER_SECURITY.md، TENANT_STAFF_AUTHENTICATION.md، TENANT_STAFF_IDENTITY_AND_RBAC_FOUNDATION.md: حدود الأدوار وRLS والتاريخ.
- tools/dev-db/docker-compose.yml، bootstrap-roles.sql، api-env.example.sh: identity والـmapping ومنح المصدر؛ خطوط credentials حجبت من العرض.
- API config/database.php وroutes/api.php: named connections وعقد المسارات فقط.
- app/Modules/Tenancy/Application/LeadService.php؛ app/Modules/Provider/Application/PlanCatalogService.php وTenantSubscriptionService.php؛ app/Modules/Provider/Infrastructure/Persistence/ProviderDatabaseContext.php: عمليات SQL المطلوبة والسياقات.
- app/Modules/Identity/Http/Middleware/ResolveTenantHost.php وTenantStaffRequestContext.php؛ app/Modules/Identity/Application/TenantHostResolver.php وTenantStaffContextGuard.php: host/session/GUC boundary.
- مقاطع TenantStaffAccountService.php، TenantStaffRoleMutationService.php، TenantStaffAuthorizationService.php، TenantStaffEffectiveAuthorizationService.php ضمن Identity/Application؛ TenantStaffAuditWriter.php وSecurityAuditWriter.php ضمن Shared/Audit: عمليات/جداول واتصالات.
- database/migrations/2026_10_23_000033_add_plans_and_entitlements.php و2026_10_23_000036_create_leads.php؛ مقاطع 000014_guard_tenant_rls_helper_context، 000023_create_tenant_staff_users، 000024_create_tenant_staff_membership_access، 000025_create_tenant_staff_recovery_audit، 000026_create_tenant_staff_authentication_access؛ بحث grants/policies بباقي migrations: متطلبات المصدر لا schema حي.
- tests المشار إليها في جدول readiness وtests/Support/Eng06CompanyHttpClient.php: قراءة guards/env/fixtures فقط.

الكتابات المصرح بها: إنشاء docs/audits/DB-VERIFY-01.md داخل API؛ إضافة checkpoint إلى root STATUS/HANDOFF وبوابة إلى PLAN. لا DECISIONS: لا قرار مالك جديد أثناء الجلسة. لا openapi أو ملفات code/config/env/SQL/tests/frontends.

## Acceptance والقرار وخطة الاستئناف

| شرط | الحالة |
|---|---|
| هوية DB آمنة ومثبتة ولا بيانات مهمة | BLOCKED |
| مطابقة schema/migrations | BLOCKED |
| إثبات privileges أو تعيين النقص بدقة حية | BLOCKED؛ المتطلبات المصدرية فقط موثقة |
| RLS/ownership بأدلة حية وتحديد الاختبارات الغائبة | PARTIAL source؛ live BLOCKED؛ الاختبارات معلنة |
| عدم تعديل DB/code أو تشغيل اختبارات مؤثرة | PASS |
| التقرير وSTATUS/PLAN/HANDOFF متسقة | تحقق الإغلاق أدناه |
| تغييرات Git محصورة بالتوثيق | تحقق الإغلاق أدناه |

**VERIFICATION = BLOCKED؛ NO-GO لتجاوز البوابة أو تنفيذ Customers/إصلاحات.** إنجاز تقرير الحجب لا يساوي اكتمال التحقق.

الخطوة التالية الوحيدة: يحدد المالك **اسم قاعدة التطوير disposable الفعلي داخل daleel-pg-scratch مع تأكيد أنها ليست قاعدة مهمة وهوية login الفحص**، أو يوفر مرجع إعداد محلي موثوق يثبت ذلك؛ لا حاجة لإرسال كلمة مرور في المحادثة. سبب طلب هذه المعلومة هو شرط STOP بهوية DB في التكليف، وليس إجراء موافقة إضافيًا مفترضًا. بعد إثباتها، تستأنف قراءة الكتالوج تحت التفويض الحالي، مع recheck مختصر لـHEAD/container عند تغير الجلسة.

عند فك الحجب: SELECT للهوية والإصدار ثم metadata/aggregates الآمنة، migration repository مقابل 36 ملفًا، pg_roles/pg_auth_members/pg_class/pg_policies/pg_constraint/pg_indexes/pg_default_acl وhas_*_privilege لكل login ولكل عمود مستخدم. لا قراءة pg_authid أو business rows. بعدها تصنيف drift وتحديث نفس Evidence IDs بسجل جلسة إضافي.

طلب تفويض مستقل مؤجل: إنشاء Acceptance stack جديدة معزولة بأسماء/volume/port محددة، migrations وfixtures اصطناعية واختبارات A/B/no-context/CRUD/raw-SQL تحت non-owner roles؛ لا يجوز استخدام الحاوية الحالية لهذا الغرض ضمن هذه المهمة. الإصلاحات وCustomers وcommit تحتاج قرارات منفصلة.

Handoff checkpoint: آخر خطوة = مراجعة مصدر وتوثيق حجب identity؛ التالية فقط = تحديد الهدف الصحيح. ممنوع إعادة تنفيذ Phase 0/1/Staff/Leads أو bootstrap/migrate/test على الحاوية الحالية أو اعتبار نتائج 82/124 حديثة. أسئلة مفتوحة: DB name/provenance، login الفعلي، owners/grants/inheritance، migration/policy drift. root docs خارج Git ويجب حفظها/نقلها بآلية مشاركة المشروع المعتمدة؛ لم تُرفع تلقائيًا.


## DBV-008 — إغلاق وثائقي ومقارنة قبل/بعد

| ملف الجذر | SHA256 قبل | SHA256 بعد | المقارنة |
|---|---|---|---|
| docs/STATUS.md | C05198913D73B8C92994F53B3EF285C3E65F880997B71A3FCCED6336F7BC73CE | 2E6B6C9562C87C522953763A85EDCD1F9F2F74AECAD3B2859EB7CC53F89474FD | original bytes preserved; appended 1628 bytes |
| docs/PLAN.md | EA2546586419936AACD6AD5C70BF60EF819357F1DEC6D65CFC1EE054DFC59852 | 852FF949A6EF87A5A56AFC7BC961B3A51B02A71698106BE35C8123019A8CD464 | original bytes preserved; appended 1014 bytes |
| docs/HANDOFF.md | 34DFACD429A05611E1C0E1D90948724F320A07DF5249A67561E37C5E6146E9E5 | 089826F631E43DF865FBC4DAE4A5A065C5CABFF1F33E2FDFCAA79ED6C9753503 | original bytes preserved; appended 1690 bytes |

تحقق الإغلاق: git status --short --untracked-files=all داخل API يعرض فقط `?? docs/audits/DB-VERIFY-01.md`؛ git diff --stat للملفات tracked فارغ لأن التقرير جديد untracked. الواجهات الثلاث git status فارغة. لم يتغير HEAD/branch ولم يحدث staging أو commit. ملفات الجذر الثلاثة أضيفت إليها أقسام فقط، والمقارنة الثنائية أعلاه أثبتت بقاء كل بايت سابق. STATUS/PLAN/HANDOFF والتقرير تستخدم BLOCKED/NO-GO ونفس خطوة تحديد DB؛ وثائق الجذر ليست ضمن Git. بنود سلامة الكتابة واتساق التسليم PASS؛ بنود قبول DB تظل BLOCKED.
## DB-VERIFY-01 / CONTINUATION — Live Database Discovery & Docker Log Review

التوقيت: 2026-10-23 23:18:40 +03:00 Africa/Cairo؛ Codex؛ قراءة وتوثيق فقط. تصنيف اكتشاف الهوية: **IDENTITY_DISCOVERED_PENDING_OWNER**. بوابة DB-VERIFY-01: **BLOCKED / NO-GO**.

- DBV-CONT-001 FACT: قرئت ملفات الحوكمة والتقرير السابق بالترتيب. الجذر I:\WORK\DALEEL-CRM خارج Git. API HEAD d6870839f38b1f05786288071dbe0bb7719d5386؛ الواجهات: 6fb01b8838de52de621dab4691a5cdd5710c29f6، 9fa43befadaaa5d4583f8de6bf7a06c60e891bef، a802e44b8a269071bcb46fcaa675aafb43b12a87. Git قبل: API ?? docs/audits/؛ الثلاثة الأخرى نظيفة. أمر: git rev-parse HEAD وgit status --short لكل repo.
- DBV-CONT-002 FACT: docker ps -a --filter name=daleel-pg وdocker inspect بحقوله المنتقاة: ID b05a2967dfcb، daleel-pg-scratch، postgres:16، running، 127.0.0.1:55432→5432، mount نوع volume إلى /var/lib/postgresql/data؛ Compose project/service labels فارغة. لا حاوية daleel-pg ثانية في المرشح. تعريف Compose الرسمي يسمي الحاوية daleel-pg؛ الاختلاف لا يثبت طبيعة scratch.
- DBV-CONT-003 FACT: اتصال واحد postgres/postgres داخل الحاوية، PGOPTIONS default_transaction_read_only=on، psql -X -w -v ON_ERROR_STOP=1؛ SELECT datname,pg_get_userbyid(datdba) FROM pg_catalog.pg_database WHERE datallowconn AND NOT datistemplate. النتيجة: daleel_scratch/postgres وpostgres/postgres؛ daleel_dev غير موجودة. لم يُستعلم عن أي مرشح بعد ذلك.
- DBV-CONT-004 OWNER_STATEMENT: القاعدة القديمة daleel_dev حذفت وكانت فارغة؛ لا حاجة لاستعادتها. لا تعميم على daleel_scratch الحالية. المرشح الأخير غير مثبت الهوية أو خلوه من بيانات مهمة؛ STOP قبل catalogs الخاصة به. تصنيف عدم وجود DB مشروع مؤكدة: UNKNOWN؛ غياب daleel_dev وحده ليس regression.
- DBV-CONT-005 HISTORICAL: docker logs --timestamps --tail 500 مع ترشيح أسماء الأخطاء فقط (لا DETAIL/UUID/values). عند 2026-10-23 18:45:28.886Z ظهر membership_roles_pkey: تكرار مفتاح أثناء عملية سابقة. عند 18:45:28.894Z ظهر role_permissions_scope_check: scope مرفوض بقيد. أخطاء current transaction is aborted تكررت بين 18:44:53Z و18:45:28Z، وهي تبعات معاملة أُجهضت وليست جذر المشكلة بالضرورة. عند 19:44:17.183Z ظهر غياب daleel_dev. لا تثبت logs استمرار خلل حالي؛ لم يُعد إنتاجها. UTC +3 للقاهرة بتاريخ الجلسة.

| محور | LIVE الآن | STATIC/تاريخي | حالة |
|---|---|---|---|
| databases | postgres وdaleel_scratch فقط؛ كلاهما owner postgres | daleel_dev كان اسم أدوات dev-db | VERIFIED للأسماء، هوية المشروع BLOCKED |
| migrations | لا قراءة لجدول migrations | 36 ملف مصدر بالتقرير السابق | BLOCKED |
| roles/grants | لا pg_roles أو ACL في المرشح | فجوة منح محتملة بالمصدر في التقرير السابق | BLOCKED؛ لا LIVE_PERMISSION_DENIED |
| RLS/ownership | لا قراءة جداول أو policies | تعريف FORCE والسياسات بالمصدر فقط | BLOCKED؛ A/B NOT_EXECUTED |

Finding F1: P1، ثقة عالية في الجرد ومتوسطة في ربطه بالمشروع: قاعدة مرشحة غير معتمدة؛ فحصها العميق قد يمس بيئة غير مقصودة. F2: P2، ثقة عالية في توقيت logs ومنخفضة في انطباقها الآن: أخطاء constraint تاريخية تحتاج تفسيرًا في بيئة Acceptance مستقلة لاحقًا. F3: P1، ثقة مصدرية فقط: فرضية GRANTs باقية بلا catalog. لا إصلاح نُفذ. الاختبارات الجديدة=0؛ migrations/seed/fixtures/A-B/Customers لم تُنفذ.

الخطوة الواحدة للمالك: تقديم دليل غير سري يربط daleel_scratch الحالية بمشروع DALEEL-CRM ويحدد هل يجوز فحص metadata فيها رغم احتمال بيانات فعلية. شرط STOP: غياب الرابط أو وجود بيئة مشتركة/حساسة. معيار الاستئناف: تطابق الاسم مع إعداد محلي موثوق وملكية البيئة، ثم metadata SELECT فقط بتفويض جديد محدد. لا كلمات مرور في المحادثة.

تغييرات هذه الجلسة محصورة بملحق هذا التقرير وSTATUS/PLAN/HANDOFF؛ docs/DECISIONS.md وcode وDB وواجهات وOpenAPI دون تعديل. اقرأ الملحق قبل أي استئناف؛ لا تكرر الجرد إلا إذا تغيرت الحاوية. root docs خارج Git وتحتاج حفظًا بآلية مشاركة المشروع.

## DB-VERIFY-01 / RESUME-02 — Full Local Env & DB Audit (2026-10-23 23:30 +03:00)

Scope: Codex (QA/Security reviewer, Docs/handoff keeper). قراءة محلية وSQL catalog بمعاملة READ ONLY وstatement_timeout=5s؛ لا كتابة DB/container/code، ولا tests/migrations/fixtures. تفويض قراءة أسرار DEV محليًا لا يجيز نشر قيمها أو الاتصال بخدمات خارجية. هذا DELTA عن DBV-CONT-001..005.

### Evidence index

| ID | التصنيف | المصدر والنتيجة |
|---|---|---|
| DBV-R02-001 | VERIFIED_SOURCE، ثقة عالية | 23:28 +03؛ governance/AGENTS/التقرير السابق وGit: API HEAD d6870839f38b1f05786288071dbe0bb7719d5386؛ الواجهات HEAD بلا تغير؛ API status قبل `?? docs/audits/DB-VERIFY-01.md`، الواجهات نظيفة. |
| DBV-R02-002 | VERIFIED_SOURCE، عالية | 23:28–23:29؛ قراءة نصية منقحة لـ`.env`/`.env.example`/`phpunit.xml`/`config/database.php`/`tools/dev-db/*`؛ API `.env` يحدد `daleel_crm_api` على host 5432 باسم مستخدم placeholder؛ ليس هدف الفحص المسموح ولا دليل تشغيل. Compose وscript يحددان `daleel_dev` على 55432؛ غائبة. لا config cache. |
| DBV-R02-003 | VERIFIED_LIVE، عالية | Docker metadata: b05a2967dfcb، `daleel-pg-scratch`، postgres:16، running، 127.0.0.1:55432→5432، volume إلى `/var/lib/postgresql/data`، لا Compose labels ولا حاوية `daleel-pg` ثانية. |
| DBV-R02-004 | VERIFIED_LIVE، عالية | `docker exec` داخل scratch إلى `daleel_scratch` بحساب الصيانة postgres؛ `PGOPTIONS=default_transaction_read_only=on`، `psql -X -w -v ON_ERROR_STOP=1`، `BEGIN READ ONLY; SET LOCAL statement_timeout='5s'`؛ PostgreSQL 16.15، 36 جدولًا، sequence واحدة، 18 جدولًا ENABLE+FORCE RLS. |
| DBV-R02-005 | VERIFIED_LIVE، عالية | `SELECT migration,batch FROM public.migrations` وCompare-Object مع أسماء ملفات المصدر: 36/36 في batch 1، missing=0، extra=0؛ لا إثبات سلامة تنفيذ DDL أو التطبيق. |
| DBV-R02-006 | VERIFIED_LIVE، عالية | `pg_roles`, `pg_auth_members`, `pg_policies`, `pg_stat_user_tables`: ستة `dl_*` LOGIN بلا SUPERUSER/BYPASSRLS؛ ستة `daleel_*` NOLOGIN؛ 94 سياسة؛ `n_live_tup` تقريبي: جداول أعمال/هوية 0 والمرجعية غير صفرية. لا business rows قُرئت. |
| DBV-R02-007 | VERIFIED_LIVE، عالية | `has_table_privilege` عبر 36 جدولًا و`has_schema_privilege`: dl_host SELECT على جدولين؛ dl_provider_ctl SELECT على جدولين وINSERT على واحد؛ dl_onboarding/dl_provider/dl_tauth/dl_truntime صفر امتيازات جدولية فعالة. schema USAGE للجميع. لم يجر login بهذه الأدوار. |
| DBV-R02-008 | HISTORICAL، متوسطة | DBV-CONT-005 logs: constraint/transaction errors 18:44–18:45Z؛ missing daleel_dev 19:44Z. لم تُعد الإنتاج. |

### Config and static-versus-live

| Component | source | target / role / state |
|---|---|---|
| API default | `.env`, `config/database.php` | `daleel_crm_api`, 127.0.0.1:5432، username placeholder وpassword موجودة دون كشفها؛ CONFIGURED فقط ومتعارض مع D-11؛ لم يُستخدم 5432. |
| Named provider/control/onboarding/host/auth/runtime | `config/database.php` | بعض host/port/name يرث الافتراضي وبعضها يتطلب متغيرات منفصلة؛ المقابلة غائبة من `.env`؛ NOT_VERIFIED. |
| Official dev-db | Compose وapi-env script | `daleel_dev`, 127.0.0.1:55432، أسماء dl_*؛ CONFIGURED، القاعدة والحاوية الرسمية غائبتان. |
| Scratch | Docker/catalog | `daleel_scratch` داخل الحاوية؛ postgres maintenance فقط CONNECTIVITY_VERIFIED؛ لا Laravel runtime proof. |
| Tests | `phpunit.xml` | DB_CONNECTION=pgsql، DB_URL فارغ؛ cache=array/queue=sync/session=array؛ TEST_ONLY، 0 tests. |
| Frontends | `.env*`/`.npmrc` scan | لا ملفات محلية ظاهرة؛ runtime غير مختبر. |

PHP الحالي 8.6.0RC3 عبر Herd، Composer 2.10.3، Node 24.22.1، Docker 29.9.2؛ وثيقة LOCAL_DEVELOPMENT التاريخية تذكر PHP 8.4.26 المختبر. لا `bootstrap/cache/config.php`. عدم وجود cache لا يثبت متغيرات عملية خادم آخر. لم تُشغّل hooks أو Artisan.

| محور | LIVE | حد الاستنتاج |
|---|---|---|
| DB identity | 36 migration names، جداول leads/staff/subscriptions، أدوار dl_* | PROJECT_DB_CONFIRMED كبصمة DALEEL-CRM محلية؛ لا اعتمادها runtime target أو disposable. |
| Migration parity | 36/36 names، batch 1، 36 جدولًا | PASS_METADATA للأسماء فقط؛ DDL/behavior غير مثبتين. |
| Data | pg_stat_user_tables تقريبي: أعمال/هوية 0؛ المرجعية غير صفرية | ليست DB فارغة؛ الإحصاء ليس COUNT ولا برهان خلو. |
| Grants | login roles غير BYPASSRLS؛ منح فعالة ضئيلة | LIVE_GRANT_MISSING لعمليات الجداول المفحوصة؛ function/sequence/column grants لم تُستنفد. |
| RLS | 18/36 ENABLE+FORCE، 94 policies، owner postgres | POLICY_PRESENT؛ USING/WITH CHECK غير مطابقة تفصيليًا؛ TENANT_ISOLATION_NOT_PROVEN. |

`dl_provider` بلا SELECT/INSERT/UPDATE على `provider_users` رغم طلب bootstrap لها، و`dl_truntime` بلا SELECT/INSERT/UPDATE/DELETE على `leads`؛ فجوة grants حية للأدوار التي يسميها script. سبب حدوثها غير مثبت. postgres superuser/owner لا يثبت RLS للـnon-owner. لم يُختبر login للأدوار ولا اتصال Laravel ولا A/B. volume لا يوصف disposable اعتمادًا على `n_live_tup=0`.

### Logs, risks, options, gate

`membership_roles_pkey` و`role_permissions_scope_check`: HISTORICAL_ONLY؛ أولها تعارض مفتاح والثاني scope مرفوض بقيد. `current transaction is aborted`: تابع لفشل معاملة سابق ولا يحدد الجذر. `daleel_dev does not exist`: HISTORICAL_ONLY ومتسق مع الجرد الحالي. جميعها NEEDS_REPRODUCTION في بيئة قبول منفصلة قبل نسبتها لكود حالي؛ لا DETAIL/UUID نُقل.

Findings: F-R02-1 P1/ثقة عالية: grants runtime شبه غائبة (DBV-R02-007)، قد تمنع CRUD إذا استُخدمت scratch؛ تحتاج تفويض إصلاح بعد تثبيت الهدف. F-R02-2 P1/عالية: `.env` يشير إلى host 5432 المحظور وDB مختلف (DBV-R02-002)، خطر توجيه خاطئ. F-R02-3 P1/عالية للحد: وجود السياسات ليس إثبات A/B (DBV-R02-004/006). F-R02-4 P2/متوسطة: logs تاريخية (DBV-R02-008).

Options للمالك: A اعتماد scratch بعد تثبيت ملكيتها وحماية volume وتصحيح config/grants واختبارات؛ خطر بيانات حالية غير مصنفة. B بيئة dev جديدة معزولة بتفويض مستقل؛ تحافظ على scratch وتحتاج وقت تجهيز. C حسم ENV/roles أولًا دون DB writes؛ آمن تحضيريًا ولا يمنح GO. **الخطوة الواحدة الموصى بها:** قرار المالك A أو B؛ نرجح B لقبول قابل لإعادة الإنتاج دون مساس scratch، مع تفويض جديد محدد وSTOP عند تضارب port/volume أو بيانات غير مصنفة، ومعايير قبول migration parity وnon-owner grants وA/B. لا خيار نُفذ هنا.

Inspection matrix: Docker/identity PASS_METADATA؛ config PARTIAL؛ migration names PASS_METADATA؛ grants PARTIAL مع gap حي؛ RLS PARTIAL؛ runtime login/A-B/tests NOT_EXECUTED؛ DB writes NOT_EXECUTED. ENV_DISCOVERY=ENV_PARTIALLY_IDENTIFIED؛ DB_TARGET=PROJECT_DB_CONFIRMED لبصمة المخطط فقط؛ DB-VERIFY-01=BLOCKED/NO-GO. الاختبارات الجديدة 0؛ لا migration/seed/fixtures/Customers. docs الجذر خارج Git ويحتاج حفظًا مستقلًا. أول استئناف: اقرأ هذا الملحق وLatest checkpoint؛ لا تكرر Phase 0/1/Leads ولا تستخدم host 5432. لا قرار معماري جديد ولا تعديل DECISIONS.
