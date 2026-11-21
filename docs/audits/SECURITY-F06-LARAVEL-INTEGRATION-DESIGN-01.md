# SECURITY-F06-LARAVEL-INTEGRATION-DESIGN-01

وثيقة تصميم هندسي تنفيذي — ربط Laravel الحقيقي بمرساة SQL غير قابلة للانتحال لإغلاق F06.
هذه وثيقة **تصميم فقط**؛ لا كود تنفيذي، لا migration، لا تعديل منتج، لا اتصال بأي بيئة محمية.

---

## (أ) الحكم التنفيذي

**`PASS_DESIGN_SCOPED`**

الأسباب المبنية على الأدلة:
- خط الأساس (Git) الخماسي مطابق تمامًا لما أبلغه المالك؛ لا drift حقيقي (انظر الفرق الطفيف المُفسَّر في §ب).
- مرجع POC (الدلتا المقبولة `f06-poc04-proof-closeout/`) مطابق بصمةً لِما ورد في التكليف — `run_tests.sh` و`003_comparison.sql` كليهما بصمتهما مطابقة حرفيًا.
- تتبّع مسار HTTP→SQL الحقيقي في Laravel **اكتمل بالمصدر الفعلي** (لا تخمين) وحدَّد **بدقة موضع الثغرة**: اعتماد SQL واحد مشترك (`TENANT_RUNTIME_DB_USERNAME`) تُشغَّل به كل طلبات كل الشركات والموظفين، وهوية الصف (tenant/actor) تُمرَّر فقط عبر GUC قابل للتزوير بأي SQL حر على ذات الاتصال.
- أحد حلّي بنية الاتصال (الخيار A، SQL LOGIN لكل actor/tenant) **قابل للدفاع عنه هندسيًا** ومتوافق مع الأنماط الموجودة فعليًا في نفس المستودع (أدوار NOLOGIN جماعية + SECURITY DEFINER بمالك محدد — نفس نمط `daleel_tenant_auth_lookup` و`daleel_provider_first_admin_writer` الحاليين). الخيار B (بوابة ثقة عند DB لا تعتمد على توقيع Laravel) **غير واقعي في هذه المعمارية** بسبب غياب أي وسيط (reverse proxy/service mesh) بين PHP وPostgreSQL يمكنه حمل هوية غير قابلة لـ Laravel نفسه أن يزوّرها؛ موثَّق بالسبب لا بالاختراع.
- بقيت فجوات ثقة **مُعلَنة لا مُغلَقة**: `ON_WIRE_AUTH_METHOD=NOT_VERIFIED`، نافذة `H06b` الملتزمة، مخاطر اختراق عملية PHP (الخصم ب) **غير محصورة** بهذا التصميم وحده، وT4b/F16 مستقلان تمامًا ولا يُعالَجهما هذا التصميم.
- لم تُنفَّذ أي شريحة برمجية. القرار هو **تصميمي** لا تنفيذي: `READY_FOR_IMPLEMENTATION_AUTHORIZATION=YES_CONDITIONAL` (الشروط في §ي و§ل).

---

## (ب) W0 — خمس Git baselines وحالة الملفات

| Repo | Path | Branch | HEAD الحي (مُتحقَّق الآن) | المرجع المُعلَن في التكليف | الحالة |
|---|---|---|---|---|---|
| ROOT | `I:\WORK\DALEEL-CRM` | `master` | `c2ee5a3a3e128f86147e06d39cd50ca7ff2cf7d9` | نفسه | **مطابق** |
| API | `daleel-crm-api` | `preserve/rm02-rm05-baseline` | `e8cee07c2c39df5a1531cbd63168695347202371` | نفسه | **مطابق** |
| WEB | `daleel-crm` | `master` | `6fb01b8838de52de621dab4691a5cdd5710c29f6` | نفسه | **مطابق** |
| ADMIN | `daleel-crm-admin` | `master` | `9fa43befadaaa5d4583f8de6bf7a06c60e891bef` | نفسه | **مطابق** |
| SUPER | `daleel-crm-super-admin` | `master` | `a802e44b8a269071bcb46fcaa675aafb43b12a87` | نفسه | **مطابق** |

**حالة untracked/unstaged (قبل كتابة هذا الملف):**
- ROOT: ثلاثة ملفات `M` غير staged — `docs/EVIDENCE-REGISTER.md`، `docs/HANDOFF-CURRENT.md`، `docs/WORK-LEDGER.md` — ومجلد `?? .codex-remote-attachments/` غير متتبَّع. **لم تُلمَس هذه الملفات في هذه الجولة.**
- API: `?? tools/` (ملفات POC01–04 والإغلاق اللاحق، غير متتبَّعة) — **لم تُلمَس**.
- WEB/ADMIN/SUPER: نظيفة (`git status --porcelain=v1` بلا خرج).
- `staged=0` في الخمسة.

**فرق مُفسَّر لا يُعدّ drift:** محتوى `docs/HANDOFF-CURRENT.md` (أحد الملفات الثلاثة غير المحفوظة) يذكر داخليًا أن "آخر commit محفوظ" على ROOT هو `00ea4d54…`، بينما HEAD الحي فعليًا هو `c2ee5a3a…` (تحقّق عبر `git log --oneline`: `c2ee5a3` أحدث بتكملة واحدة فوق `00ea4d5` فوق `25fe826` فوق `b99be57` — سلسلة أسلاف صحيحة، لا تفرّع). هذا تأخّر طبيعي في نص وثيقة ذاكرة لم تُحدَّث بعد آخر commit، وليس انحرافًا في الهوية أو عملًا متزامنًا غير معروف. لم يُستخدَم هذا كذريعة لتعديل الملف.

**بعد كتابة هذا الملف:** الإضافة الوحيدة في مستودع API هي الملف الجديد نفسه `docs/audits/SECURITY-F06-LARAVEL-INTEGRATION-DESIGN-01.md` (كان غير موجود، تحقّقنا قبل الكتابة)؛ لا تغيير على أي من الثلاثة الجذرية ولا على مجلد `tools/`. لا `git add`/`commit`/`stage`.

---

## (ج) حدود السلطة وتصنيف الأدلة

| الادّعاء | المصدر | التصنيف |
|---|---|---|
| اعتماد SQL واحد مشترك لكل الشركات/الموظفين عبر `pgsql_tenant_runtime` | `config/database.php:166-176`، `.env.example:68` | `VERIFIED_SOURCE` |
| هوية الصف تمرَّر عبر `set_config('app.tenant_id'/'app.user_id', …, true)` على نفس الاتصال المشترك | `TenantStaffRequestContext.php:31-33,47-48`، `TenantStaffContextGuard.php:72-74,101-104` | `VERIFIED_SOURCE` |
| دوال RLS تقرأ GUC مباشرة بـ`SECURITY INVOKER` دون مرساة هوية مصادَق عليها | `database/migrations/2026_10_06_000008_enable_tenant_rls.php:13-35` | `VERIFIED_SOURCE` |
| جدول `leads` الحقيقي 18 عمودًا، بلا أي `UNIQUE`، 3 فهارس غير فريدة | `database/migrations/2026_10_23_000036_create_leads.php:46-73` | `VERIFIED_SOURCE` |
| `LeadService::assignLead()` يسمح بإعادة إسناد مصرَّح بها لحائزي `ALL_TENANT` فقط | `app/Modules/Tenancy/Application/LeadService.php:146-164` | `VERIFIED_SOURCE` |
| `daleel_tenant_runtime` دور NOLOGIN جماعي بلا bypass/create | `database/migrations/2026_10_24_000037_…php:43-63` | `VERIFIED_SOURCE` |
| `CURRENT_USER` هو المرساة الوحيدة غير المنتحَلة اليوم، فقط في 3 سياسات preauth | `docs/HANDOFF-CURRENT.md §4` + `database/migrations/2026_10_12_000026_…php:74-97` (مطابقة مصدرية) | `VERIFIED_SOURCE` |
| لا Octane/Horizon، لا jobs `ShouldQueue`، لا PgBouncer في كود/إعداد API | فحص `composer.json` وبحث شامل `grep` (بدون نتائج) | `VERIFIED_SOURCE` (غياب موثَّق، لا افتراض) |
| اختبارات 51/51 HTTP wire، 11/11 Kernel، 29/29 PHPUnit التاريخية | `docs/HANDOFF-CURRENT.md §4-أ`، `DEV-FOUNDATION-01.md` | `DOCUMENTED_PRIOR` — **لم تُعَد تشغيلها في هذه الجولة** |
| نجاح POC04-closeout (F3/F5/F6/H03) على sandbox اصطناعية | تقارير الإغلاق السابقة (`REPORT_F5_F6C_FINAL_GATE.md` وسابقاتها) | `DOCUMENTED_PRIOR` |
| `ON_WIRE_AUTH_METHOD` (SCRAM فعليًا على السلك) | لم يُقَس في أي مرحلة سابقة أو هذه | `NOT_VERIFIED` |
| عدد موظفين/شركات متزامنين يحتمله اتصال Postgres الواحد في الإنتاج الحقيقي | لا بيانات إنتاج مفحوصة | `STATIC_INFERENCE` (حساب نظري في §و، غير مُقاس) |

---

## (د) مخطط تدفق HTTP→SQL الحالي (بالمصدر الفعلي)

```
1. Request يصل بـ Host:<tenant-slug>.<base_domain>
   → TenantHostResolver::resolve()  [app/Modules/Identity/Application/TenantHostResolver.php:14-84]
     - يتحقق من قانونية الـhost (lowercase, لا IP, لا نقطة زائدة) ثم من انتمائه لـ config('tenancy.base_domain')
     - اتصال DB مستقل: pgsql_tenant_runtime ≠ هذا — يستخدم 'pgsql_hostname_resolver'
       (config/database.php:144-154، اعتماد TENANT_HOST_DB_USERNAME مستقل)
     - set_config('app.context_mode','HOST_RESOLUTION',true) + استعلام tenant_hostnames/tenant_registry_domains
     - fail-closed: أي خلل (host غير نشط، mapping غائب) → InvalidArgumentException
     → ينتج TenantHostContext (tenant_id, tenant_slug, hostname, base_domain, environment_scope)
     هذه الطبقة هي حدود T4b (انظر §هـ) — لا تُعالَج هنا.

2. middleware TenantStaffRequestContext::handle()
   [app/Modules/Identity/Http/Middleware/TenantStaffRequestContext.php:18-67]
   - يقرأ tenant_host_context من attributes (من الخطوة 1)
   - DB::connection('pgsql_tenant_runtime')->beginTransaction()   ← نفس الاتصال/الاعتماد المشترك لكل الطلبات
   - تصفير دفاعي لـ app.context_mode/app.tenant_id/app.user_id عبر set_config(...,'',true)
   - إن كان route هو login: logout + forget الجلسة
   - وإلا إن وُجدت جلسة identity.tenant_staff مخزَّنة:
       → TenantStaffContextGuard::activateFromSession()
         [app/Modules/Identity/Application/TenantStaffContextGuard.php:32-99]
         - يطابق tenant_id/hostname/user_id/membership_id/auth_version/authorization_version
           المخزَّنة في جلسة Laravel (session driver — ليس SQL) مع TenantHostContext
         - set_config('app.context_mode','TENANT') / set_config('app.tenant_id', host->tenantId)
           / set_config('app.user_id', userId)   ← كل هذا على الاتصال المشترك (TenantStaffContextGuard.php:72-74)
         - يعيد التحقق من tenants/tenant_staff_users/tenant_staff_memberships (status=ACTIVE,
           auth_version/authorization_version مطابقَين) عبر SELECT على نفس الاتصال
         - فشل أي شرط → TenantAccessException → تصفير GUC + logout + AuthenticationException
   - $next($request) يُنفَّذ **داخل** هذه المعاملة المفتوحة
   - commit عند النجاح؛ rollback عند أي Throwable

3. داخل الـcontroller/service (مثال LeadService)
   [app/Modules/Tenancy/Application/LeadService.php]
   - DB::connection('pgsql_tenant_runtime')->table('leads')->where('tenant_id', $actor->tenantId)…
     ← tenant_id هنا **قيد تطبيقي** (WHERE) فوق RLS، لا بديل عنها
   - RLS الفعلية (migration 2026_10_23_000036_create_leads.php:81-87) تعتمد على
     app_rls_context_mode()/app_rls_current_tenant_id() وكلاهما SECURITY INVOKER يقرأ
     current_setting('app.context_mode'/'app.tenant_id', true) **بلا أي تحقق مصادقة إضافي**
     [database/migrations/2026_10_06_000008_enable_tenant_rls.php:13-35]
   - نطاق ALL_TENANT/ASSIGNED/SELF طبقة تطبيقية بحتة فوق ذلك
     (TenantStaffAuthorizationService::effectiveGrants + LeadService::rowInScope/applyScopeFilter)

4. Response يُعاد؛ الاتصال غير persistent (لا 'persistent'=>true في إعداد pgsql أي مكان)
   فيُغلَق طبيعيًا مع انتهاء عملية PHP-FPM للطلب (لا Octane/Horizon في هذا المستودع — بحث شامل بلا نتائج).
```

**الفجوة الجوهرية بالمصدر:** بين الخطوتين 2 و3، أي SQL حر يُنفَّذ على اتصال `pgsql_tenant_runtime` (أي حرية استعلام بما فيها injection ضمن اعتماد التشغيل نفسه) يمكنه إعادة `set_config('app.tenant_id', '<company-other>', true)` دون أي رفض من PostgreSQL، لأن الاعتماد المُصادَق عليه فعليًا على الاتصال (نفس اللوغن لكل الشركات) لا علاقة له بقيمة الـGUC. هذا هو F06 بالضبط، مُثبتًا بالمصدر لا بالاستدلال.

**اختلاف WEB/ADMIN/SUPER:** الثلاثة Frontends خارج نطاق فحص هذه الجولة (المالك منع لمسها)؛ من جهة API فإن `TenantStaffRequestContext` middleware عام لكل مسارات `tenant_staff` بصرف النظر عن أي Frontend استدعاه — لا فرع كود مختلف باسم WEB/ADMIN/SUPER وُجد ضمن النطاق المفحوص. عمل الخلفية (background): لا jobs/queue مكتشفة (`NOT_FOUND_IN_SCANNED_SCOPE`)، فكل معالجة SQL تمر بنفس مسار الطلب المتزامن.

---

## (هـ) فجوات الثقة المستقلة — F06 / T4b / F16

- **F06 (هذا التصميم يستهدفه):** OPEN/HIGH بالمصدر. السبب الجذري مُثبَّت في §د: اعتماد مشترك + GUC. **لا يُغلَق** بمجرد تمرير `hostname`/`tenant_id` من نفس العميل — هذا بالضبط افتراض خاطئ حذّر منه التكليف؛ `TenantHostContext` نفسه (من الخطوة 1) **لا يحمي** من تزوير GUC داخل الاتصال في الخطوة 3، لأنه طبقة مختلفة تمامًا (اتصال DB مختلف، لحظة زمنية مختلفة).
- **T4b (مستقل، لا يُعالَج هنا):** `TenantHostResolver` يعتمد على مطابقة hostname عبر اتصال DB مستقل (`pgsql_hostname_resolver`) بمنطق `set_config('app.context_mode','HOST_RESOLUTION',true)` — نفس عائلة الخطر (GUC على اتصال) لكن على بيانات **تعيين Host→Tenant**، لا بيانات شركة. حلّه يحتاج **مرساة Host موثوقة مستقلة** (كما نص التكليف) ومسار عمل مستقل بالكامل؛ هذه الوثيقة **لا تصمم حله**، فقط تُسجّل أن أي حل F06 لا يعالج T4b تلقائيًا.
- **F16 (مستقل، لا يُعالَج هنا):** خطر حارس ADMIN مزيّف (`isAuthenticated` mock cookie) في مسارات محددة — لم تُفحَص في هذه الجولة (خارج النطاق المصرَّح)، ويبقى `OPEN` كما ورد في `docs/HANDOFF-CURRENT.md §5`.
- **لا ادّعاء إغلاق F06 حتى بعد هذا التصميم** قبل wire integration حقيقي (HTTP فعلي + SQL فعلي على بيئة منفصلة، مُختبر، لا POC).

---

## (و) مقارنة بدائل بنية الاتصال وقرار مبدئي

### الخيار A — SQL LOGIN مستقل لكل (شركة، موظف) + `session_user` كمرساة

**الآلية:** كل عضوية (membership) نشطة تملك دور PostgreSQL `LOGIN` خاصًا بها (أو بالحد الأدنى دور لكل موظف عابر للشركات إن وُجد)، باسمه اعتماد خاص (كلمة مرور SCRAM). عند تفعيل السياق في `TenantStaffContextGuard` (بعد كل التحقّقات الحالية بلا تغيير)، لا يُستدعى `set_config` لهوية التفويض؛ بل يُفتَح **اتصال PostgreSQL جديد باسم مستخدم محدَّد مسبقًا**، أو — أكثر واقعية مع Laravel — يُنفَّذ `SET SESSION AUTHORIZATION`/إعادة اتصال PDO باعتماد العضوية فعليًا (وليس `SET ROLE`، لأن `SET ROLE` يبقى executable من نفس الاتصال المشترك ولا يغيّر `session_user`). دوال RLS تتحول من `current_setting('app.tenant_id')` إلى resolver `SECURITY DEFINER` (مملوك لدور NOLOGIN منفصل، بلا BYPASSRLS) يقرأ **`session_user`** حصريًا من جدول mapping محمي (`actor_identity_map`-مثل، بلا SELECT/UPDATE لأي دور LOGIN).

**مطابقة ما أُثبت في POC:** هذا هو نفس نموذج `f06-poc04-proof-closeout/001_schema_roles.sql` حرفيًا (أدوار LOGIN لكل actor، `actor_identity_map` محمي، resolvers `SECURITY DEFINER`). الفرق الجوهري المطلوب في التصميم (لا في SQL): **كيف يختار Laravel، في منتصف معالجة طلب HTTP واحد، أي اعتماد PDO يستخدمه** — هذا تحدٍّ معماري حقيقي في Laravel، لأن `DB::connection()` في Laravel مصمَّم حول إعدادات اتصال **ثابتة في config** لا اعتمادات تُحدَّد في وقت التشغيل لكل طلب.
**الحل الهندسي المتاح فعليًا في Laravel (دون تعديل جوهر Framework):** `Config::set('database.connections.pgsql_tenant_runtime.username', …)` + `DB::purge('pgsql_tenant_runtime')` **قبل** أول استخدام للاتصال في الطلب، بحيث يُعاد بناء اتصال PDO جديد بالاعتماد الصحيح في كل طلب. هذا نمط موجود ومُستخدم في مشاريع Laravel متعددة-المستأجرين الحقيقية؛ **لم يُعثر على استخدام فعلي له في هذا المستودع حاليًا** (`NOT_FOUND_IN_SCANNED_SCOPE`) — فهو إضافة تصميمية جديدة، لا ميزة موجودة يُعاد استخدامها.

**تقييم أصل السلطة:** السلطة تنتقل من "امتلاك اعتماد التشغيل المشترك" إلى "امتلاك اعتماد actor محدَّد مُصادَق عليه فعليًا من PostgreSQL نفسه (SCRAM)". مهاجم SQL تحت اعتماد A1 (الخصم أ في التكليف) **لا يستطيع** تغيير `session_user` بأي SQL حر (`SET ROLE`/`SET SESSION AUTHORIZATION` يحتاجان صلاحية عضوية فعلية في الدور الهدف، وهذا ما تثبته POC04 الأدوار `NOINHERIT`). مهاجم اخترق عملية PHP (الخصم ب) **قادر** على فتح اتصالات بأي اعتماد actor تحتفظ به نفس عملية PHP في مخزن الأسرار — هذا **خطر باقٍ صريح**، لا يُغلَق بهذا الخيار، ويجب أن يُعلَن `PHP_MULTI_CREDENTIAL_COMPROMISE_RISK=OPEN` لا `CONTAINED` (التكليف يمنع كتابة CONTAINED بلا دليل، ولا يوجد دليل عزل عملية هنا).

**القرار المبدئي: `RECOMMENDED` بشروط قبول:**
1. Provisioner مستقل الصلاحية (§ز-2) — لا HTTP runtime يملك `CREATEROLE`.
2. حل واقعي لحد الاتصالات/الأدوار (انظر الحساب أدناه) قبل أي بيئة بأكثر من بضع مئات موظف متزامن.
3. سياسة أسرار (تخزين/دوران/إبطال) مستقلة قابلة للاختبار (§ز-3) قبل أي بيئة حقيقية.
4. إثبات تجريبي حقيقي (لا POC) أن `Config::set`+`DB::purge` ينتج اتصالًا بالهوية الصحيحة **قبل** أي استعلام تنفيذي في الطلب — هذا بالضبط هدف الشريحة الأولى IMPLEMENT-01 (§ي).

### الخيار B — مرساة ثقة مثبَّتة عند DB لا يستطيع Laravel تزويرها

**لماذا هو `UNRESOLVED` فعليًا وليس بديلًا واقعيًا هنا:** أي "بوابة ثقة" يجب أن تكون كيانًا **لا يستطيع كود PHP نفسه توقيعه بنفسه نيابةً عن أي actor** — أي يجب أن يقف بين Laravel وPostgreSQL (reverse proxy مصادِق، أو mTLS بشهادة خاصة بكل actor تُدار خارج عملية PHP، أو HSM/wallet خارجي). **لا يوجد في هذا المستودع أو في البنية المفحوصة أي وسيط من هذا النوع** (لا PgBouncer، لا service mesh، لا Vault/HSM مذكور) — `NOT_FOUND_IN_SCANNED_SCOPE`. بديل "GUC موقَّع" (مثل توليد JWT GUC تتحقق منه دالة DB) **لا يحل المشكلة لأن Laravel نفسه هو من يوقِّع**، فمهاجم اخترق عملية PHP يستطيع توليد توقيع صحيح لأي actor — هذا **نفس** ثغرة الخصم ب في الخيار A، بلا أي ميزة إضافية، بل بتعقيد تنفيذي أكبر (بنية تشفير إضافية) لا يقابله ضمان أمني جديد. **التصريح الصريح المطلوب بالتكليف:** هذا البديل **غير مناسب في هذه المعمارية الحالية** لأن تطبيقه الحقيقي (وسيط خارج PHP) غير موجود ويحتاج مكوّنًا بنيويًا جديدًا كاملًا (ليس تصميم ربط، بل مشروع بنية تحتية مستقل) يتجاوز نطاق "ربط Laravel بمرساة SQL". **القرار: `REJECTED` لعدم الواقعية في هذه الجولة**، لا لعيب مبدئي في الفكرة.

### حساب نظري لحدود الاتصالات (`STATIC_INFERENCE`, غير مُقاس)

PostgreSQL الافتراضي `max_connections=100` (قيمة شائعة، غير مؤكَّدة لبيئة إنتاج هذا المشروع تحديدًا — `NOT_VERIFIED`). كل طلب HTTP في PHP-FPM غير-Octane يفتح اتصال PDO جديدًا (غير persistent، مؤكَّد من الإعداد) ويُغلقه عند نهاية الطلب. مع N عامل PHP-FPM متزامن، الحد الأعلى النظري للاتصالات المتزامنة على `pgsql_tenant_runtime` هو N (بصرف النظر عن أي أدوار)، **لا** عدد الموظفين الكلي — أدوار LOGIN لكل actor لا تضاعف عدد الاتصالات المتزامنة، فقط تضاعف **عدد الأدوار المعرَّفة** في `pg_roles` (تكلفة كتالوج، لا تكلفة اتصال). الخطر الحقيقي هو تكلفة **كتالوج** PostgreSQL مع آلاف الأدوار (`pg_authid`/`pg_auth_members`)، وهذا قابل للقياس التجريبي في شريحة لاحقة (provisioning)، **ليس** في هذا التصميم.

---

## (ز) قرارات العقود التشغيلية

### ز-1) من يثبت tenant/actor، وهل يمكن تبديلهما عبر header/cookie؟

لا تغيير على هذه الطبقة في الخيار A: `TenantHostResolver` (host فقط، بلا ثقة بأي header من العميل بخلاف `Host` نفسه المطابَق ضد mapping DB) ثم `TenantStaffContextGuard::activateFromSession` (التحقق الصارم الموجود فعليًا، سطور 41-48، يطابق tenant_id/hostname/user_id/membership_id/auth_version/authorization_version من **جلسة Laravel الموثوقة من جهة الخادم** — لا من أي قيمة عميل حرة). **لا يمكن للعميل تبديل tenant_id/membership عبر header/cookie اليوم** لأن الجلسة من جهة الخادم فقط (`$request->session()->get(...)`)، والقيم تُعاد-تحقَّق بالكامل من DB في كل طلب. **هذا لا يتغيّر بالخيار A** — التغيير الوحيد هو: بعد نجاح هذا التحقق بالكامل (نفس الكود)، يُحدَّد اعتماد PDO بناءً على `membership_id` المُحقَّق، لا بـ`set_config`.
**منع bootstrap cycle:** اختيار اعتماد actor **يحدث بعد** نجاح `activateFromSession`/`activateAfterCredentialCheck` بالكامل — وكلاهما يستخدمان اليوم نفس اتصال `pgsql_tenant_runtime` **المشترك الضعيف حاليًا** لقراءة `tenants`/`tenant_staff_users`/`tenant_staff_memberships` (سطور 76-87). في التصميم الجديد، **هذه القراءة التحقّقية نفسها** يجب أن تنتقل إلى اتصال بصلاحية SELECT محدودة فقط (بلا أي قدرة كتابة) — **وليس** إلى اعتماد actor بعد (لأنه غير معروف قبل اكتمال التحقق) — فتُمنَع حلقة bootstrap بإبقاء هذه القراءة التحقّقية الأولى على دور منفصل محدود (`daleel_tenant_auth_lookup`-مثل، نفس نمط المصادقة الموجود فعليًا في migration 026)، ثم فقط بعد نجاحها يُحدَّد اعتماد actor الكامل لباقي الطلب.

### ز-2) Provisioner مستقل الصلاحية لإنشاء/تعليق/نقل/حذف الهوية

يُعاد استخدام النمط الموجود فعليًا حرفيًا (لا اختراع): دور NOLOGIN جماعي بلا BYPASSRLS/CREATEROLE (مطابق `daleel_provider_first_admin_writer`، migration 027) + RESTRICTIVE policy مرتبطة بصفوف "عملية تحكم" READY (نمط migration 030 `company_lifecycle`). `CredentialProvisioner` (اسم مقترح، **`PROPOSED_NOT_CREATED`**) هو خدمة Laravel منفصلة تعمل **فقط** عبر اتصال DB مخصَّص (`pgsql_actor_provisioner`-مقترح) يحمل العضوية في دور الإنشاء، لا HTTP runtime العادي. حالات: انضمام (CREATE ROLE + INSERT mapping)، تعليق (REVOKE LOGIN أو تعليق في mapping دون حذف الدور)، نقل شركة (ليس مدعومًا منطقيًا اليوم — `tenant_staff_memberships` لكل (tenant,staff) مستقلة؛ "نقل" يعني عضوية جديدة بدور SQL جديد، لا تعديل دور قائم)، حذف (REVOKE LOGIN + لاحقًا DROP ROLE بعد تأكد عدم وجود اتصالات مفتوحة). idempotency: كل عملية provisioning يجب أن تُسجَّل بمعرِّف عملية (نفس نمط `created_by_provider_operation_id` الموجود فعليًا في `tenant_staff_memberships`، migration 037 سطر 26) بحيث إعادة تنفيذ نفس العملية لا تُنشئ دورًا مكررًا (`CREATE ROLE IF NOT EXISTS` منطقيًا عبر فحص `pg_roles` أولًا، كما يفعل `DO $guard$` في migrations 027/037 فعليًا).

### ز-3) الأسرار

**التخزين:** لا تخزين في أي عمود DB عادي ولا في ملفات Laravel العادية. الخيار الواقعي الوحيد المتاح دون بنية تحتية جديدة: Laravel's encrypted config/`.env` **لكل اعتماد على حدة غير ممكن عمليًا** (آلاف الأعمدة)؛ الحل الصحيح هو **مخزن أسرار خارجي** (Vault/AWS Secrets Manager/مكافئ) — **لا يوجد حاليًا في هذا المستودع** (`NOT_FOUND_IN_SCANNED_SCOPE`)، فإدخاله جزء من شريحة provisioning، لا من IMPLEMENT-01. **من يفك التشفير:** فقط عملية PHP وقت الطلب، بعد نجاح `activateFromSession` — نفس حد الخصم ب المُعلَن. **عدم التسريب في logs/headers/queue:** يُطبَّق بإضافة الاسم إلى allowlist الحجب الحالي في Laravel (`'password'` موجود بالفعل كنمط حجب قياسي لـLaravel؛ يُضاف نمط اعتماد actor بنفس الطريقة) — **تصميم، لا كود فعلي هنا**. **rollback فشل rotation:** يجب أن يحتفظ provisioner باعتماد قديم صالح حتى تأكيد نجاح الجديد (نمط "كلمتا مرور صالحتان لفترة انتقالية" القياسي)، **وليس** استبدالًا فوريًا بلا نافذة تراجع.
**Revocation لاتصالات/معاملات قائمة:** مطابق تمامًا لما أثبتته POC04 (`H06b`/`H06c`): تعليق العضوية في mapping لا يقطع معاملة مفتوحة فورًا (نافذة committed موجودة وموصوفة، PostgreSQL لا يفحص الاتصال وسط `pg_sleep`-مثل انتظار)؛ الإبطال الفوري الحقيقي للاتصال نفسه يحتاج `pg_terminate_backend` بهوية (pid+backend_start) موثوقة — وهذا عملية إدارية مستقلة (provisioner)، **ليست** جزءًا من مسار الطلب العادي.

### ز-4) معاملات Laravel المتداخلة، الاستثناءات، وتبدّل الهوية بين طلبين

`TenantStaffRequestContext` الحالي يفتح معاملة واحدة (`beginTransaction`) تلتف حول الطلب بالكامل — **لا savepoints متداخلة مكتشفة** في النطاق المفحوص لهذا المسار. هذا يبقى كما هو في الخيار A (لا حاجة لتغييره، لأن اختيار اعتماد actor يحدث **قبل** `beginTransaction` لا داخله — عبر `Config::set`+`DB::purge` قبل أول `DB::connection('pgsql_tenant_runtime')->…`). عند استثناء: `rollBack()` الموجود فعليًا (سطر 61-63) يبقى كافيًا لإلغاء أي تغيير بيانات؛ **لا GUC يحتاج إلغاءً** في التصميم الجديد لأنه لا يوجد GUC هوية بعد الآن. **تبدّل الهوية بين طلبين:** كل طلب يبني اتصاله من الصفر (غير persistent، مؤكَّد) فلا تلوّث بين طلبين مختلفين — هذا **أقوى** من الوضع الحالي حيث يمكن نظريًا (لو وُجد persistent connection pooling يومًا) أن يتسرب GUC بين طلبين؛ الخيار A يُلغي هذا الخطر بنيويًا لأن الهوية ذاتها (`session_user`) مرتبطة بالاتصال لا بقيمة قابلة لإعادة الكتابة.
**CLI/الصيانة:** أي أمر `artisan` يستخدم `pgsql_tenant_runtime` يحتاج نفس آلية اختيار الاعتماد قبل التنفيذ (مثلًا عبر سياق provider/system منفصل تمامًا عن سياق actor الموظف) — **لم يُعثر على استخدام CLI فعلي لهذا الاتصال** (`NOT_FOUND_IN_SCANNED_SCOPE`)، فهذا بند مستقبلي إن ظهر.

### ز-5) PgBouncer

`NOT_FOUND` — لا PgBouncer في هذا المستودع أو إعداده (بحث شامل بلا نتائج). **إن أُضيف لاحقًا:** وضع `session pooling` هو الوحيد المتوافق مع `session_user`/`SET SESSION AUTHORIZATION` كمرساة (لأن `transaction`/`statement` pooling يُعيدان استخدام الاتصال الفعلي بين عملاء مختلفين بين المعاملات، فيفسدان أي ضمان هوية مرتبط بالاتصال). هذا قيد تصميمي يجب تسجيله **الآن** حتى لا يُضاف PgBouncer بوضع transaction لاحقًا دون مراجعة أمنية.

### ز-6) عقد RBAC الخاص بـLeads (`ALL_TENANT`/`ASSIGNED`/`SELF`)

**لا تغيير على هذا العقد.** `LeadService::rowInScope`/`applyScopeFilter`/`assignLead` (الأسطر المذكورة في §ج) تبقى كما هي حرفيًا — هذه طبقة تطبيقية فوق tenant_id، لا علاقة لها بهوية الاتصال. التصميم الجديد **لا ينسخ** قيد `owner_actor_id` الثابت أو trigger منع الملكية المطلق من POC إلى Leads الحقيقي — ذلك قيد اصطناعي خاص بإثبات POC فقط، والتكليف ينص صريحًا على منع هذا النسخ.

### ز-7) بيانات الشركات والموظفين الحاليين (دون migration 039 الآن)

مخطط تصميمي فقط: جدول mapping جديد (اسم مقترح `actor_sql_identity_map`، **`PROPOSED_NOT_CREATED`**) بمفتاح مركَّب `(tenant_id, membership_id)` → `role_name` فريد، FK إلى `tenant_staff_memberships(tenant_id, id)` (نفس نمط FK المركَّب الموجود فعليًا في `leads_assigned_membership_fk`، migration 036 سطر 66-67). Backfill: لكل عضوية `ACTIVE` حالية، إنشاء دور SQL واحد عبر provisioner، idempotent بمعرِّف عملية. تسمية أدوار آمنة الطول (حد PostgreSQL `NAMEDATALEN=64`؛ استخدام UUID مختصر أو تسلسل لا الاسم الحقيقي لتفادي تسريب PII في `pg_roles` العلنية القراءة). منع الأدوار اليتيمة: قيد DB (trigger أو فحص دوري) يقارن `pg_roles` مع `actor_sql_identity_map` ويُنبّه عند وجود دور بلا صف mapping (لا حذف تلقائي). **Rollback:** الخيار A **لا يحتاج إزالة** الاتصال المشترك القديم فورًا — يمكن تشغيل الاثنين بالتوازي لفترة (feature flag في `TenantStaffContextGuard` يختار المسار)، فالتراجع هو إيقاف الـflag، لا حذف بيانات.

### ز-8) T4b كحد مستقل

كما في §هـ: هذه الوثيقة **تحدد الحد فقط** — أي حل F06 (الخيار A) يفترض أن `TenantHostContext` الداخل من الخطوة 1 **صحيح أصلًا**؛ لا يثبته ولا يبطله. معالجة T4b الفعلية (مرساة Host موثوقة، مسار عمل مستقل) تحتاج تصميمًا منفصلًا بالكامل، **لا تبدأ هنا**.

---

## (ح) فهرس التغييرات المتوقَّع على مستوى الملفات (بلا كود فعلي)

> **تنويه:** كل مسار أدناه من نوع `MODIFY` هو ملف موجود فعليًا تحقَّقنا منه بالمصدر. كل اسم من نوع `CREATE` هو **اسم مقترح `PROPOSED_NOT_CREATED`**، ليس ملفًا موجودًا.

| المسار | النوع | الوظيفة | المدخل/المخرج | أثر Rollback |
|---|---|---|---|---|
| `app/Modules/Identity/Application/TenantStaffContextGuard.php` | MODIFY | إزالة استدعاءات `set_config` للهوية (سطور 72-74) واستبدالها باستدعاء `ActorConnectionFactory` بعد نجاح التحقق | مدخل: `TenantHostContext`+بيانات جلسة محقَّقة؛ مخرج: `TenantStaffContext` كما هو تمامًا | وراء feature flag — إبقاء المسار القديم قابلًا للتفعيل حتى تثبيت الجديد |
| `app/Modules/Identity/Http/Middleware/TenantStaffRequestContext.php` | MODIFY | إزالة تصفير GUC الدفاعي (سطور 31-33,47-48) إن لم يعد له معنى، أو إبقاؤه كطبقة دفاعية إضافية غير ضارة | — | لا أثر بيانات |
| `config/database.php` | MODIFY | `pgsql_tenant_runtime` يصبح **قالب اتصال** بلا username/password ثابتين (يُستكملان وقت التشغيل)؛ إبقاء بقية الاتصالات كما هي تمامًا | — | إعادة القيم الثابتة من `.env` تُرجع السلوك القديم فورًا |
| `app/Modules/Identity/Application/ActorConnectionFactory.php` | CREATE (`PROPOSED_NOT_CREATED`) | `resolveFor(TenantStaffContext $actor): Connection` — تنفّذ `Config::set` + `DB::purge('pgsql_tenant_runtime')` بالاعتماد المستخرج من `ActorSqlIdentityResolver` | مدخل: `TenantStaffContext`؛ مخرج: `Connection` جاهز بهوية `session_user` صحيحة | — |
| `app/Modules/Identity/Application/ActorSqlIdentityResolver.php` | CREATE (`PROPOSED_NOT_CREATED`) | يقرأ اعتماد actor من مخزن الأسرار (اسم دور + كلمة مرور حالية) عبر `(tenant_id, membership_id)` — قراءة فقط، لا كتابة | مدخل: `(tenantId, membershipId)`؛ مخرج: بيانات اتصال (لا تُطبَع، لا تُسجَّل) | — |
| `app/Modules/Identity/Application/CredentialProvisioner.php` | CREATE (`PROPOSED_NOT_CREATED`) | إنشاء/تعليق/إبطال دور SQL لكل عضوية، عبر اتصال provisioner مستقل | مدخل: أمر provisioning + معرِّف عملية idempotency؛ مخرج: تأكيد/فشل | عملية DB منفصلة قابلة للتراجع الفردي |
| `database/migrations/2026_XX_XX_0XX_create_actor_sql_identity_map.php` | MIGRATION (مستقبلية، **ليست الآن ولا 039**) | جدول mapping + دوال resolver `SECURITY DEFINER` + RLS الجديدة المعتمدة على `session_user` | — | forward-only، كبقية migrations هذا المستودع (`down()` يرمي استثناء، نفس النمط الموجود) |
| `database/migrations/2026_10_23_000036_create_leads.php` | **لا تُعدَّل** | RLS الحالية تبقى، فقط الدوال التي تستدعيها (`app_rls_context_mode`/`app_rls_current_tenant_id`) تُعاد تعريفها في migration جديدة لتقرأ من resolver الجديد | — | — |
| `tests/Feature/Identity/ActorConnectionFactoryTest.php` | TEST (CREATE) | يثبت أن `Config::set`+`purge` ينتج `session_user` الصحيح على DB اصطناعية | — | — |
| `tests/Feature/Tenancy/LeadServiceActorIsolationTest.php` | TEST (CREATE) | يعيد نفس حالات A1/A2/B1 الموجودة فكرتها في POC، لكن عبر HTTP حقيقي لا SQL مباشر | — | — |

---

## (ط) جدول اختبارات القبول (Test Matrix)

| ID | التهديد | الإعداد | التوقع | الأداة | SQL sandbox؟ | الدليل المتوقع |
|---|---|---|---|---|---|---|
| T-ID-01 | انتحال GUC تحت اعتماد A1 | `SET LOCAL app.tenant_id` حر تحت اتصال A1 | رفض أو تجاهل تام (لا تغيّر النتيجة) | PHPUnit/psql | نعم | 0 صفوف من B، 42501/تجاهل |
| T-ID-02 | `SET ROLE` تحت A1 إلى A2 | أمر SQL حر | رفض `42501` | psql | نعم | SQLSTATE 42501 |
| T-ID-03 | login غير مالك البيانات | A1 يحاول قراءة جدول mapping | رفض | psql | نعم | 42501 |
| T-ID-04 | SQL injection تحت اعتماد A1 | محاكاة حقن ضمن استعلام مُعامَل | يبقى محصورًا بصلاحيات A1 فقط | PHPUnit | نعم | لا تسريب B |
| T-ID-05 | عضوية معلَّقة تحاول اتصالًا | تعليق membership ثم محاولة استخدام actor factory | رفض قبل أي استعلام بيانات | PHPUnit | نعم | استثناء تطبيقي + لا اتصال PDO جديد |
| T-LD-01 | قراءة Lead لشركة أخرى | tenant A يطلب Lead من tenant B عبر HTTP | 403/404 تطبيقي + RLS كخط دفاع ثانٍ | HTTP wire | نعم | HTTP 403/404، 0 صفوف DB |
| T-LD-02 | A1/A2 نفس الشركة، scope SELF | A2 يطلب Lead أنشأه A1 | رفض scope | HTTP wire | نعم | 403 |
| T-LD-03 | إعادة إسناد مصرَّحة | ALL_TENANT يعيد إسناد Lead | نجاح | HTTP wire | نعم | 200 + `assigned_membership_id` محدَّث |
| T-LD-04 | إعادة إسناد ممنوعة | ASSIGNED/SELF يحاول إعادة إسناد | 403 | HTTP wire | نعم | `AuthorizationDeniedException` |
| T-LD-05 | لا فرض UNIQUE اصطناعي | إدخال Leads بنفس الاسم/الهاتف | يُسمَح (لا قيد UNIQUE في المنتج) | PHPUnit | نعم | إدخال ناجح مزدوج |
| T-HW-01 | Host tampering + actor factory | `X-Forwarded-Host` مزوَّر | يُتجاهَل (سلوك موجود مؤكَّد RM04) + لا اعتماد خاطئ يُحدَّد | HTTP حقيقي | نعم | نفس سلوك RM04 التاريخي + لا تغيّر اعتماد |
| T-HW-02 | طلبان متعاقبان A1 ثم B1 على نفس عامل PHP-FPM | تسلسل حقيقي غير متزامن | اتصالان مستقلان، لا تسرّب هوية | HTTP حقيقي | نعم | `session_user` مختلف لكل طلب، مُسجَّل |
| T-HW-03 | CSRF/cookies على مسار actor factory الجديد | طلب بلا CSRF token | 419 كما هو السلوك الحالي | HTTP حقيقي | لا (نفس Kernel الحالي) | 419 |
| T-PR-01 | provisioning أول أدمن | إنشاء دور + mapping لأول مرة | نجاح + idempotent عند التكرار | PHPUnit | نعم | صف واحد فقط بعد تكرار الأمر |
| T-PR-02 | تعليق عضوية أثناء معاملة مفتوحة | توقيت متحكَّم فيه (نفس أسلوب H06b) | الاتصال القديم يفشل عند أول استعلام تالٍ، لا يُقطَع فورًا (نافذة مُعلَنة) | psql متحكَّم | نعم | توثيق النافذة، لا ادّعاء قطع فوري |
| T-PR-03 | rotation فاشل جزئيًا | حقن فشل في منتصف rotation | الاعتماد القديم يبقى صالحًا (rollback) | PHPUnit | نعم | لا انقطاع خدمة |
| T-TC-01 | عضوية دور owner/ACL | فحص `pg_auth_members`/`has_schema_privilege` للدور الجديد | بلا BYPASSRLS/CREATEROLE/عضوية خارجية | psql | نعم | مطابق لنمط `DO $guard$` الحالي |
| T-TC-02 | PUBLIC EXECUTE على resolver الجديد | فحص ACL الدالة | 0 | psql | نعم | `aclexplode` فارغ لـPUBLIC |
| T-TC-03 | تصنيف SQLSTATE للرفض | كل حالة رفض أعلاه | `42501` فقط يُحتسَب أمنيًا (نفس منهج POC المقبول) | psql | نعم | لا 23505/42601 يُحتسَب خطأ أمنيًا |

---

## (ي) أصغر شريحة تنفيذية — `SECURITY-F06-LARAVEL-IMPLEMENT-01`

**الحجم:** PR واحد قابل للمراجعة في جلسة. **لا migration على بيئة محمية. لا تعديل على Leads/RLS الحالية.**

**المحتوى المقترح:**
1. `ActorConnectionFactory` + `ActorSqlIdentityResolver` (اسمان مقترحان) على **قاعدة اصطناعية جديدة ومعزولة بالكامل** (نفس سياج Docker/`--internal`/بلا منفذ منشور المُستخدَم في كل جولات POC السابقة)، بسطر HTTP واحد فقط: `GET /api/v1/leads` (القراءة الأبسط، أثر كتابة صفري).
2. دوران اتصال حقيقي واحد: طلب A1 → اتصال بـ`session_user=role_a1`؛ طلب A2 → اتصال مختلف `session_user=role_a2`، على نفس عامل PHP-FPM بالتتابع (يثبت T-HW-02 حقيقيًا لا بمحاكاة).
3. **لا تُحذف** آلية GUC القديمة — تبقى خلف feature flag مُعطَّل افتراضيًا، فالتراجع هو تعطيل الـflag فقط.

**معايير القبول (GO):**
- T-ID-01, T-ID-02, T-HW-02 أعلاه PASS حقيقيًا (HTTP + SQL على sandbox جديدة، لا POC سابقة).
- 0 تغيير على استجابة `GET /api/v1/leads` من منظور العميل (نفس الحمولة والحالة تمامًا) — إثبات أن التبديل غير مرئي خارجيًا.
- `kill_rc`/`wait_rc`/هوية الاتصال تُسجَّل بنفس دقة منهج POC04 المقبول (لا تراجع في معيار الإثبات).

**معايير الرفض (NO-GO لهذه الشريحة بعينها):**
- تعذُّر إثبات أن `DB::purge` يمنع تلوّث اتصال بين طلبين فعليًا (لا نظريًا) على نفس عامل.
- أي حاجة لمنح HTTP runtime صلاحية `CREATEROLE`/`CREATEDB` لتعمل الشريحة (يعني أن العزل انهار).

**أكبر المخاطر:** أداء (اتصال PDO جديد لكل طلب بدل إعادة استخدام pool موجود) — غير مقاس هنا، `STATIC_INFERENCE` فقط أن التكلفة الإضافية هي زمن SCRAM handshake واحد إضافي لكل طلب، يحتاج قياسًا حقيقيًا في الشريحة نفسها قبل أي قرار على بيئة بحمل حقيقي.

**ترتيب الشرائح التالية (بالتسلسل المنطقي لا بالتواريخ):**
1. **IMPLEMENT-01** (أعلاه) — gate: GO تنفيذي صريح من المالك + sandbox مستقلة.
2. **Provisioning** (`CredentialProvisioner` + مخزن أسرار حقيقي) — gate: نجاح IMPLEMENT-01 + قرار المالك على أداة مخزن الأسرار.
3. **Migration/Backfill** (`actor_sql_identity_map` + تحويل العضويات الحالية) — gate: نجاح Provisioning على بيئة اصطناعية بحجم بيانات واقعي.
4. **RLS/RBAC الكامل** (تبديل كل الجداول من GUC إلى resolver، لا فقط Leads) — gate: نجاح 3 + مراجعة أمنية مستقلة شاملة (لا Claude وحده).
5. **Queue/Pooling** إن استُحدِثا لاحقًا — gate: قرار معماري مستقل منفصل عند ظهور الحاجة الفعلية (غير موجودة اليوم).
6. **E2E كامل + T4b** — gate: تفويض مستقل صريح، خارج نطاق F06 بالكامل.

**`GO_TO_DESIGN_ACCEPTANCE` ممكن الآن** (هذه الوثيقة). **`GO_TO_IMPLEMENTATION` يحتاج:** تفويضًا صريحًا من المالك + مساحة اختبار مستقلة (sandbox جديدة لم تُستخدَم) + قرار المالك الصريح على الخيار A (أو بديل آخر يقترحه) وعلى أداة مخزن الأسرار المرحلية.

---

## (ك) Delta/Impact Review

- **مقارنة بآخر baseline مُثبَّت:** لا تغيير على أي كود أو DB أو ACL أو RLS فعلي؛ الإضافة الوحيدة هذا الملف. `POC_SOURCE_REFERENCE=PASS_SOURCE_SCOPED` (بصمتا `run_tests.sh`/`003_comparison.sql` مطابقتان حرفيًا للمرجع).
- **Migrations:** لا إنشاء، لا تشغيل. `039` **لم تُنشأ** (نفس حالة كل الجولات السابقة).
- **DB/ACL:** لا تغيير على أي صلاحية أو دور حقيقي.
- **Git:** لا commit/stage. الإضافة الوحيدة ملف تقرير واحد غير متتبَّع بعد.
- **الاعتماديات:** لا حزمة Composer جديدة أُضيفت أو اقتُرحت بالفعل (مخزن الأسرار الخارجي **مذكور كحاجة مستقبلية**، لا كاعتمادية مُضافة الآن).
- **مخاطر الانحدار إن نُفِّذ التصميم لاحقًا:** أداء (handshake SCRAM لكل طلب)، تضخم كتالوج `pg_roles` مع نمو الموظفين، تعقيد تشغيلي إضافي (rotation/provisioning) لم يكن موجودًا، واحتمال كسر أي كود موجود يفترض ثبات اسم اتصال/اعتماد `pgsql_tenant_runtime` الحالي — يحتاج فحصًا كاملًا لكل استدعاء لهذا الاتصال (القائمة في §د موجودة بالفعل: `TenantStaffAccountService`, `TenantStaffAdminInvariant`, `TenantStaffAuthorizationService`, `TenantStaffContextGuard`, `TenantStaffEffectiveAuthorizationService`, `TenantStaffRoleMutationService`, `TenantStaffRequestContext`, `TenantStaffUser`, `TenantStaffAuditWriter`, `LeadService`) — **كل هذه الملفات التسعة ستستخدم نفس `ActorConnectionFactory` دون تغيير منطقها الداخلي**، لأن التبديل يحدث عند لحظة فتح الاتصال فقط، لا عند كل استدعاء.

---

## (ل) قرار التوقف الصريح

**التنفيذ لم يبدأ.** لا migration (ولا 039). لا اتصال ببيئة محمية (G2/RM02/DEV/scratch/POC أي حاوية). لا Git write. لا تعديل على Leads أو RLS أو ACL حقيقية. لا معالجة لـT4b أو F16. لا Customers، لا Production.

---

## أعلام الحالة الإلزامية

```
W0_PRECHECK = PASS
GIT_BASELINE = VERIFIED_LIVE_MATCHES_REPORTED (5/5 HEADs identical; HANDOFF-CURRENT.md text lag explained, not a drift)
POC_SOURCE_REFERENCE = PASS_SOURCE_SCOPED (run_tests.sh=befd0b80…d7a2ba, 003_comparison.sql=579259a8…2cd0b, both verified identical)
ACTUAL_HTTP_TO_SQL_FLOW = DOCUMENTED_WITH_SOURCE_REFS (TenantHostResolver -> TenantStaffRequestContext -> TenantStaffContextGuard -> LeadService -> RLS functions; file:line cited throughout §د)
SELECTED_SQL_IDENTITY_ARCHITECTURE = RECOMMENDED (Option A: per-actor SQL LOGIN + session_user; Option B REJECTED as unrealistic in this architecture — no out-of-PHP trust gateway exists)
PHP_MULTI_CREDENTIAL_COMPROMISE_RISK = OPEN (not contained by this design; no process isolation evidence exists)
CREDENTIAL_PROVISION_ROTATE_REVOKE = DESIGNED_NOT_BUILT (reuses existing NOLOGIN-group + SECURITY DEFINER pattern already in migrations 026/027/037; no secret store exists yet — NOT_FOUND_IN_SCANNED_SCOPE)
QUEUE_POOL_WORKER_POLICY = NOT_FOUND_IN_SCANNED_SCOPE (no Octane/Horizon/ShouldQueue jobs/PgBouncer found in this repo; session-mode-only constraint documented for any future PgBouncer addition)
LEADS_REASSIGNMENT_CONTRACT = PRESERVED_UNCHANGED (LeadService::assignLead ALL_TENANT-only reassignment kept verbatim; POC's absolute-ownership trigger explicitly NOT ported)
T4B_DEPENDENCY = INDEPENDENT_NOT_ADDRESSED (TenantHostResolver's own GUC-on-connection pattern is a separate, undesigned risk)
FIRST_IMPLEMENTATION_SLICE_DEFINED = YES (SECURITY-F06-LARAVEL-IMPLEMENT-01, single read-only HTTP path, scoped sandbox, explicit GO/NO-GO criteria in §ي)
TEST_MATRIX_DEFINED = YES (§ط, 20 IDs across identity/Leads/HTTP-wire/provisioning/threat-containment)
ROLLBACK_AND_DEPLOYMENT_GATES_DEFINED = YES (feature-flag coexistence with current GUC path; rollback = flag off, no data deletion required)
ROOT_DOC_CHANGES = PRESERVED_UNCOMMITTED (3 ROOT docs untouched, still unstaged exactly as found)
POC_UNTRACKED_FILES = UNTOUCHED (tools/ under API untouched)
GIT_COMMIT = NOT_EXECUTED
DOCKER_SQL_RUNTIME = NOT_EXECUTED
MIGRATION_039 = NOT_CREATED_NOT_RUN
G2_RM02_DEV_POC_PROTECTION = PRESERVED_NOT_ACCESSED
F06_PRODUCT_REMEDIATION = NOT_PERFORMED
T4B_REMEDIATION = NOT_PERFORMED
F16_REMEDIATION = NOT_PERFORMED
CUSTOMERS = NO_GO
PRODUCTION = NO_GO
READY_FOR_IMPLEMENTATION_AUTHORIZATION = YES_CONDITIONAL (conditions: owner sign-off on Option A, a secrets-store decision, and a fresh isolated sandbox for IMPLEMENT-01 — none of this exists yet)
```
