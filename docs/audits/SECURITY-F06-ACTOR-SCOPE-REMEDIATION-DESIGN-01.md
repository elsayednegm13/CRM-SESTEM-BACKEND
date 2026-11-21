<div dir="rtl">

# SECURITY-F06-ACTOR-SCOPE-REMEDIATION-DESIGN-01

## أ) EXECUTIVE_VERDICT

**PARTIAL_DESIGN.** يمكن تحديد حد SQL صحيح لـLeads وشريحة اختبار صغيرة، لكن لا يجوز اعتمادها كعلاج منتج بعد: اعتماد actor يرث حاليًا امتيازات كتابة مصدر الصلاحيات نفسه. لهذا يستطيع SQL حر أن يحاول صناعة grant قبل استدعاء أي سياسة تعتمد عليه. يلزم إغلاق هذه القناة واختبار أثر ذلك على إدارة الفريق والأدوار قبل إعلان `ACTOR_SCOPE_AT_SQL`. التصميم المختار **B+C**: سياسات `RESTRICTIVE` لكل عملية، بهوية `session_user` وصلاحيات فعالة من مصدر محمي؛ وامتيازات أعمدة ضيقة مع وظيفة إعادة إسناد محددة. الشريحة الأولى المقترحة `SECURITY-F06-ACTOR-SCOPE-IMPLEMENT-01` اختبارية على Leads الحقيقي في Sandbox جديدة، مشروطة بقفل كتابة مصدر التفويض هناك، مع اختبار موجب لإعادة إسناد A1. هذا الاسم تخطيطي ولا يفوض التنفيذ.

دليل التشغيل السابق مصنف `DOCUMENTED_PRIOR`: تقرير I03 المستقل داخل نقطة الاسترجاع المذكورة أدناه سجّل HTTP 23/23 تحت كل من FLAG OFF وON ودليل SQL 21/21 لحد الشركة/SET ROLE؛ لم يُعد أي اختبار هنا، وما زال SQL الحر داخل الشركة مفتوحًا. التقرير مرجع خارجي محلي لا يُعد مصدرًا حيًا للكتالوج.

## ب) W0 وسلامة الخط الأساس

قرأنا تعليمات ROOT/API والوثائق المطلوبة، وفحصنا Git قراءة فقط قبل الكتابة وبعدها. الفروع وHEAD: ROOT `master/c2ee5a3a3e128f86147e06d39cd50ca7ff2cf7d9`؛ API `preserve/rm02-rm05-baseline/e8cee07c2c39df5a1531cbd63168695347202371`؛ WEB `master/6fb01b8838de52de621dab4691a5cdd5710c29f6`؛ ADMIN `master/9fa43befadaaa5d4583f8de6bf7a06c60e891bef`؛ SUPER `master/a802e44b8a269071bcb46fcaa675aafb43b12a87`. الثلاثة الأخيرة نظيفة. ROOT يحمل التعديلات الثلاثة المعروفة و`CLAUDE.md` بتصنيف `OWNER_APPROVED_PRE_EXISTING_CHANGE` ومرفقات غير متتبعة؛ API يحمل تعديلات Laravel الثلاثة وملفات I01–I03/POC السابقة غير المتتبعة، بالإضافة إلى هذه الوثيقة وحدها في الجولة. لا يعد عدد الملفات وحده drift. الملف الهدف لم يكن موجودًا. حالة البيئة الحالية `NOT_VERIFIED_LIVE`، وآخر مرحلة تشغيلية موثقة I03؛ المحظور DB/Docker/HTTP/tests/Git write؛ الخطوة التالية تفويض تنفيذ مستقل.

بصمة `CLAUDE.md` قبل الكتابة `a972f9ef6f3e9959bb86687d7ffa9eae096ce9d78c1d3d515cc66e2191e8487a`. نقطة الاسترجاع الخارجية `I:\WORK\DALEEL-CRM-RECOVERY\SECURITY-F06-I03-REVIEW-AND-RECOVERY-01-20261026T051638Z-c12a0835` مقروءة فقط؛ تحقق SHA-256 لـ`manifest/FILES_SHA256.tsv` = `54842a573b1af75fbbca8399bfff04c4534246ddfe8fb68b759d1a678a85ac92`، و`BASELINE.json` يسجل 57 ملفًا و57/57 استعادة سابقة. لم نفحص payload أو نعد الاستعادة هنا. مستندات ROOT التاريخية تلزم تحديث STATUS/DECISIONS بنهاية الجلسة، لكن تفويض هذه الجولة يحصر الكتابة في هذا الملف؛ الحد الأضيق مقدم، وتظل الوثيقة وحدها handoff.

## ج) VERIFIED_SOURCE INVENTORY

كل مراجع هذا القسم `VERIFIED_SOURCE` من الشجرة الحالية، ما لم يرد وسم آخر. المسارات أدناه نسبية لجذر API.

| العقد | الدليل المصدرّي | الاستنتاج المحدود |
|---|---|---|
| Host → tenant | `app/Modules/Identity/Http/Middleware/ResolveTenantHost.php:14-30`؛ `app/Modules/Identity/Application/TenantHostResolver.php` | `getHost()` يمر إلى resolver ثم `tenant_host_context`؛ لا يأتي tenant من body. ثقة proxy/Host تشغيلية خارج إثبات SQL. |
| session → user/membership | `app/Modules/Identity/Application/TenantStaffContextGuard.php:15-36,48-66,69-115`؛ `app/Modules/Identity/Domain/TenantStaffContext.php:5-14` | يطابق tuple المخزن مع Host، ويعيد فحص tenant/staff/membership و`auth_version`/`authorization_version`؛ المسار القديم يكتب GUC على اتصال runtime. |
| FLAG OFF/ON | `app/Modules/Identity/Http/Middleware/TenantStaffRequestContext.php:29-45,80-90,104-185`؛ `config/f06_actor_sql.php:9-19,28-36` | OFF افتراضيًا؛ ON مقيد بقائمة البيئة القابلة للضبط، افتراضيها testing. OFF يستخدم اتصالًا مشتركًا؛ ON يتحقق أولًا على bootstrap ثم يبدل الاعتماد قبل المعاملة ويعيد الاتصال في `finally`. لا يُنسب ذلك إلى منتج العملاء. |
| bootstrap/actor | `app/Modules/Identity/Application/TrustedActorBootstrapVerifier.php:26-52`؛ `ActorSqlIdentityResolver.php:19-27`؛ `ActorConnectionFactory.php:45-75,78-103` | bootstrap يرجع اسم SQL لدور مطابق؛ خريطة كلمة المرور صناعية؛ `switchTo` يفحص `session_user` ويرفض التبديل وسط معاملة. كلمة مرور actor الآخر أو اختراق PHP خارج ضمان هذا الحد. |
| HTTP Leads | `routes/api.php:90-96`؛ `app/Modules/Tenancy/Http/Controllers/LeadController.php:13-86,89-95` | list/show/create/update/stage/assign/archive تمر إلى LeadService؛ DELETE HTTP يعني archive وليس `DELETE FROM leads`. |
| التخزين الفعلي للمنح | `app/Modules/Identity/Application/TenantStaffAuthorizationService.php:75-125`؛ `app/Modules/Identity/Domain/EffectivePermissions.php:16-60,63-78` | union موجب لـ`tenant_staff_membership_roles` غير الملغاة مع `roles` ACTIVE غير مؤرشفة، ثم `role_permissions`، ومعها `tenant_staff_permission_grants` المباشرة غير الملغاة؛ يتحقق catalog `permissions` من ACTIVE وscopeable وallowed_scopes وdelegable. `NONE` لا يمنح، و`ALL_TENANT` يهيمن. البيانات غير السليمة ترفض كامل snapshot. لا يكفي role name ولا user_id وحده. |
| الجداول والمفاتيح | `database/migrations/2026_10_06_000005_create_rbac_reference_tables.php:12-25`؛ `000006_create_tenant_rbac_tables.php:12-41`؛ `2026_10_11_000023_create_tenant_staff_users.php:12-30,38-67`؛ `000024_create_tenant_staff_membership_access.php:12-40,105-139` | `permissions(key,status,scopeable,allowed_scopes,delegable)`؛ `roles(id,tenant_id,status,archived_at)`؛ `role_permissions(tenant_id,role_id,permission_key,scope)`؛ `tenant_staff_users(id,tenant_id,status,auth_version)`؛ `tenant_staff_memberships(id,tenant_id,staff_user_id,status,authorization_version)`؛ assignment/direct grant يملكان `revoked_at`، وFK مركبة tenant+id. `membership_roles` القديم ليس مصدر الخدمة الجديدة. |
| النسخ والإبطال | `TenantStaffAccountService.php:78-112`؛ `TenantStaffRoleMutationService.php:122-135,167-179,224-228` | تعليق العضوية يزيد `authorization_version`؛ تغيير التعيين/المنحة يزيده. `auth_version` مستقل على staff. القراءة من SQL أثناء معاملة لا تعني إبطالًا لحظيًا لكل snapshot قائم. |
| leads/schema | `database/migrations/2026_10_23_000036_create_leads.php:30-44,46-87` | 18 عمودًا؛ `assigned_membership_id` nullable و`created_by_membership_id` غير nullable؛ FK مركبة إلى العضويات؛ فهارس `(tenant_id,pipeline_stage)`, `(tenant_id,assigned_membership_id)`, `(tenant_id,status)`؛ لا `UNIQUE(tenant_id,code)` ولا قفل creator في الجدول. |
| سياسات leads المنتج | `000036_create_leads.php:81-87`؛ `2026_10_06_000008_enable_tenant_rls.php:13-34` | ENABLE+FORCE. `leads_tenant_select` SELECT/USING؛ `leads_tenant_insert` INSERT/WITH CHECK؛ `leads_tenant_update` UPDATE/USING+WITH CHECK؛ `leads_tenant_delete` DELETE/USING. كلها `PERMISSIVE TO PUBLIC` افتراضيًا لغياب AS/TO، وتعتمد `app.context_mode` و`app.tenant_id` القابلين للتزوير. دوال 008 `STABLE SECURITY INVOKER` وتعيد NULL لهوية UUID غائبة/باطلة. |
| ACL المنتج | `2026_10_12_000026_create_tenant_staff_authentication_access.php:60-68,223-236`؛ `2026_10_24_000037_grant_tenant_runtime_phase2_write_contract.php:16-40`؛ `000038_narrow_tenant_runtime_select_grants.php:19-46` | 026 يمنح SELECT لأعمدة التفويض ويقيّد `lookup_tenant_staff_credentials` إلى auth client بعد REVOKE PUBLIC؛ 037 يمنح runtime SELECT/INSERT لكل أعمدة leads وUPDATE للأعمدة المحددة، بلا DELETE/TRUNCATE/REFERENCES مصرح بها في 037، ويمنح كتابة `role_permissions` وassignment/direct grants. 038 يسحب أعمدة أخرى، لا يغيّر leads. الامتياز الفعلي في الكتالوج `NOT_VERIFIED_LIVE`. |
| fixtures منفصلة | `tools/security/f06-laravel-i03/000_provision_roles.sql:96-99`؛ `002_actor_sql_fixture.sql:17-49,91-99` | عضوية المجموعة `ADMIN FALSE, INHERIT TRUE, SET FALSE`، mapping صناعي وresolver `session_user→tenant_id` وسياسة `RESTRICTIVE` للـactor على tenant فقط؛ ليست migrations منتج، ولا تستخرج نطاق ASSIGNED/SELF. الاعتماد الاسمي لثلاثة actors وA4 في `TO` غير صالح كعقد provisioning عام. |

`app/Modules/Tenancy/Application/LeadService.php:28-45,48-61,65-99,102-171,173-219` هو مسار CRUD المنطقي الوحيد الذي وجده بحث `leads` في `app` و`routes`؛ لم نجد مسار كتابة آخر داخل `app`، لكن ذلك لا يثبت غياب views أو functions أو grants مضافة في قاعدة حية (`NOT_VERIFIED_LIVE`). migration 027 تنشئ سياسات وكاتب provider لأول admin (`2026_10_14_000027_enable_provider_first_admin_bootstrap.php:64-80,83-154`)؛ ليست سياسة Leads. المالك الحي لـ`leads` والدوال، PUBLIC EXECUTE الفعلي، عضوية كل role وسلاسلها، grants الموروثة، views/triggers والـDDL في catalog: `NOT_VERIFIED_LIVE`. مصدر 036 لا يحدد `OWNER TO`، لذا لا نخمن مالك الجدول من fixture سابقة.

## د) CURRENT_PERMISSION_MATRIX

| العملية | ALL_TENANT | ASSIGNED | SELF | حد المصدر |
|---|---|---|---|---|
| SELECT list/show | `leads.view` يرى الشركة؛ list فقط ACTIVE | يرى `assigned_membership_id = membershipId` | يرى `created_by_membership_id = membershipId` | `LeadService.php:28-61,190-219`؛ show لا يرشح status. اجتماع ASSIGNED+SELF = OR. NULL assignment لا يطابق ASSIGNED؛ creator غير NULL. |
| INSERT | `leads.manage` يقبل assignment المرسل، حتى NULL؛ FK يثبت الشركة لا ACTIVE | `leads.manage` يجبر assignment إلى نفسه | مثله: يجبر assignment إلى نفسه | `LeadService.php:65-99`؛ `LeadController.php:28-44`. استرجاع النتيجة عبر `getLead` يتطلب أيضًا `leads.view`، وقد يفشل/يرجع رفضًا إذا أسندها ALL_TENANT لغيره مع view أضيق. |
| UPDATE حقول/مرحلة | `leads.manage` على أي Lead بالشركة | على المسند إليه | على المنشأ منه | `LeadService.php:102-143,173-203`؛ بعد التحديث يستدعي `getLead` الذي يتطلب `leads.view`. الحقول لا تشمل tenant/creator/assignment. |
| ASSIGN | فقط `leads.manage:ALL_TENANT`؛ العضو الهدف ACTIVE ومن نفس الشركة | مرفوض | مرفوض | `LeadService.php:146-164`. هذا مسار مشروع يجب الحفاظ عليه؛ إنشاء Lead من ALL_TENANT إلى عضو آخر ليس هو `assignLead`. |
| DELETE | لا DELETE فعلي عبر HTTP؛ archive بـ`leads.manage`/نطاق الصف | archive داخل نطاق manage | archive داخل نطاق manage | `LeadService.php:166-171`؛ `routes/api.php:96`. SQL DELETE يجب أن يرفض حتى مع view/manage إلى أن يوجد عقد منتج. |

ليس هناك `leads.create/read/update/delete` مفاتيح مستقلة في migration 036؛ المفاتيح الحقيقية `leads.view` و`leads.manage`، والأخير يغطي الإنشاء والتعديل والأرشفة فقط، مع استثناء assign. نطاقات الدور والمباشر تتحد، ولا يجوز اختزالها إلى نطاق واحد. سياسة SQL SELECT المقترحة تستخدم `view`، وسياسة التعديل تستخدم `manage`؛ تداخل SELECT المطلوب لـ`UPDATE WHERE/RETURNING` ومسار `getLead` يجعل حالة manage بلا view بحاجة لاختبار عقدي صريح، ولا نمنحها قراءة SQL واسعة ضمنيًا.

## هـ) THREAT_MODEL

**T1** A4/A2 يملك اعتماد PostgreSQL الشخصي وSQL حر على اتصاله؛ يستطيع `set_config` ومحاولة `SET ROLE` وتحديث جداول يملك عليها grant. لا يملك CREATEROLE/BYPASSRLS أو كلمة مرور غيره في نموذج الاختبار. اليوم سياسات 036 تضع حد tenant فقط، وfixture I03 تضيف حد tenant بـ`session_user`؛ لذلك قد يقرأ/يغير Lead زميل داخل A دون المرور بفلتر PHP. **T2** A1 صاحب `leads.manage:ALL_TENANT` يجب أن يعيد الإسناد المشروع. **T3** تغيير grant/حالة العضوية/الإسناد أثناء معاملة قد يظهر بتأخر وفق snapshot، لذا يحدد التصميم ضمان statement/commit ولا يعد بإبطال فوري. **T4** من يملك عملية PHP واعتمادات actors متعددة يستطيع فتح اتصال باسم آخر؛ يبقى OPEN. **T5** حد A/B ورفض SET ROLE الجماعي يجب إعادة إثباتهما بعد كل تعديل.

المخاطر الأخرى: `PUBLIC EXECUTE` الافتراضي للدوال الجديدة، `search_path` يشمل schema أو temp غير موثوقة، owner أو BYPASSRLS، `TRUNCATE`/DDL/`REFERENCES` خارج RLS، view أو `SECURITY DEFINER` يفتحان طريقًا موازيًا، JOIN/`UPDATE RETURNING` يكشفان الصف، وFK/UNIQUE قد تكون oracle للوجود. في leads الفعلي لا يوجد unique `(tenant_id,code)`؛ المفتاح UUID وFK العضوية موجودان، فلا ننقل مخاطر POC المصطنعة حرفيًا. وثائق PostgreSQL 16 تؤكد OR/AND، تجاوز owner المعتاد إلا FORCE، واستثناء `TRUNCATE`/`REFERENCES` وفحوص التكامل المرجعي؛ [RLS](https://www.postgresql.org/docs/16/ddl-rowsecurity.html)، [CREATE POLICY](https://www.postgresql.org/docs/16/sql-createpolicy.html).

## و) ALTERNATIVES_AND_DECISION

| الخيار | الأثر | القرار |
|---|---|---|
| A: tenant RLS + فلتر Laravel | دلتا صفر وأداء معلوم؛ HTTP الصحيح لا يمنع T1 أو SQL حر، والـGUC قابل للتزوير | مرفوض لإغلاق actor scope. |
| B: RESTRICTIVE actor RLS من `session_user` ومنح فعالة | صغير نسبيًا في Leads، يقيّد SELECT/INSERT/UPDATE ويعمل مع سياسة tenant الموجودة؛ lookup لكل صف وسطح revocation/ACL معقد. وحده لا يحمي مصدر grants القابل للكتابة ولا يفرق OLD/NEW لحماية assignment في SELF | أساس مختار بشرط حماية مصدر التفويض، غير كاف وحده. |
| C: وظائف محددة + سحب direct writes | يسمح بضبط إعادة الإسناد وOLD/NEW؛ زيادة دالة/ACL ومسار Laravel ومراجعة definer؛ لا يفترض أن definer يتجاوز FORCE RLS | يضاف إلى B لعمود assignment فقط في أول شريحة، مع مالك غير runtime وEXECUTE محدود. |

الترجيح B+C. يجب قفل INSERT/UPDATE/DELETE على `role_permissions`, `tenant_staff_membership_roles`, `tenant_staff_permission_grants` وكتابة `roles`/`tenant_staff_memberships` المؤثرة في التفويض عن actors في Sandbox الشريحة، أو توفير وظائف إدارة مؤهلة بمرساة SQL حقيقية ضمن شريحة أوسع. المصدر الحالي يمنح هذه الكتابة للمجموعة (`000037...:16-34`) وسياسات 024 تسمح في حد tenant/GUC بالكتابة من actor نشط (`000024...:195-205`). مجرد قراءتها من definer لا يجعلها موثوقة. سحبها سيؤثر في HTTP إدارة الفريق والأدوار تحت FLAG ON؛ لذلك لا يكتمل GO المنتج حتى يُقرر عقد تلك المسارات ويثبت مستقلًا. لا نضيف خدمة أو تبعية جديدة.

## ز) TARGET_RLS_AND_ACL_CONTRACT

هذا **منطق مواصفة، ليس SQL قابلًا للتطبيق**؛ أسماء الدوال والجداول المقترحة غير موجودة في migrations المنتج. مرساة الهوية: جدول mapping محمي وفريد `sql_role_name → (tenant_id,membership_id,staff_user_id)`، يملكه دور NOLOGIN مخصص لا يملك actor عضويته ولا SELECT/UPDATE عليه؛ resolver `SECURITY DEFINER` مؤهل EXECUTE فقط لدور actor runtime. يعتمد `session_user` حصريًا، ويتحقق من تطابق tenant/staff/membership وACTIVE لكل من tenant/staff/membership، ومن عدم وجود mapping مكرر/معطل. غياب mapping أو اختلافه يعيد DENY/NULL. `auth_version` و`authorization_version` من session للتحقق قبل الاتصال كما الآن؛ سياسة SQL لا تعتمد GUC أو tuple مرسل للتفويض، وتقرأ الحالة والمنح الملتزمة من الجداول المحمية. يلزم تصميم provisioning/تعطيل mapping منفصل قبل الإنتاج.

دالة `has_scope(op, row)` المقترحة تعيد true فقط عند grant فعلي صالح لاسم `leads.view` أو `leads.manage`: role assignment غير ملغى، role ACTIVE وغير مؤرشف، أو direct grant غير ملغى و`delegable=true`؛ permission ACTIVE وscopeable=true والنطاق في `allowed_scopes`، مع سلوك fail closed للبيانات غير الصالحة كما `EffectivePermissions`. `ALL_TENANT` أو `ASSIGNED` بمطابقة assignment أو `SELF` بمطابقة creator. `TEAM` و`NONE` وNULL لا يمنحون صف Lead. يجب منع تعديل الجداول المرجعية من actor SQL قبل الاعتماد على الدالة. يملك definer حقوق SELECT اللازمة فقط على أعمدة الجداول، ولا يملك BYPASSRLS أو leads أو CREATE في schema غير موثوقة؛ السياسة على جداول المرجع نفسها قد تمنع lookup، فيلزم إثبات ACL/RLS لكل قراءة دون منح SELECT شامل للـactor. الدوال مؤهلة schema بالكامل و`search_path` موثوق مع `pg_temp` أخيرًا، وREVOKE PUBLIC EXECUTE في المعاملة نفسها؛ [CREATE FUNCTION](https://www.postgresql.org/docs/16/sql-createfunction.html).

منطق السياسات `AS RESTRICTIVE TO <actor-runtime-group>`، المجموعة ذات `INHERIT TRUE, SET FALSE`، مع تدقيق جميع سلاسل العضوية الحالية والمستقبلية؛ لا يكفي TO قائمة A1/A2/A4/B1. السياسات الحالية PERMISSIVE تعطي قاعدة السماح، والقيد الجديد AND فوقها؛ عند وصول actor جديد بلا mapping يفشل مغلقًا، لكن لا يُسمح له بتجاوز المجموعة عبر grant مباشر. مسار shared bootstrap/OFF لا يدخل الضمان، ويحظر في gate المنتج. `SET ROLE` إلى المجموعة أو actor آخر يرفض؛ حتى لو تغير `current_user` يجب أن يظل `session_user` هو المرساة وأن تنطبق السياسة، وإلا STOP. [Role membership](https://www.postgresql.org/docs/16/role-membership.html)، [GRANT](https://www.postgresql.org/docs/16/sql-grant.html).

| الأمر | USING على OLD | WITH CHECK على NEW | ACL إضافي |
|---|---|---|---|
| SELECT | `identity_valid ∧ tenant_match ∧ has_scope(view,row)` | لا ينطبق | SELECT أعمدة leads التي يحتاجها LeadService فقط؛ COUNT/JOIN/RETURNING لا يرى خارج النطاق. |
| INSERT | لا ينطبق | `identity_valid ∧ tenant_match ∧ has_manage_for_new ∧ created_by = actor.membership_id ∧ (manage:ALL_TENANT ? target=NULL أو عضوية ACTIVE في الشركة : assigned=actor.membership_id)` | إبقاء INSERT للأعمدة اللازمة؛ FK وحده لا يثبت ACTIVE. ALL_TENANT يستطيع NULL بحسب `createLead`. |
| UPDATE | `identity_valid ∧ tenant_match ∧ has_scope(manage,OLD)` | `identity_valid ∧ tenant_match ∧ has_scope(manage,NEW)` | لا UPDATE لـtenant_id/created_by/id. اسحب UPDATE المباشر لـ`assigned_membership_id` عن actors؛ وظيفة إعادة إسناد مؤهلة تتحقق من OLD/NEW و`manage:ALL_TENANT`. تحديث حقول عادية يحافظ على assignment. |
| DELETE | false لكل actor | لا ينطبق | لا DELETE grant؛ الأرشفة UPDATE status داخل manage. |

السياسة وحدها لا تقارن OLD وNEW، ولا تكفي لتمنع SELF من تبديل assignment مع بقاء creator مطابقًا. لا تستعمل trigger يمنع كل نقل؛ وظيفة reassignment ضيقة تتحقق داخل المعاملة من actor mapped و`leads.manage:ALL_TENANT`، صف الشركة، العضو الهدف ACTIVE، ثم تحدّث assignment وتعيد صفًا ضمن نطاق view المشروع. إما يملكها owner خاضع لـFORCE مع سياسة صريحة تسمح بهذا المسار المؤهل، أو دور مخصص بامتياز UPDATE ضيق وسياسات محددة؛ **لا** نفترض أن SECURITY DEFINER يعفي من FORCE. يحظر منح EXECUTE إلى PUBLIC/shared bootstrap/actor غير معتمد، ويحظر إدخال actor/tenant كحجة سلطة. لا تمنح الوظيفة UPDATE عامًا أو SQL ديناميكيًا.

حالات `WITH CHECK`: قيمة NULL للهوية/الصلاحية تعني deny؛ `UPDATE 0`/`SELECT 0` خارج النطاق ليس SQLSTATE 42501 بالضرورة؛ مخالفة WITH CHECK غالبًا 42501؛ غياب grant 42501؛ FK قد يعطي 23503 وUNIQUE قد يعطي 23505، وليسا إثباتًا بأن RLS صحيح. Syntax error لا يدخل دليل الحماية. يجب توثيق كل نتيجة مع rc وSQLSTATE والصفوف. [CREATE POLICY](https://www.postgresql.org/docs/16/sql-createpolicy.html).

## ح) LEADS_REASSIGNMENT_AND_REVOCATION_IMPACT

`assignLead` الحالي يشترط `manage:ALL_TENANT`، ثم يفحص عضوية الهدف ACTIVE ويحدث assignment (`LeadService.php:146-164`). تحديث ASSIGNED من صف مسند إليه إلى زميل يُرفض بسبب WITH CHECK الجديد؛ تحديث SELF قد يبقى داخل SELF لو تغير assignment، لذا يسد سحب امتياز العمود المسار. ALL_TENANT يستخدم وظيفة مؤهلة؛ `LeadService::assignLead` يحتاج تعديل call فقط بعد إثبات parity. SQL INSERT يفرض creator هو actor ويقيد assignment؛ هذا أشد من FK لكنه يطابق إنشاء الخدمة. `created_by` لا يتحول عند إعادة الإسناد؛ منشئ SELF يستمر في رؤية Lead حتى إن نقل assignment، بينما ASSIGNED يفقده. NULL assignment يظهر لـALL_TENANT وSELF للمنشئ، ولا يظهر لـASSIGNED. لا يُضاف trigger قفل مالك أو unique من POC.

حالة العضوية/المنح بعد COMMIT جديد تظهر وفق snapshot لكل statement في READ COMMITTED، لكن statement/transaction قائم قد يستمر بمعلومة قديمة، وSELECT/UPDATE مقفول أو تابع لـsubquery قد يواجه race كما تحذر وثائق RLS. لا ادعاء revocation لحظي؛ يلزم اختبار معاملتين وتحديد الحاجة إلى قفل صفوف membership/grants أو إبطال الاتصال عند التعليق/تدوير كلمة المرور. version checks في bootstrap تمنع session قديمة في الطلب التالي، وليست حاجزًا كافيًا أمام اتصال actor قديم يظل حيًا. حالة دور معطل/SQL credential قديم تُراجع في provisioning. قرار المالك قبل توسيع المنتج: هل يسمح بنطاق Leads مع تعطيل كتابة إدارة الصلاحيات مؤقتًا في Sandbox الاختبار، أم تُضم وظائف إدارة الأدوار الآمنة إلى الشريحة التالية؟ أثرها الوظيفي مانع لقبول FLAG ON عام.

## ط) TEST_MATRIX

كل الصفوف **DEFINED_NOT_EXECUTED**. بيئة مستقبلية: PostgreSQL 16 جديدة مع 38 migration الحقيقية، بيانات A/B صناعية، A1 view/manage ALL_TENANT، A4 view/manage ASSIGNED، A2 view/manage SELF، B1 منفصل؛ صفوف تشمل A4 assigned لم ينشئه، صفًا أنشأه A4 وأسند لغيره، صفًا أنشأه A2 وأسند لغيره، وصفًا مسندًا A2 أنشأه غيره، وصف NULL. اعزل كل SQL هجومي داخل معاملة rollback وبصمات قبل/بعد مع مقارنة rowcount وحقول حساسة؛ لا تمس G2/acceptance أو suites تاريخية. `HTTP` يشير إلى LeadController/LeadService الحقيقيين مع login/CSRF/Host؛ أرقام الأكواد المتوقعة وفق الاستثناءات الحالية وتحتاج إثبات على wire.

| ID | الفعل والضابط | المتوقع والدليل المستقبلي |
|---|---|---|
| S01 | A1 SELECT/COUNT داخل A ثم B؛ A4 ASSIGNED وA2 SELF على الأربعة المتقاطعة | A1 يرى كل A المصرح بها ولا B؛ A4 يرى assigned فقط؛ A2 يرى created فقط؛ `rc=0` مع IDs/COUNT محددة، لا مجرد SQL ناجح. SQL gate. |
| S02 | A4/A2 SQL SELECT وJOIN على Lead زميل، وتبديل GUC إلى B | `0 row`, `COUNT=0`, `rc=0`؛ SQL gate يثبت الضوابط الموجبة و`session_user` لكل A1/A2/A4/B1. |
| S03 | A4/A2 UPDATE حقل عادي على صف داخل النطاق وخارجه، ثم `UPDATE ... RETURNING` | داخل النطاق `UPDATE 1` حيث view/manage متوافقان؛ خارجه `UPDATE 0`، RETURNING صفر؛ بصمة rollback. |
| S04 | A4/A2 INSERT بأنفسهم، ثم محاولة creator آخر/tenant آخر/assignment زميل أو NULL | الموجب `INSERT 0 1` ثم SELECT مسموح؛ المخالف يرفض policy 42501 أو 0 حسب الصياغة، بلا أثر؛ لا تُقبل 23503 وحدها. |
| S05 | A4 ينقل assignment إلى غيره، A2 يغير assignment مع بقاء creator، ويحاولان تعديل created_by/tenant_id | 42501 بسبب ACL العمود/الـpolicy؛ لا أثر. اختبار OLD/NEW يشمل تغيير normal field مع assignment متزامن من معاملة ثانية. |
| S06 | A1 عبر `assignLead` يعيد إسناد صف A إلى عضو A ACTIVE ثم يحاول هدف B/SUSPENDED | الأول HTTP 200 وSQL UPDATE 1؛ المخالف HTTP 422، أو رفض policy/الوظيفة إذا SQL حر؛ A4/A2 HTTP 403 وSQL 42501. |
| S07 | A4/A2 SQL DELETE لصف داخل/خارج النطاق وHTTP archive مشروع | DELETE 42501 بسبب ACL؛ archive HTTP ناجح بحسب manage/view، status فقط ARCHIVED؛ لا physical deletion. |
| S08 | SQL حر يمنح لنفسه `leads.manage:ALL_TENANT` عبر role_permissions/direct grants/roles/assignment | 42501 على كتابة مصدر الصلاحيات في Sandbox؛ ثم S02/S03 يظلان رفضًا. بدون هذه البوابة لا PASS. |
| S09 | `SET ROLE` المجموعة/actor آخر، سلسلة عضوية جديدة، mapping مفقود/معطل، PUBLIC EXECUTE وتجربة definer | SET ROLE 42501/rc≠0، الدور الجديد لا يتجاوز actor policy؛ mapping مفقود صفر صف/42501، لا EXECUTE عام؛ كتالوج + SQL gate. |
| S10 | تعليق actor وتغيير grant/role/version، credential قديم، معاملتان متوازيتان | طلب لاحق يرفض 401؛ SQL statement بعد commit يرفض بحسب snapshot المعرّف؛ سجل نافذة المعاملة القائمة، بلا ادعاء إبطال فوري. |
| S11 | FLAG OFF ثم ON على LeadController/LeadService الحقيقيين، Host B، CSRF، worker/request reuse | OFF يمثل legacy فقط؛ ON يثبت APP_HTTP_RBAC مستقلًا وSQL actor scope؛ HTTP 200/201/403/401/419 المتوقعة حسب الحالة. Worker حقيقي `NOT_VERIFIED` حتى اختبار مخصص. |
| S12 | ضوابط سلبية في Sandbox جديدة: حذف actor restrictive أو إعادة grant كتابة المصدر أو السماح SET ROLE | harness يفشل عمدًا ويكشف تسريب/تغيير واحد على الأقل؛ بعدها الإصلاح وإعادة gate الكامل، و3 جولات بعد آخر تعديل إن كان متناسبًا. |

نتائج البوابة منفصلة: `ACTOR_SCOPE_AT_SQL`, `TENANT_BOUNDARY_AT_SQL`, `APP_HTTP_RBAC`. لا ترفع PASS من 42501 على جدول غير قابل للوصول أصلًا: أثبت أولًا SELECT/UPDATE/INSERT موجبًا تحت الاعتماد نفسه. صنف 42501 و23503/23505 و0 صف وrc على حدة. نفذ plan/EXPLAIN على حجم واقعي لاحقًا؛ لا benchmark الآن.

## ي) MINIMAL_IMPLEMENTATION_SLICE

`SECURITY-F06-ACTOR-SCOPE-IMPLEMENT-01` المقترحة، غير منفذة:

1. **CREATE في Sandbox جديدة فقط:** fixture SQL لهوية actor/mapping محمي، دوال تحقق grant وpolicies الأربعة لـleads، ACL عمود assignment ووظيفة إعادة إسناد، وharness SQL/HTTP مستقل. لا تعديل migration المنتج 036 ولا إنشاء 039 في هذه المرحلة. استخدم أسماء roles غير hardcoded عبر group membership وفحص catalog بعد provisioning.
2. **MODIFY متوقع بتفويض لاحق:** `app/Modules/Tenancy/Application/LeadService.php` لمسار `assignLead` إلى الوظيفة الضيقة؛ وربما `config/f06_actor_sql.php` لتسمية دالة الاختبار فقط. اختبارات عقد LeadController/LeadService الحالية أو ملف اختبار جديد مع بيانات حقيقية في Sandbox. لا تعديل WEB/ADMIN/SUPER/ROOT.
3. **بوابة لازمة قبل S01:** سحب امتيازات الكتابة المباشرة عن جداول الصلاحيات للـactor في Sandbox، وتدقيق direct/membership/role grant paths. إذا تعذر هذا دون كسر عقد إدارة الأدوار/الموظفين المطلوب في نطاق قبول المرحلة، `BLOCKED` وحدد قرار التفويض؛ لا تقبل سياسة Leads تعتمد على grants قابلة للتغيير من T1.
4. **HTTP الأدنى:** A1 إنشاء/عرض/تعديل/assign، A4 ASSIGNED وA2 SELF list/show/update/رفض assign، archive المسموح، مع FLAG ON؛ FLAG OFF مقارنة سلوك legacy فقط. لا تستخدم Closure بديلًا للخدمة ولا suites التاريخية المحمية.

التبعيات: actor login وmapping موثوق → حماية جداول grants → دالة effective grants → RLS SELECT/INSERT/UPDATE/DELETE → ACL/وظيفة assign → HTTP parity → negative controls → مراجعة أثر الأداء/التراجع. يمكن اختبار ذلك على leads الحقيقي من migration 036 داخل Sandbox جديدة بلا تعديل migration المنتج؛ نشر migration منتج لاحقًا يحتاج خطة بيانات وcatalog وفحص grants/owner وترتيب نشر atomically. تراجع Sandbox بإزالة fixture داخل Sandbox وإعادة بنائه؛ إطفاء FLAG في المنتج يعيد مسار GUC غير المحمي، فلا يُعد rollback أمنيًا مقبولًا. migration 039 غير منشأة وغير مشغلة.

## ك) DELTA_IMPACT_REVIEW

الدلتا المصرح بها هذه الوثيقة فقط؛ لا كود أو SQL أو schema أو grants أو Composer أو اختبار أو Git write. سياسات RLS المستقبلية تضيف lookups على كل صف وقد تعطل تحسينات الخطة؛ فهارس مصدر grants القائمة يجب قياسها مقابل `session_user` mapping و`(tenant_id,membership_id,revoked_at)`، وLeads يملك فهرس tenant+assignment لكنه لا يملك tenant+creator؛ لا تضف فهرسًا قبل EXPLAIN واقعي. `STABLE` قد يعيد استخدام نتيجة ضمن statement لا عبر commit بالضرورة؛ توثيق snapshot والرصد مطلوب. `SECURITY DEFINER` لا يضمن سلامة إذا كان owner يستطيع تجاوز RLS أو كان `search_path`/EXECUTE واسعًا. لا صلاحيات table owner أو BYPASSRLS للـactors، ولا `CREATE` في schemas موثوقة، ولا TRUNCATE/DDL/REFERENCES؛ تحقق catalog حيّ لاحقًا. أثر إغلاق grants على Staff/Role HTTP هو الدَّين الحاسم. خطر اختراق PHP متعدد الاعتمادات، T4b، F16، provisioning/secret store، worker reuse والإبطال أثناء المعاملة تبقى مفتوحة.

## ل) GO_NO_GO_AND_STOP

`GO` فقط لتصميم شريحة Sandbox مشروطة بتفويض جديد وبقفل مصدر المنح واختبار reassignment موجب. `NO_GO` لتنفيذ الآن، ولقبول F06 منتجًا، ولـCustomers/Production. إذا ظهر drift غير مفسر في HEAD أو ملف مصدر معتمد، أو عجز عن حماية جداول grants مع الحفاظ على المسارات المطلوبة، توقف قبل أي كتابة/تشغيل جديد.

```text
W0_PRECHECK = PASS
GIT_BASELINE = VERIFIED
OWNER_APPROVED_ROOT_CLAUDE = PRESERVED_UNCHANGED
RECOVERY_57_FILE_CHECKPOINT = REFERENCED_READONLY_VERIFIED_SHA
ACTUAL_LEADS_RBAC_CONTRACT = VERIFIED_SOURCE
ACTUAL_PERMISSION_STORAGE_AND_GRANTS = VERIFIED_SOURCE
CURRENT_RLS_POLICY_INTERACTION = VERIFIED_SOURCE
TENANT_SQL_BOUNDARY = DOCUMENTED_PRIOR_NOT_RETESTED
ACTOR_SCOPE_SQL_ARBITRARY = OPEN_DOCUMENTED_PRIOR
SET_ROLE_GROUP_CORRECTION = DOCUMENTED_PRIOR_NOT_RETESTED
SELECTED_ACTOR_SCOPE_ARCHITECTURE = RECOMMENDED_WITH_REASON
ASSIGNLEAD_ALL_TENANT_CONTRACT = PRESERVED_IN_DESIGN
RLS_USING_AND_WITH_CHECK_CONTRACT = SPECIFIED
SQL_AUTHZ_DEF_AND_ACL_RISK = ASSESSED
FIRST_IMPLEMENTATION_SLICE = DEFINED_NOT_EXECUTED
TEST_MATRIX = DEFINED_NOT_EXECUTED
DESIGN_DOC_ONLY_NEW_FILE = YES
GIT_COMMIT = NOT_EXECUTED
DOCKER_SQL_HTTP_RUNTIME = NOT_EXECUTED
MIGRATION_039 = NOT_CREATED_NOT_RUN
F06_PRODUCT_REMEDIATION = NOT_PERFORMED
ACTOR_SCOPE_ARBITRARY_SQL = OPEN
PHP_MULTI_CREDENTIAL_COMPROMISE_RISK = OPEN
T4B_REMEDIATION = NOT_PERFORMED
F16_REMEDIATION = NOT_PERFORMED
CUSTOMERS = NO_GO
PRODUCTION = NO_GO
NEXT_GATE = OWNER_SCOPED_ACTOR_SCOPE_IMPLEMENTATION_AUTHORIZATION_OR_TARGETED_DESIGN_DECISION
```

</div>
