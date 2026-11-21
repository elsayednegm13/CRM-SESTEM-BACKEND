# قفل نطاق الملفات بعد G1

`SOURCE_FILE_ALLOWLIST_LOCKED=YES` وفق شيفرة 2026-10-26. تعديل مصدر المنتج مسموح فقط في المسارات التالية وبقدر العملية المبيّن:

1. `app/Modules/Identity/Application/ActorConnectionFactory.php`: تمييز غياب اعتماد mapped actor أو mapping خادم دون fallback؛ لا تغيير منطق switch/reset.
2. `app/Modules/Identity/Domain/Exceptions/ActorSqlUnavailableException.php`: نوع جديد صغير لأن أنواع `TenantAccessException`/`AuthorizationDeniedException` الحالية تعني رفض العميل، ولا تمثل خلل جاهزية الخادم 503.
3. `app/Modules/Shared/Http/ApiErrorResponse.php`: ترجمة النوع المحدد فقط إلى 503 ورسالة عامة؛ بقية الـmatch ثابتة.
4. `app/Modules/Tenancy/Application/LeadService.php`: تصنيف SQLSTATE `42883` عند استدعاء `f06scope_assign_lead` تحت ON فقط؛ فرع OFF ثابت.
5. `app/Modules/Identity/Application/TenantStaffRoleMutationService.php`: تصنيف غياب `f06team01_direct_permission`، ثم G4-B/C branches محددة إذا اجتازت بوابات SQL/HTTP؛ لا تغيير contract عام.
6. `app/Modules/Identity/Application/TenantStaffAccountService.php`: G4-C فقط إذا ثبت عقد disable/reactivate؛ G4-D محجوبة حتى قرار provisioning.

الملفات الجديدة الأخرى محصورة في `tools/security/f06-api-admin-compact-01/` وتقرير واحد `docs/audits/SECURITY-F06-API-ADMIN-COMPACT-01.md`. لا تعديل routes/controllers/middleware/`config/f06_actor_sql.php`/`database/migrations`/`TenantStaffAuthorizationService`/`TenantStaffAdminInvariant`/`TenantStaffAuditWriter`/ROOT/WEB/ADMIN/SUPER. أي حاجة مؤكدة لخارج ذلك تفرض `STOP_SCOPE_EXPANSION_AUTH_REQUIRED` قبل الكتابة.

G2 يحتاج 1–4 والجزء المصنف من 5. G4-A لا تعديل منتج متوقع. G4-B/C لا تبدأ قبل G2b وG3. SQL overlays وfixtures والـharness جديدة داخل مجلد الجولة فقط. الافتراض الإنتاجي: الدالتان 050 و`f06scope_assign_lead` محليتان ولا migration منتج؛ `DEPLOYMENT_NOT_READY` يبقى حتى تفويض منفصل.
