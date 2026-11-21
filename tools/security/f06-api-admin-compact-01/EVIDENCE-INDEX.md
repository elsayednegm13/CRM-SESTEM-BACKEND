# فهرس أدلة SECURITY-F06-API-ADMIN-COMPACT-01

كل JSON هنا منقح ولا يحتوي كلمات مرور أو body خام. ملفات HTTP الخام وسجلات Laravel وsecrets التجريبية بقيت في `C:\Users\NEGM\AppData\Local\Temp\f06-compact01-44e1ef49-902l521d` خارج المستودع، ولا تُنقل مع التقرير.

| الملف | الدليل | الحد |
|---|---|---|
| `CHANGE_SCOPE.tsv`, `DELTA-SHA256.tsv` | بصمات preimage/delta | لا تُثبت runtime |
| `CONTRACT_MATRIX.md`, `ALLOWLIST.md` | G1 المصدر والحدود | مصدر فقط |
| `g2_source_gate.php` | missing credential/unmapped/missing function typed | بلا DB |
| `g2_http_evidence.json` | E1/E2/E4 direct، 503، body hash، fingerprint | Laravel HTTPS |
| `g2_http_assign_clone_evidence.json` | E4 assign في نسخة DB مع غياب الوظيفة | clone فقط |
| `g2_http_mapping_clone_evidence.json` | E3 role مجهول في clone | clone فقط |
| `http_admin_evidence.json` | 38 نتيجة OFF/ON وأثر grant/version/audit والرفض | A5 الضيق وGET فقط |
| `sql_scope_evidence.json` | 31 اختبار SQL لـLeads/tenant/SET ROLE | rollback |
| `g5_sql_evidence.json` | grant/revoke موجب و6 سلبيات SQLSTATE 42501 | rollback |
| `negative_mutation_evidence.json` | 2/2 كشف فساد policy/ACL واستعادة | rollback |
| `final_catalog_evidence.json` | system ID/role membership/function ACL/RLS/triggers/baseline fingerprint | القاعدة الأصلية |
| `ATTEMPT-LEDGER.md` | الإخفاقات المصححة والحادث البيئي | لا يمحو المحاولات |

التقرير النهائي: `../../docs/audits/SECURITY-F06-API-ADMIN-COMPACT-01.md`. لا دليل على same-worker أو replay للاختبارات التاريخية أو G4-B/C/D.
