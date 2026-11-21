-- New synthetic identities after the copied I03 fixture; sandbox only.
BEGIN;
CREATE ROLE daleel_f06team01_actor_a5 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD NULL;
ALTER ROLE daleel_f06team01_actor_a5 PASSWORD :'actor_a5_password';

INSERT INTO public.tenant_staff_users
 (id,tenant_id,canonical_email,display_email,display_name,password_hash,status,auth_version,created_at,updated_at)
VALUES
 ('aaaaaaa0-0000-0000-0000-000000000000','11111111-1111-1111-1111-111111111111',
  'a0@tenant-a.sandbox','A0@Tenant-A.sandbox','Passive company-admin invariant anchor',:'hash_login_a0','ACTIVE',1,now(),now()),
 ('aaaaaaa5-0000-0000-0000-000000000005','11111111-1111-1111-1111-111111111111',
  'a5@tenant-a.sandbox','A5@Tenant-A.sandbox','Actor A5 team manager',:'hash_login_a5','ACTIVE',1,now(),now());

SELECT pg_catalog.set_config('app.context_mode','TENANT',true);
SELECT pg_catalog.set_config('app.tenant_id','11111111-1111-1111-1111-111111111111',true);
SELECT pg_catalog.set_config('app.user_id','aaaaaaa1-0000-0000-0000-000000000001',true);
INSERT INTO public.tenant_staff_memberships
 (id,tenant_id,staff_user_id,status,authorization_version,joined_at,created_by_membership_id,created_at,updated_at)
VALUES
 ('a1111111-0000-0000-0000-00000000a000','11111111-1111-1111-1111-111111111111',
  'aaaaaaa0-0000-0000-0000-000000000000','ACTIVE',1,now(),'a1111111-0000-0000-0000-00000000a001',now(),now()),
 ('a1111111-0000-0000-0000-00000000a005','11111111-1111-1111-1111-111111111111',
  'aaaaaaa5-0000-0000-0000-000000000005','ACTIVE',1,now(),'a1111111-0000-0000-0000-00000000a001',now(),now());
SELECT pg_catalog.set_config('app.user_id','',true);

INSERT INTO public.roles (id,tenant_id,display_name,normalized_name,status,version,created_at,updated_at)
VALUES
 ('ea000000-0000-0000-0000-00000000000a','11111111-1111-1111-1111-111111111111',
  'Passive invariant role','passive_invariant','ACTIVE',1,now(),now()),
 ('ea000005-0000-0000-0000-00000000000a','11111111-1111-1111-1111-111111111111',
  'A5 manager','a5_manager','ACTIVE',1,now(),now());
INSERT INTO public.role_permissions (tenant_id,role_id,permission_key,scope) VALUES
 ('11111111-1111-1111-1111-111111111111','ea000000-0000-0000-0000-00000000000a','company.administer','ALL_TENANT'),
 ('11111111-1111-1111-1111-111111111111','ea000005-0000-0000-0000-00000000000a','member.manage',NULL),
 ('11111111-1111-1111-1111-111111111111','ea000005-0000-0000-0000-00000000000a','member.view',NULL),
 ('11111111-1111-1111-1111-111111111111','ea000005-0000-0000-0000-00000000000a','role.manage',NULL),
 ('11111111-1111-1111-1111-111111111111','ea000005-0000-0000-0000-00000000000a','role.view',NULL),
 ('11111111-1111-1111-1111-111111111111','ea000005-0000-0000-0000-00000000000a','leads.view','SELF');
INSERT INTO public.tenant_staff_membership_roles
 (id,tenant_id,membership_id,role_id,assigned_by_membership_id,assigned_at,created_at,updated_at)
VALUES
 ('ea010000-0000-0000-0000-000000000000','11111111-1111-1111-1111-111111111111',
  'a1111111-0000-0000-0000-00000000a000','ea000000-0000-0000-0000-00000000000a',
  'a1111111-0000-0000-0000-00000000a001',now(),now(),now()),
 ('ea010005-0000-0000-0000-000000000005','11111111-1111-1111-1111-111111111111',
  'a1111111-0000-0000-0000-00000000a005','ea000005-0000-0000-0000-00000000000a',
  'a1111111-0000-0000-0000-00000000a001',now(),now(),now());

INSERT INTO public.f06i02_actor_sql_identity_map (tenant_id,membership_id,sql_role_name)
VALUES ('11111111-1111-1111-1111-111111111111','a1111111-0000-0000-0000-00000000a005','daleel_f06team01_actor_a5');
COMMIT;
