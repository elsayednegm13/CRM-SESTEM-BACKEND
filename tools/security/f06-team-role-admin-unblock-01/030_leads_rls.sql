-- Sandbox-only restrictive actor row scopes, additive to migration 036 and I03.
BEGIN;
CREATE POLICY f06scope_leads_view ON public.leads AS RESTRICTIVE FOR SELECT
TO daleel_f06scope_actor_runtime
USING (public.f06scope_row_allowed('leads.view',tenant_id,assigned_membership_id,created_by_membership_id));
CREATE POLICY f06scope_leads_insert ON public.leads AS RESTRICTIVE FOR INSERT
TO daleel_f06scope_actor_runtime
WITH CHECK (public.f06scope_insert_allowed(tenant_id,assigned_membership_id,created_by_membership_id));
CREATE POLICY f06scope_leads_update ON public.leads AS RESTRICTIVE FOR UPDATE
TO daleel_f06scope_actor_runtime
USING (public.f06scope_row_allowed('leads.manage',tenant_id,assigned_membership_id,created_by_membership_id))
WITH CHECK (public.f06scope_row_allowed('leads.manage',tenant_id,assigned_membership_id,created_by_membership_id));
CREATE POLICY f06scope_leads_delete ON public.leads AS RESTRICTIVE FOR DELETE
TO daleel_f06scope_actor_runtime USING (false);
COMMIT;
