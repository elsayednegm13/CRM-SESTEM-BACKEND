param(
    [Parameter(Mandatory=$true)][string]$ContextPath,
    [Parameter(Mandatory=$true)][ValidateSet('a','b')][string]$Sandbox,
    [Parameter(Mandatory=$true)][ValidateSet('before','after')][string]$Phase
)
$ErrorActionPreference='Stop'
$context=Get-Content -LiteralPath $ContextPath -Raw | ConvertFrom-Json
$container="$($context.prefix)-pg-$Sandbox"
$db=$context.database
$tenantA='11111111-1111-1111-1111-111111111111'
$tenantB='22222222-2222-2222-2222-222222222222'
$userA='aaaaaaa1-0000-0000-0000-000000000001'
$userB='bbbbbbb1-0000-0000-0000-000000000001'
$memberA='a1111111-0000-0000-0000-00000000a001'
$memberB='b1111111-0000-0000-0000-00000000b001'
$evidence=[Collections.Generic.List[string]]::new()
$observed=@{}
function RunCase([string]$label,[string]$actor,[string]$password,[string]$sql) {
    $result=@(docker exec -e "PGPASSWORD=$password" $container psql -h 127.0.0.1 -U $actor -d $db -X -tA -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -c $sql 2>&1)
    $rc=$LASTEXITCODE
    $line="$label|rc=$rc|$($result -join ' // ')"
    $evidence.Add($line)
    $observed[$label]=$line
    Write-Output $line
}
$a1='daleel_f06i02_actor_a1';$a2='daleel_f06i02_actor_a2';$b1='daleel_f06i02_actor_b1'
$setA="SELECT set_config('app.context_mode','TENANT',true),set_config('app.tenant_id','$tenantA',true),set_config('app.user_id','$userA',true);"
$setB="SELECT set_config('app.context_mode','TENANT',true),set_config('app.tenant_id','$tenantB',true),set_config('app.user_id','$userB',true);"
RunCase 'A1_LEGIT' $a1 $context.actor_a1_password "BEGIN; $setA SELECT session_user,current_user,inet_client_addr(),count(*) FROM public.leads WHERE tenant_id='$tenantA'; ROLLBACK;"
RunCase 'B1_LEGIT' $b1 $context.actor_b1_password "BEGIN; $setB SELECT session_user,current_user,inet_client_addr(),count(*) FROM public.leads WHERE tenant_id='$tenantB'; ROLLBACK;"
RunCase 'A1_LEGIT_UPDATE_A' $a1 $context.actor_a1_password "BEGIN; $setA UPDATE public.leads SET name='legitimate-probe' WHERE tenant_id='$tenantA' AND created_by_membership_id='$memberA'; ROLLBACK;"
RunCase 'A1_LEGIT_INSERT_A' $a1 $context.actor_a1_password "BEGIN; $setA INSERT INTO public.leads (id,tenant_id,name,created_by_membership_id,created_at,updated_at) VALUES ('f06b0100-0000-0000-0000-000000000003','$tenantA','legitimate-probe','$memberA',now(),now()); ROLLBACK;"
RunCase 'A1_TO_B1_DENY' $a1 $context.actor_a1_password 'SET ROLE daleel_f06i02_actor_b1;'
RunCase 'A1_TO_GROUP' $a1 $context.actor_a1_password 'SET ROLE daleel_tenant_runtime; SELECT session_user,current_user,inet_client_addr();'
RunCase 'A2_TO_GROUP' $a2 $context.actor_a2_password 'SET ROLE daleel_tenant_runtime; SELECT session_user,current_user;'
RunCase 'B1_TO_GROUP' $b1 $context.actor_b1_password 'SET ROLE daleel_tenant_runtime; SELECT session_user,current_user;'
RunCase 'A1_GUC_ONLY_SELECT_B' $a1 $context.actor_a1_password "BEGIN; $setB SELECT count(*) FROM public.leads WHERE tenant_id='$tenantB'; ROLLBACK;"
RunCase 'A1_GROUP_SELECT_B' $a1 $context.actor_a1_password "BEGIN; SET ROLE daleel_tenant_runtime; $setB SELECT session_user,current_user,count(*) FROM public.leads WHERE tenant_id='$tenantB'; ROLLBACK;"
RunCase 'A1_GROUP_UPDATE_B' $a1 $context.actor_a1_password "BEGIN; SET ROLE daleel_tenant_runtime; $setB UPDATE public.leads SET name='boundary-probe' WHERE tenant_id='$tenantB'; ROLLBACK;"
RunCase 'A1_GROUP_INSERT_B' $a1 $context.actor_a1_password "BEGIN; SET ROLE daleel_tenant_runtime; $setB INSERT INTO public.leads (id,tenant_id,name,created_by_membership_id,created_at,updated_at) VALUES ('f06b0100-0000-0000-0000-000000000001','$tenantB','boundary-probe','$memberB',now(),now()); ROLLBACK;"
RunCase 'A1_GUC_ONLY_UPDATE_B' $a1 $context.actor_a1_password "BEGIN; $setB UPDATE public.leads SET name='boundary-probe' WHERE tenant_id='$tenantB'; ROLLBACK;"
RunCase 'A1_GUC_ONLY_INSERT_B' $a1 $context.actor_a1_password "BEGIN; $setB INSERT INTO public.leads (id,tenant_id,name,created_by_membership_id,created_at,updated_at) VALUES ('f06b0100-0000-0000-0000-000000000002','$tenantB','boundary-probe','$memberB',now(),now()); ROLLBACK;"
RunCase 'A1_RESET_ROLE' $a1 $context.actor_a1_password 'SET ROLE NONE; SELECT session_user,current_user; RESET ROLE; SELECT session_user,current_user;'
RunCase 'A1_SET_SESSION_AUTH_GROUP' $a1 $context.actor_a1_password 'SET SESSION AUTHORIZATION daleel_tenant_runtime;'
function Require([string]$label,[string]$pattern) {
    if(-not $observed.ContainsKey($label) -or $observed[$label] -notmatch $pattern){
        throw "Boundary gate failed: $label"
    }
}
Require 'A1_LEGIT' 'rc=0.*actor_a1\|daleel_f06i02_actor_a1\|127\.0\.0\.1\|2'
Require 'B1_LEGIT' 'rc=0.*actor_b1\|daleel_f06i02_actor_b1\|127\.0\.0\.1\|1'
Require 'A1_LEGIT_UPDATE_A' 'rc=0.*UPDATE 1.*ROLLBACK'
Require 'A1_LEGIT_INSERT_A' 'rc=0.*INSERT 0 1.*ROLLBACK'
Require 'A1_TO_B1_DENY' 'rc=1.*42501.*permission denied to set role'
Require 'A1_GUC_ONLY_SELECT_B' 'rc=0.* // 0 // ROLLBACK'
Require 'A1_GUC_ONLY_UPDATE_B' 'rc=0.*UPDATE 0.*ROLLBACK'
Require 'A1_GUC_ONLY_INSERT_B' 'rc=1.*42501.*row-level security policy'
Require 'A1_RESET_ROLE' 'rc=0.*actor_a1\|daleel_f06i02_actor_a1.*RESET.*actor_a1\|daleel_f06i02_actor_a1'
Require 'A1_SET_SESSION_AUTH_GROUP' 'rc=1.*42501.*permission denied to set session authorization'
if($Phase -eq 'before'){
    Require 'A1_TO_GROUP' 'rc=0.*actor_a1\|daleel_tenant_runtime'
    Require 'A2_TO_GROUP' 'rc=0.*actor_a2\|daleel_tenant_runtime'
    Require 'B1_TO_GROUP' 'rc=0.*actor_b1\|daleel_tenant_runtime'
    Require 'A1_GROUP_SELECT_B' 'rc=0.*actor_a1\|daleel_tenant_runtime\|1.*ROLLBACK'
    Require 'A1_GROUP_UPDATE_B' 'rc=0.*UPDATE 1.*ROLLBACK'
    Require 'A1_GROUP_INSERT_B' 'rc=0.*INSERT 0 1.*ROLLBACK'
} else {
    foreach($label in @('A1_TO_GROUP','A2_TO_GROUP','B1_TO_GROUP','A1_GROUP_SELECT_B','A1_GROUP_UPDATE_B','A1_GROUP_INSERT_B')){
        Require $label 'rc=1.*42501.*permission denied to set role'
    }
}
$evidence.Add("GATE_$Phase=PASS")
Write-Output "GATE_$Phase=PASS"
$evidencePath=Join-Path $PSScriptRoot "evidence_$Phase-$Sandbox.txt"
[IO.File]::WriteAllLines($evidencePath,$evidence,[Text.UTF8Encoding]::new($false))
