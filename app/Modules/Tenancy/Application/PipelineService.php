<?php

declare(strict_types=1);

namespace App\Modules\Tenancy\Application;

use App\Modules\Identity\Application\TenantStaffAuthorizationService;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/** Tenant-owned pipelines; no client-supplied tenant selector is accepted. */
final class PipelineService
{
    private const CONNECTION = 'pgsql_tenant_runtime';
    public function __construct(private readonly TenantStaffAuthorizationService $authorization) {}

    /** @return list<array<string,mixed>> */
    public function list(TenantStaffContext $actor): array
    {
        $this->require($actor, 'deals.view');
        $db = DB::connection(self::CONNECTION);
        return $db->table('sales_pipelines')->where('tenant_id', $actor->tenantId)->orderBy('name')->get()->map(function (object $pipeline) use ($db, $actor): array {
            $stages = $db->table('sales_pipeline_stages')->where('tenant_id', $actor->tenantId)->where('pipeline_id', $pipeline->id)->orderBy('sort_order')->get()->map(fn (object $stage) => $this->stage($stage))->all();
            return ['id' => $pipeline->id, 'name' => $pipeline->name, 'is_default' => (bool) $pipeline->is_default, 'stages' => $stages];
        })->all();
    }

    /** @param array<string,mixed> $input @return array<string,mixed> */
    public function create(TenantStaffContext $actor, array $input): array
    {
        $this->require($actor, 'pipelines.manage');
        $name = trim((string) ($input['name'] ?? ''));
        if ($name === '' || mb_strlen($name) > 120) throw \Illuminate\Validation\ValidationException::withMessages(['name' => ['A pipeline name is required.']]);
        $stages = $input['stages'] ?? [];
        if (!is_array($stages) || $stages === []) throw \Illuminate\Validation\ValidationException::withMessages(['stages' => ['At least one stage is required.']]);
        return DB::connection(self::CONNECTION)->transaction(function () use ($actor, $name, $stages): array {
            $db = DB::connection(self::CONNECTION); $id = (string) Str::uuid7(); $now = now('UTC');
            $db->table('sales_pipelines')->insert(['id'=>$id,'tenant_id'=>$actor->tenantId,'name'=>$name,'is_default'=>false,'created_by_membership_id'=>$actor->membershipId,'created_at'=>$now,'updated_at'=>$now]);
            foreach (array_values($stages) as $index => $raw) {
                if (!is_array($raw)) throw \Illuminate\Validation\ValidationException::withMessages(['stages'=>['Each stage must be an object.']]);
                $stageName = trim((string) ($raw['name'] ?? '')); $kind = $raw['kind'] ?? 'OPEN';
                if ($stageName === '' || mb_strlen($stageName)>120 || !in_array($kind,['OPEN','WON','LOST'],true)) throw \Illuminate\Validation\ValidationException::withMessages(['stages'=>['Invalid stage.']]);
                $db->table('sales_pipeline_stages')->insert(['id'=>(string)Str::uuid7(),'tenant_id'=>$actor->tenantId,'pipeline_id'=>$id,'name'=>$stageName,'sort_order'=>$index+1,'kind'=>$kind,'is_active'=>true,'created_at'=>$now,'updated_at'=>$now]);
            }
            return $this->pipeline($actor, $id);
        });
    }

    /** @return array<string,mixed> */
    public function pipeline(TenantStaffContext $actor, string $id): array
    {
        $pipeline=DB::connection(self::CONNECTION)->table('sales_pipelines')->where('tenant_id',$actor->tenantId)->where('id',$id)->first(); if($pipeline===null) throw TenantAccessException::objectNotFound();
        $stages=DB::connection(self::CONNECTION)->table('sales_pipeline_stages')->where('tenant_id',$actor->tenantId)->where('pipeline_id',$id)->orderBy('sort_order')->get()->map(fn(object $s)=>$this->stage($s))->all();
        return ['id'=>$pipeline->id,'name'=>$pipeline->name,'is_default'=>(bool)$pipeline->is_default,'stages'=>$stages];
    }
    /** @return array<string,mixed> */ private function stage(object $stage): array { return ['id'=>$stage->id,'name'=>$stage->name,'kind'=>$stage->kind,'sort_order'=>(int)$stage->sort_order,'is_active'=>(bool)$stage->is_active]; }
    private function require(TenantStaffContext $actor, string $permission): void { if (!in_array(null, $this->authorization->effectiveGrants($actor)[$permission] ?? [], true)) throw new AuthorizationDeniedException; }
}
