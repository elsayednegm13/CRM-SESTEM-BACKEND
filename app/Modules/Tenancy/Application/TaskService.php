<?php

declare(strict_types=1);

namespace App\Modules\Tenancy\Application;

use App\Modules\Identity\Application\TenantStaffAuthorizationService;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

final class TaskService
{
    private const CONNECTION='pgsql_tenant_runtime';
    public function __construct(private readonly TenantStaffAuthorizationService $authorization) {}
    /** @return array{data:list<array<string,mixed>>,meta:array<string,int>} */ public function list(TenantStaffContext $actor,?string $status,int $page,int $perPage):array{$this->require($actor,'tasks.view');$q=DB::connection(self::CONNECTION)->table('sales_tasks')->where('tenant_id',$actor->tenantId);if($status!==null)$q->where('status',$status);$total=(clone $q)->count();return['data'=>$q->orderBy('due_at')->forPage($page,$perPage)->get()->map(fn(object $t)=>$this->present($t))->all(),'meta'=>['page'=>$page,'per_page'=>$perPage,'total'=>$total]];}
    /** @param array<string,mixed> $input @return array<string,mixed> */ public function create(TenantStaffContext $actor,array $input):array{$this->require($actor,'tasks.manage');$task=SalesInput::task($input);return DB::connection(self::CONNECTION)->transaction(function()use($actor,$task):array{$db=DB::connection(self::CONNECTION);$this->assertReferences($db,$actor,$task);$id=(string)Str::uuid7();$now=now('UTC');$db->table('sales_tasks')->insert(['id'=>$id,'tenant_id'=>$actor->tenantId,...$task,'completed_at'=>$task['status']==='DONE'?$now:null,'created_by_membership_id'=>$actor->membershipId,'created_at'=>$now,'updated_at'=>$now]);$db->table('sales_activities')->insert(['id'=>(string)Str::uuid7(),'tenant_id'=>$actor->tenantId,'customer_id'=>$task['customer_id'],'deal_id'=>$task['deal_id'],'task_id'=>$id,'event_type'=>'task.created','actor_membership_id'=>$actor->membershipId,'metadata'=>json_encode([],JSON_THROW_ON_ERROR),'occurred_at'=>$now]);return $this->present($this->find($actor,$id));});}
    /** @param array<string,mixed> $input @return array<string,mixed> */ public function update(TenantStaffContext $actor,string $id,array $input):array{$this->require($actor,'tasks.manage');return DB::connection(self::CONNECTION)->transaction(function()use($actor,$id,$input):array{$db=DB::connection(self::CONNECTION);$row=$this->find($actor,$id,true);$task=SalesInput::task([...$this->present($row),...$input]);$this->assertReferences($db,$actor,$task);$now=now('UTC');$db->table('sales_tasks')->where('tenant_id',$actor->tenantId)->where('id',$id)->update([...$task,'completed_at'=>$task['status']==='DONE'?($row->completed_at??$now):null,'updated_at'=>$now]);return $this->present($this->find($actor,$id));});}
    /** @return array<string,mixed> */ public function complete(TenantStaffContext $actor,string $id):array{return $this->update($actor,$id,['status'=>'DONE']);}
    private function assertReferences($db,TenantStaffContext $actor,array $task):void{if($task['customer_id']!==null&&!$db->table('customers')->where('tenant_id',$actor->tenantId)->where('id',$task['customer_id'])->exists())throw TenantAccessException::objectNotFound();if($task['deal_id']!==null&&!$db->table('deals')->where('tenant_id',$actor->tenantId)->where('id',$task['deal_id'])->exists())throw TenantAccessException::objectNotFound();if($task['assignee_membership_id']!==null&&!$db->table('tenant_staff_memberships')->where('tenant_id',$actor->tenantId)->where('id',$task['assignee_membership_id'])->where('status','ACTIVE')->exists())throw TenantAccessException::objectNotFound();}
    private function find(TenantStaffContext $actor,string $id,bool $lock=false):object{$q=DB::connection(self::CONNECTION)->table('sales_tasks')->where('tenant_id',$actor->tenantId)->where('id',$id);if($lock)$q->lockForUpdate();$row=$q->first();if($row===null)throw TenantAccessException::objectNotFound();return $row;}
    /** @return array<string,mixed> */ private function present(object $t):array{return ['id'=>$t->id,'customer_id'=>$t->customer_id,'deal_id'=>$t->deal_id,'title'=>$t->title,'description'=>$t->description,'assignee_membership_id'=>$t->assignee_membership_id,'due_at'=>$t->due_at,'status'=>$t->status,'priority'=>$t->priority,'completed_at'=>$t->completed_at,'created_at'=>$t->created_at,'updated_at'=>$t->updated_at];}
    private function require(TenantStaffContext $actor,string $permission):void{if(!in_array(null,$this->authorization->effectiveGrants($actor)[$permission]??[],true))throw new AuthorizationDeniedException;}
}
