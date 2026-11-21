<?php
declare(strict_types=1);
namespace App\Modules\Tenancy\Http\Controllers;
use App\Modules\Identity\Domain\TenantStaffContext; use App\Modules\Tenancy\Application\TaskService; use App\Modules\Tenancy\Domain\TenantAccessException; use Illuminate\Http\JsonResponse; use Illuminate\Http\Request;
final class TaskController {
 public function index(Request $r,TaskService $s):JsonResponse{$i=$r->validate(['status'=>['sometimes','nullable','in:TODO,IN_PROGRESS,DONE,CANCELLED'],'page'=>['sometimes','integer','min:1'],'per_page'=>['sometimes','integer','min:1','max:100']]);$out=$s->list($this->context($r),$i['status']??null,(int)($i['page']??1),(int)($i['per_page']??25));return response()->json(['data'=>$out['data'],'meta'=>[...$out['meta'],'request_id'=>$r->attributes->get('request_id')]]);}
 public function store(Request $r,TaskService $s):JsonResponse{return $this->reply($r,$s->create($this->context($r),$r->validate($this->rules())),201);}
 public function update(Request $r,string $task,TaskService $s):JsonResponse{return $this->reply($r,$s->update($this->context($r),$task,$r->validate($this->rules(false))));}
 public function complete(Request $r,string $task,TaskService $s):JsonResponse{return $this->reply($r,$s->complete($this->context($r),$task));}
 private function rules(bool $required=true):array{$p=$required?'required':'sometimes';return ['title'=>[$p,'string','max:160'],'description'=>['sometimes','nullable','string','max:2000'],'customer_id'=>['sometimes','nullable','uuid'],'deal_id'=>['sometimes','nullable','uuid'],'assignee_membership_id'=>['sometimes','nullable','uuid'],'due_at'=>['sometimes','nullable','date'],'status'=>['sometimes','in:TODO,IN_PROGRESS,DONE,CANCELLED'],'priority'=>['sometimes','in:LOW,NORMAL,HIGH']];}
 private function reply(Request $r,array $d,int $status=200):JsonResponse{return response()->json(['data'=>$d,'meta'=>['request_id'=>$r->attributes->get('request_id')]],$status);}
 private function context(Request $r):TenantStaffContext{$c=$r->attributes->get('tenant_staff_context');if(!$c instanceof TenantStaffContext)throw TenantAccessException::contextRequired();return $c;}
}
