<?php
declare(strict_types=1);
namespace App\Modules\Tenancy\Http\Controllers;
use App\Modules\Identity\Domain\TenantStaffContext; use App\Modules\Tenancy\Application\DealService; use App\Modules\Tenancy\Domain\TenantAccessException; use Illuminate\Http\JsonResponse; use Illuminate\Http\Request;
final class DealController {
 public function index(Request $r,DealService $s):JsonResponse{$i=$r->validate(['stage_id'=>['sometimes','nullable','uuid'],'page'=>['sometimes','integer','min:1'],'per_page'=>['sometimes','integer','min:1','max:100']]);$out=$s->list($this->context($r),$i['stage_id']??null,(int)($i['page']??1),(int)($i['per_page']??25));return response()->json(['data'=>$out['data'],'meta'=>[...$out['meta'],'request_id'=>$r->attributes->get('request_id')]]);}
 public function store(Request $r,DealService $s):JsonResponse{return $this->reply($r,$s->create($this->context($r),$r->validate($this->rules())),201);}
 public function show(Request $r,string $deal,DealService $s):JsonResponse{return $this->reply($r,$s->show($this->context($r),$deal));}
 public function update(Request $r,string $deal,DealService $s):JsonResponse{return $this->reply($r,$s->update($this->context($r),$deal,$r->validate($this->rules(false))));}
 public function transition(Request $r,string $deal,DealService $s):JsonResponse{return $this->reply($r,$s->transition($this->context($r),$deal,$r->validate(['from_stage_id'=>['required','uuid'],'to_stage_id'=>['required','uuid'],'version'=>['required','integer','min:1']])));}
 private function rules(bool $required=true):array{$p=$required?'required':'sometimes';return ['title'=>[$p,'string','max:160'],'customer_id'=>[$p,'uuid'],'contact_id'=>['sometimes','nullable','uuid'],'pipeline_id'=>[$p,'uuid'],'stage_id'=>[$p,'uuid'],'value_amount'=>[$p,'regex:/^\\d{1,16}(?:\\.\\d{1,4})?$/'],'currency_code'=>[$p,'string','size:3'],'owner_membership_id'=>['sometimes','nullable','uuid']];}
 private function reply(Request $r,array $d,int $status=200):JsonResponse{return response()->json(['data'=>$d,'meta'=>['request_id'=>$r->attributes->get('request_id')]],$status);}
 private function context(Request $r):TenantStaffContext{$c=$r->attributes->get('tenant_staff_context');if(!$c instanceof TenantStaffContext)throw TenantAccessException::contextRequired();return $c;}
}
