<?php
declare(strict_types=1);
namespace App\Modules\Tenancy\Http\Controllers;
use App\Modules\Identity\Domain\TenantStaffContext; use App\Modules\Tenancy\Application\PipelineService; use App\Modules\Tenancy\Domain\TenantAccessException; use Illuminate\Http\JsonResponse; use Illuminate\Http\Request;
final class PipelineController {
 public function index(Request $r,PipelineService $s):JsonResponse{return response()->json(['data'=>$s->list($this->context($r)),'meta'=>['request_id'=>$r->attributes->get('request_id')]]);}
 public function store(Request $r,PipelineService $s):JsonResponse{$input=$r->validate(['name'=>['required','string','max:120'],'stages'=>['required','array','min:1'],'stages.*.name'=>['required','string','max:120'],'stages.*.kind'=>['sometimes','in:OPEN,WON,LOST']]);return response()->json(['data'=>$s->create($this->context($r),$input),'meta'=>['request_id'=>$r->attributes->get('request_id')]],201);}
 private function context(Request $r):TenantStaffContext{$c=$r->attributes->get('tenant_staff_context');if(!$c instanceof TenantStaffContext)throw TenantAccessException::contextRequired();return $c;}
}
