<?php
declare(strict_types=1);
namespace Tests\Unit\Modules\Identity\Application;
use App\Modules\Identity\Application\TenantAuthorityAuthenticator;
use App\Modules\Identity\Application\TenantAuthorityBridge;
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUser;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use LogicException;
use Tests\TestCase;

final class TenantAuthorityBridgeTest extends TestCase {
 private function request(): Request {$r=Request::create('/','POST');$s=new Store('bridge',new ArraySessionHandler(60));$s->start();$r->setLaravelSession($s);return $r;}
 private function host(): TenantHostContext {return new TenantHostContext('019c4a5b-5010-7f00-8a00-50e6e64c335a','a','a.test','test','LOCAL_TEST');}
 public function test_b01_returns_only_rotated_bound_authority(): void {$r=$this->request();$b=new TenantAuthorityBridge(new class implements TenantAuthorityAuthenticator {public function authenticate(TenantHostContext $h,string $e,string $p,string $k,Request $r): TenantStaffUser {$r->session()->migrate(true);$r->attributes->set('tenant_staff_context',new TenantStaffContext($h->tenantId,$h->hostname,'019c4a5b-5010-7f00-8a00-50e6e64c335b','019c4a5b-5010-7f00-8a00-50e6e64c335c',1,1));$r->session()->put('identity.tenant_staff',['authority_generation'=>'019c4a5b-5010-7f00-8a00-50e6e64c335d']);return new TenantStaffUser;}});$out=$b->authenticateAndBind($this->host(),'a@b.test','x','k',$r);self::assertSame('019c4a5b-5010-7f00-8a00-50e6e64c335d',$out['authority_generation']);}
 public function test_b02_rejects_unrotated_or_unbound_result(): void {$r=$this->request();$b=new TenantAuthorityBridge(new class implements TenantAuthorityAuthenticator {public function authenticate(TenantHostContext $h,string $e,string $p,string $k,Request $r): TenantStaffUser {return new TenantStaffUser;}});$this->expectException(LogicException::class);$b->authenticateAndBind($this->host(),'a','x','k',$r);}
}
