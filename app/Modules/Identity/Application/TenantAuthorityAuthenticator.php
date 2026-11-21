<?php
declare(strict_types=1);
namespace App\Modules\Identity\Application;
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUser;
use Illuminate\Http\Request;
interface TenantAuthorityAuthenticator { public function authenticate(TenantHostContext $host,string $email,string $password,string $retryKey,Request $request): TenantStaffUser; }
