<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Modules\Identity\Application\F3CommittedWitnessObserver;
use App\Modules\Identity\Application\TenantAcceptanceRequestBinder;
use App\Modules\Identity\Application\TenantHostResolver;
use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Identity\Http\Middleware\EnsureTenantLoginClientProof;
use Illuminate\Console\Command;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Cookie as HttpCookie;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/** Independent, stdin-only, default-disabled F3 committed-witness consumer. */
final class ObserveF3CommittedWitness extends Command
{
    protected $signature = 'dcrm:f3-observe-committed-witness';
    protected $description = 'Observe a committed F3 witness from an independent restricted session';

    public function handle(
        TenantHostResolver $hosts,
        EmailAddressNormalizer $emails,
        EnsureTenantLoginClientProof $clientProof,
        TenantAcceptanceRequestBinder $requests,
        F3CommittedWitnessObserver $observer,
    ): int {
        if (config('f3_acceptance.enabled') !== true
            || ! in_array(app()->environment(), (array) config('f3_acceptance.allowed_environments'), true)) {
            $this->error('F3_COMMITTED_OBSERVER_DISABLED');
            return self::FAILURE;
        }
        try {
            $input = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
            $this->assertInput($input);
            if (! hash_equals((string) config('f3_acceptance.run_id'), $input['run_id'])) {
                throw new \LogicException('run-id');
            }
            $host = $hosts->resolve($input['host']);
            $email = $emails->normalize($input['email']);
            $request = Request::create(
                'https://'.$input['host'].'/api/v1/auth/login', 'POST', [],
                ['daleel_login_client' => $this->issueLoginClientProof($clientProof, $input['host'])],
                [], ['HTTP_HOST' => $input['host'], 'HTTPS' => 'on'],
            );
            $session = new Store('dcrm-f3-observer-'.$input['run_id'], new ArraySessionHandler(900));
            $session->start();
            $request->setLaravelSession($session);
            $result = null;
            $requests->run($request, function () use (&$result, $clientProof, $observer, $host, $email, $input, $request): void {
                $clientProof->handle($request, function () use (&$result, $observer, $host, $email, $input, $request): Response {
                    $result = $observer->observe(
                        $host, $email, $input['password'], $input['retry_key'], $request,
                        $input['actor_tenant_id'], $input['observer_membership_id'], $input['admin_membership_id'],
                        $input['own_witness']['lead_id'], $input['foreign_witness']['tenant_id'],
                        $input['foreign_witness']['lead_id'], $input['own_witness']['commit_xid'],
                        $input['own_witness']['commit_backend_pid'], $input['run_id'],
                    );
                    return response()->noContent();
                });
            });
            if (! is_array($result) || ($result['classification'] ?? null) !== 'F3_COMMITTED_WITNESS_INDEPENDENTLY_OBSERVED'
                || ($result['cleanup_status'] ?? null) !== 'COMPLETE') {
                throw new \LogicException('result');
            }
            $this->line(json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            return self::SUCCESS;
        } catch (Throwable $exception) {
            $this->error('F3_COMMITTED_OBSERVER_REJECTED:'.$exception::class);
            return self::FAILURE;
        }
    }

    private function assertInput(mixed $input): void
    {
        $keys = ['version','run_id','host','email','password','retry_key','actor_tenant_id','observer_membership_id','admin_membership_id','own_witness','foreign_witness'];
        if (! is_array($input) || array_keys($input) !== $keys || $input['version'] !== 'DCRM-008-F3-COMMITTED-OBSERVER-V1'
            || ! is_string($input['run_id']) || preg_match('/^[a-z0-9-]{8,64}$/D', $input['run_id']) !== 1
            || ! is_string($input['host']) || ! is_string($input['email']) || ! is_string($input['password'])
            || $input['password'] === '' || strlen($input['password']) > 1024
            || ! is_string($input['retry_key']) || ! Str::isUuid($input['retry_key'])
            || ! Str::isUuid($input['actor_tenant_id']) || ! Str::isUuid($input['observer_membership_id'])
            || ! Str::isUuid($input['admin_membership_id'])
            || hash_equals($input['observer_membership_id'], $input['admin_membership_id'])
            || ! $this->witness($input['own_witness'], true) || ! $this->witness($input['foreign_witness'], false)
            || ! hash_equals($input['actor_tenant_id'], $input['own_witness']['tenant_id'])
            || hash_equals($input['actor_tenant_id'], $input['foreign_witness']['tenant_id'])) {
            throw new \LogicException('schema');
        }
    }

    private function witness(mixed $value, bool $withCommit): bool
    {
        $keys = $withCommit ? ['tenant_id','lead_id','commit_xid','commit_backend_pid'] : ['tenant_id','lead_id'];
        return is_array($value) && array_keys($value) === $keys
            && Str::isUuid($value['tenant_id'] ?? null) && Str::isUuid($value['lead_id'] ?? null)
            && (! $withCommit || (is_string($value['commit_xid'] ?? null)
                && preg_match('/^\d+$/D', $value['commit_xid']) === 1
                && is_int($value['commit_backend_pid'] ?? null) && $value['commit_backend_pid'] > 0));
    }

    private function issueLoginClientProof(EnsureTenantLoginClientProof $clientProof, string $host): string
    {
        Cookie::flushQueuedCookies();
        try {
            $request = Request::create('https://'.$host.'/sanctum/csrf-cookie', 'GET', [], [], [], ['HTTP_HOST' => $host, 'HTTPS' => 'on']);
            $response = $clientProof->handle($request, static fn (): Response => new Response('', 204));
            $cookie = collect(Cookie::getQueuedCookies())->first(
                static fn (HttpCookie $candidate): bool => $candidate->getName() === 'daleel_login_client',
            );
            if ($response->getStatusCode() !== 204 || ! $cookie instanceof HttpCookie || $cookie->getValue() === '') {
                throw new \LogicException('client-proof');
            }
            return $cookie->getValue();
        } finally {
            Cookie::flushQueuedCookies();
        }
    }
}
