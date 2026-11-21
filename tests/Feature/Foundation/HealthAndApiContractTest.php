<?php

namespace Tests\Feature\Foundation;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Log;
use Illuminate\Validation\ValidationException;
use Mockery;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Tests\TestCase;
use Throwable;

class HealthAndApiContractTest extends TestCase
{
    public function test_liveness_does_not_require_external_dependencies(): void
    {
        $response = $this->getJson('/api/v1/health/live')
            ->assertOk()
            ->assertJsonPath('data.status', 'alive');

        $requestId = $response->json('meta.request_id');
        $this->assertIsString($requestId);
        $this->assertMatchesRegularExpression('/^[0-9a-f-]{36}$/', $requestId);
        $this->assertSame($requestId, $response->headers->get('X-Request-ID'));
    }

    public function test_readiness_reports_unconfigured_dependencies_without_connection_details(): void
    {
        config(['foundation.dependency_checks_enabled' => false]);

        $this->getJson('/api/v1/health/ready')
            ->assertStatus(503)
            ->assertJsonPath('data.status', 'degraded')
            ->assertJsonPath('data.dependencies.database', 'not_configured')
            ->assertJsonPath('data.dependencies.redis', 'not_configured')
            ->assertDontSee('127.0.0.1')
            ->assertDontSee('password');
    }

    public function test_health_aggregates_foundation_readiness(): void
    {
        config(['foundation.dependency_checks_enabled' => false]);
        $this->getJson('/api/v1/health')
            ->assertOk()
            ->assertJsonPath('data.status', 'degraded')
            ->assertJsonPath('data.dependencies.database', 'not_configured');
    }

    public function test_request_id_is_generated_returned_and_validated(): void
    {
        $generated = $this->getJson('/api/v1/health/live')->assertOk();
        $generatedId = $generated->json('meta.request_id');
        $this->assertSame($generatedId, $generated->headers->get('X-Request-ID'));

        $trustedId = '7b7b5e70-3e78-4b3c-9ad0-05253bb552e8';
        $trusted = $this->withHeader('X-Request-ID', $trustedId)->getJson('/api/v1/health/live');
        $trusted->assertOk()->assertJsonPath('meta.request_id', $trustedId);
        $this->assertSame($trustedId, $trusted->headers->get('X-Request-ID'));

        $untrusted = $this->withHeader('X-Request-ID', str_repeat('x', 4096))->getJson('/api/v1/health/live');
        $untrusted->assertOk();
        $this->assertNotSame(str_repeat('x', 4096), $untrusted->json('meta.request_id'));
    }

    public function test_api_not_found_uses_stable_json_error_envelope(): void
    {
        $this->getJson('/api/v1/does-not-exist')
            ->assertNotFound()
            ->assertJsonPath('error.code', 'RESOURCE_NOT_FOUND')
            ->assertJsonPath('error.message', 'The requested resource was not found.')
            ->assertJsonStructure(['error' => ['code', 'message'], 'meta' => ['request_id']])
            ->assertHeader('X-Request-ID');
    }

    public function test_unexpected_api_exception_never_exposes_debug_details(): void
    {
        config(['app.debug' => true]);
        Route::get('/api/v1/foundation-test/unexpected', static function () {
            throw new \RuntimeException('sensitive internal diagnostic marker');
        });

        $this->getJson('/api/v1/foundation-test/unexpected')
            ->assertStatus(500)
            ->assertJsonPath('error.code', 'INTERNAL_ERROR')
            ->assertJsonPath('error.message', 'An unexpected error occurred.')
            ->assertDontSee('sensitive internal diagnostic marker')
            ->assertDontSee('RuntimeException')
            ->assertHeader('X-Request-ID')
            ->assertHeader('X-Content-Type-Options', 'nosniff');
    }

    public function test_validation_and_rate_limit_errors_use_stable_safe_codes(): void
    {
        Route::get('/api/v1/foundation-test/validation', static function () {
            throw ValidationException::withMessages(['name' => ['The name field is required.']]);
        });
        Route::get('/api/v1/foundation-test/throttled', static function () {
            throw new TooManyRequestsHttpException();
        });

        $this->getJson('/api/v1/foundation-test/validation')
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'VALIDATION_FAILED')
            ->assertJsonPath('error.fields.name.0', 'The name field is required.');

        $this->getJson('/api/v1/foundation-test/throttled')
            ->assertStatus(429)
            ->assertJsonPath('error.code', 'RATE_LIMITED')
            ->assertDontSee('TooManyRequestsHttpException');
    }

    public function test_request_logging_omits_query_secrets_and_request_payload(): void
    {
        $logger = Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('info')->once()->with('api.request', Mockery::on(function (array $context): bool {
            $this->assertSame('GET', $context['method']);
            $this->assertSame('api/v1/health/live', $context['route']);
            $this->assertSame(200, $context['status']);
            $this->assertArrayHasKey('request_id', $context);
            $this->assertArrayHasKey('duration_ms', $context);
            $this->assertArrayNotHasKey('password', $context);
            $this->assertArrayNotHasKey('token', $context);
            $this->assertArrayNotHasKey('query', $context);
            return true;
        }));

        Log::shouldReceive('withContext')->once();
        Log::shouldReceive('channel')->once()->with('structured')->andReturn($logger);
        Log::shouldReceive('withoutContext')->once();

        $this->getJson('/api/v1/health/live?password=private-value&token=secret-value')->assertOk();
    }

    public function test_local_cors_preflight_allows_only_an_exact_origin(): void
    {
        $this->withHeaders([
            'Origin' => 'http://localhost:3001',
            'Access-Control-Request-Method' => 'GET',
            'Access-Control-Request-Headers' => 'X-Request-ID',
        ])->options('/api/v1/health/live')
            ->assertHeader('Access-Control-Allow-Origin', 'http://localhost:3001')
            ->assertHeader('Access-Control-Allow-Credentials', 'true')
            ->assertHeader('X-Request-ID')
            ->assertHeader('X-Content-Type-Options', 'nosniff');

        $this->withHeaders([
            'Origin' => 'https://unapproved.example',
            'Access-Control-Request-Method' => 'GET',
        ])->options('/api/v1/health/live')
            ->assertHeaderMissing('Access-Control-Allow-Origin');
    }

    public function test_api_rate_limit_foundation_is_registered_at_sixty_per_minute(): void
    {
        $request = Request::create('/api/v1/foundation-test/limited', 'GET', server: ['REMOTE_ADDR' => '127.0.0.1']);
        $limit = RateLimiter::limiter('api')($request);

        $this->assertInstanceOf(Limit::class, $limit);
        $this->assertSame(60, $limit->maxAttempts);
        $this->assertSame(60, $limit->decaySeconds);
    }

    public function test_version_boundary_is_throttled_and_rate_limit_error_is_safe(): void
    {
        Route::get('/api/v1/foundation-test/rate-limit', static fn () => response()->json(['data' => ['ok' => true]]))
            ->middleware('throttle:api');

        $logger = Mockery::mock(LoggerInterface::class);
        $logger->shouldReceive('info')->times(61);
        Log::shouldReceive('withContext')->times(61);
        Log::shouldReceive('channel')->times(61)->with('structured')->andReturn($logger);
        Log::shouldReceive('withoutContext')->times(61);

        for ($attempt = 0; $attempt < 60; $attempt++) {
            $this->getJson('/api/v1/foundation-test/rate-limit')->assertOk();
        }

        $this->getJson('/api/v1/foundation-test/rate-limit')
            ->assertStatus(429)
            ->assertJsonPath('error.code', 'RATE_LIMITED')
            ->assertDontSee('TooManyRequestsHttpException');
    }
}
