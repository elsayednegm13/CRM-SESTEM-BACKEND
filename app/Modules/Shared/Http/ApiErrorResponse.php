<?php

namespace App\Modules\Shared\Http;

use App\Modules\Identity\Domain\Exceptions\ActorSqlUnavailableException;
use App\Modules\Identity\Domain\Exceptions\AuthRateLimitedException;
use App\Modules\Identity\Domain\Exceptions\AuthSessionExpiredException;
use App\Modules\Identity\Domain\Exceptions\InvalidCredentialsException;
use App\Modules\Identity\Domain\Exceptions\InvalidVerificationLinkException;
use App\Modules\Identity\Domain\Exceptions\LoginAttemptConflictException;
use App\Modules\Tenancy\Domain\TenantAccessException;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\LeadConversionConflictException;
use App\Modules\Tenancy\Domain\CustomerInputException;
use App\Modules\Tenancy\Domain\SalesConflictException;
use App\Modules\Provider\Domain\ProviderAccessException;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Illuminate\Session\TokenMismatchException;
use Illuminate\Routing\Exceptions\InvalidSignatureException;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Throwable;

class ApiErrorResponse
{
    public static function fromException(Throwable $exception, Request $request): JsonResponse
    {
        if ($exception instanceof ActorSqlUnavailableException) {
            Log::warning('ACTOR_SQL_UNAVAILABLE', [
                'reason' => $exception->reason,
                'request_id' => $request->attributes->get('request_id'),
            ]);
        }

        [$status, $code, $message, $fields] = match (true) {
            $exception instanceof ActorSqlUnavailableException => [503, 'ACTOR_SQL_UNAVAILABLE',
                'The company service is temporarily unavailable.', null],
            $exception instanceof ProviderAccessException => [$exception->status, $exception->safeCode,
                match ($exception->status) {
                    401 => 'Provider authentication is required or could not be completed.',
                    429 => 'Too many provider authentication requests. Try again later.',
                    default => 'Provider access is unavailable.',
                }, null],
            $exception instanceof AuthorizationDeniedException => [403, 'AUTHORIZATION_DENIED', 'This action is not permitted.', null],
            $exception instanceof LeadConversionConflictException => [409, 'LEAD_CONVERSION_CONFLICT', 'The lead conversion conflicts with an existing customer or conversion.', null],
            $exception instanceof SalesConflictException => [409, 'SALES_CONFLICT', 'The requested sales change conflicts with the current record.', null],
            $exception instanceof CustomerInputException => [422, 'VALIDATION_FAILED', 'The request could not be validated.', $exception->errors],
            $exception instanceof TenantAccessException => [
                $exception->status,
                $exception->safeCode,
                match ($exception->safeCode) {
                    'TENANT_SELECTOR_NOT_ALLOWED' => 'A company selector is not accepted.',
                    'RESOURCE_NOT_FOUND' => 'The requested resource was not found.',
                    default => 'Company access is unavailable.',
                },
                null,
            ],
            $exception instanceof ValidationException => [422, 'VALIDATION_FAILED', 'The request could not be validated.', $exception->errors()],
            $exception instanceof InvalidCredentialsException => [401, 'AUTH_INVALID_CREDENTIALS', 'The email or password is incorrect.', null],
            $exception instanceof LoginAttemptConflictException => [409, 'AUTH_LOGIN_ATTEMPT_CONFLICT',
                'This sign-in attempt can no longer be retried. Start a new sign-in attempt.', null],
            $exception instanceof AuthSessionExpiredException => [401, 'AUTH_SESSION_EXPIRED', 'The session has expired. Please sign in again.', null],
            $exception instanceof InvalidVerificationLinkException,
            $exception instanceof InvalidSignatureException => [422, 'AUTH_EMAIL_VERIFICATION_INVALID', 'The verification link is invalid or expired.', null],
            $exception instanceof TokenMismatchException => [419, 'AUTH_CSRF_INVALID', 'The request could not be verified. Refresh and try again.', null],
            $exception instanceof AuthenticationException => [401, 'AUTH_UNAUTHENTICATED', 'Authentication is required.', null],
            $exception instanceof AuthRateLimitedException => [429, 'AUTH_RATE_LIMITED', 'Too many authentication requests. Please try again later.', null],
            $exception instanceof AuthorizationException => [403, 'PERMISSION_DENIED', 'This action is not permitted.', null],
            $exception instanceof TooManyRequestsHttpException => [429, 'RATE_LIMITED', 'Too many requests. Please try again later.', null],
            $exception instanceof ModelNotFoundException,
            $exception instanceof NotFoundHttpException => [404, 'RESOURCE_NOT_FOUND', 'The requested resource was not found.', null],
            $exception instanceof HttpExceptionInterface => self::httpError($exception),
            default => [500, 'INTERNAL_ERROR', 'An unexpected error occurred.', null],
        };

        return response()->json([
            'error' => array_filter([
                'code' => $code,
                'message' => $message,
                'fields' => $fields,
            ], static fn ($value) => $value !== null),
            'meta' => ['request_id' => $request->attributes->get('request_id')],
        ], $status);
    }

    /** @return array{int, string, string, null} */
    private static function httpError(HttpExceptionInterface $exception): array
    {
        $status = $exception->getStatusCode();

        return match ($status) {
            401 => [401, 'AUTH_UNAUTHENTICATED', 'Authentication is required.', null],
            403 => [403, 'PERMISSION_DENIED', 'This action is not permitted.', null],
            404 => [404, 'RESOURCE_NOT_FOUND', 'The requested resource was not found.', null],
            419 => [419, 'AUTH_CSRF_INVALID', 'The request could not be verified. Refresh and try again.', null],
            429 => [429, 'RATE_LIMITED', 'Too many requests. Please try again later.', null],
            default => [
                $status >= 400 && $status < 600 ? $status : Response::HTTP_INTERNAL_SERVER_ERROR,
                'REQUEST_FAILED',
                'The request could not be completed.',
                null,
            ],
        };
    }
}
