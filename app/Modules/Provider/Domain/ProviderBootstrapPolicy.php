<?php

namespace App\Modules\Provider\Domain;

use App\Modules\Identity\Domain\EmailAddressNormalizer;
use InvalidArgumentException;
use SensitiveParameter;

final class ProviderBootstrapPolicy
{
    public function assertConfigured(#[SensitiveParameter] array $settings, int $now): void
    {
        $expiry = $settings['expires_at'] ?? null;
        if (($settings['enabled'] ?? false) !== true
            || ! is_string($settings['secret'] ?? null)
            || ! preg_match('/\A[0-9a-fA-F]{64}\z/D', $settings['secret'])
            || ! (is_int($expiry) || (is_string($expiry) && preg_match('/\A[0-9]{1,12}\z/D', $expiry)))
            || (int) $expiry <= $now || (int) $expiry - $now > 3600) {
            throw new ProviderAccessException('PROVIDER_SETUP_DISABLED', 403);
        }
    }

    public function assertSecret(#[SensitiveParameter] array $settings, #[SensitiveParameter] mixed $secret, int $now): void
    {
        $this->assertConfigured($settings, $now);
        if (! is_string($secret) || ! preg_match('/\A[0-9a-fA-F]{64}\z/D', $secret)
            || ! hash_equals($settings['secret'], $secret)) {
            throw new ProviderAccessException('PROVIDER_SETUP_DISABLED', 403);
        }
    }

    public function assertTransport(bool $secure, string $host, string $origin, bool $local, bool $allowLoopback): void
    {
        $parts = parse_url($origin);
        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || (isset($parts['path']) && $parts['path'] !== '')
            || ! in_array($parts['scheme'], ['https', 'http'], true)) {
            throw new ProviderAccessException('PROVIDER_SETUP_DISABLED', 403);
        }
        if ($secure && $parts['scheme'] === 'https') {
            return;
        }
        if ($local && $allowLoopback && $this->isLoopback($host) && $this->isLoopback($parts['host'])) {
            return;
        }
        throw new ProviderAccessException('PROVIDER_SETUP_DISABLED', 403);
    }

    /** @return array{email:string,password:string} */
    public function identity(#[SensitiveParameter] array $input, EmailAddressNormalizer $emails): array
    {
        try {
            if (! is_string($input['email'] ?? null)) {
                throw new InvalidArgumentException;
            }
            $email = $emails->normalize($input['email']);
        } catch (InvalidArgumentException) {
            throw new ProviderAccessException('PROVIDER_SETUP_INPUT_INVALID', 422);
        }
        $password = $input['password'] ?? null;
        $confirmation = $input['password_confirmation'] ?? null;
        if (! is_string($password) || ! is_string($confirmation) || strlen($password) < 14 || strlen($password) > 72
            || ! preg_match('//u', $password) || str_contains($password, "\0")
            || ! preg_match('/\p{Ll}/u', $password) || ! preg_match('/\p{Lu}/u', $password)
            || ! preg_match('/\p{N}/u', $password) || ! preg_match('/[\p{P}\p{S}]/u', $password)
            || ! hash_equals($password, $confirmation)
            || array_diff(array_keys($input), ['bootstrap_secret', 'email', 'password', 'password_confirmation']) !== []) {
            throw new ProviderAccessException('PROVIDER_SETUP_INPUT_INVALID', 422);
        }
        return ['email' => $email, 'password' => $password];
    }

    private function isLoopback(string $host): bool
    {
        $host = strtolower($host);
        return in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true) || str_ends_with($host, '.localhost');
    }
}
