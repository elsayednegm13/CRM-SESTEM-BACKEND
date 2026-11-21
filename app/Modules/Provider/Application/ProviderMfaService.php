<?php

namespace App\Modules\Provider\Application;

use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Shared\Audit\AuditEventType;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;
use OTPHP\TOTP;

final class ProviderMfaService
{
    public function __construct(private readonly SecurityAuditWriter $audit) {}

    /** @return array{secret:string,otpauth_uri:string} */
    public function startEnrollment(string $email): array
    {
        $totp = TOTP::generate(null, 32)->withLabel($email)->withIssuer('Daleel CRM Provider');
        return ['secret' => $totp->getSecret(), 'otpauth_uri' => $totp->getProvisioningUri()];
    }

    public function matchingCounter(string $secret, string $code, ?int $timestamp = null): ?int
    {
        if (! preg_match('/^[0-9]{6}$/D', $code)) {
            return null;
        }
        $timestamp ??= now('UTC')->timestamp;
        $period = (int) config('provider.totp_period_seconds');
        $current = intdiv($timestamp, $period);
        $totp = TOTP::createFromSecret($secret);
        $matched = null;
        for ($offset = -((int) config('provider.totp_skew_steps')); $offset <= (int) config('provider.totp_skew_steps'); $offset++) {
            $counter = $current + $offset;
            if ($counter >= 0 && hash_equals($totp->at($counter * $period), $code)) {
                $matched = max($matched ?? 0, $counter);
            }
        }
        return $matched;
    }

    /** @return list<string> */
    public function enroll(ConnectionInterface $connection, string $providerId, string $secret, int $counter,
        string $requestId): array
    {
        $connection->table('provider_mfa_totp')->insert([
            'provider_user_id' => $providerId,
            'secret_ciphertext' => Crypt::encryptString($secret),
            'confirmed_at' => now('UTC'),
            'last_used_counter' => $counter,
            'created_at' => now('UTC'), 'updated_at' => now('UTC'),
        ]);
        $codes = [];
        for ($i = 0; $i < 10; $i++) {
            $code = strtoupper(bin2hex(random_bytes(16)));
            $codes[] = $code;
            $connection->table('provider_mfa_recovery_codes')->insert([
                'id' => (string) Str::uuid7(), 'provider_user_id' => $providerId,
                'code_hash' => $this->recoveryHash($code),
                'created_at' => now('UTC'), 'updated_at' => now('UTC'),
            ]);
        }
        $this->audit->appendProviderMutation($providerId, $requestId,
            AuditEventType::PROVIDER_MFA_ENROLLED, $providerId);
        return $codes;
    }

    /** Consume one factor under the provider DB transaction. */
    public function consumeFactor(ConnectionInterface $connection, string $providerId, string $code,
        string $requestId): void
    {
        // Serialize every factor consumption on the Provider principal. The
        // runtime intentionally has UPDATE only on the mutable MFA columns;
        // PostgreSQL SELECT ... FOR UPDATE on an MFA table would otherwise
        // require a broader table-level UPDATE grant. A single principal lock
        // also orders TOTP and recovery-code attempts against each other.
        $providerExists = $connection->table('provider_users')->where('id', $providerId)
            ->lockForUpdate()->exists();
        if (! $providerExists) {
            throw ProviderAccessException::mfaInvalid();
        }

        if (preg_match('/^[0-9]{6}$/D', $code)) {
            $row = $connection->table('provider_mfa_totp')->where('provider_user_id', $providerId)
                ->first(['secret_ciphertext', 'last_used_counter']);
            if (! $row) {
                throw ProviderAccessException::mfaInvalid();
            }
            $counter = $this->matchingCounter(Crypt::decryptString($row->secret_ciphertext), $code);
            if ($counter === null) {
                throw ProviderAccessException::mfaInvalid();
            }
            if ($row->last_used_counter !== null && $counter <= (int) $row->last_used_counter) {
                throw ProviderAccessException::mfaReplayed();
            }
            $connection->table('provider_mfa_totp')->where('provider_user_id', $providerId)
                ->update(['last_used_counter' => $counter, 'updated_at' => now('UTC')]);
            return;
        }
        if (! preg_match('/^[A-Fa-f0-9]{32}$/D', $code)) {
            throw ProviderAccessException::mfaInvalid();
        }
        $row = $connection->table('provider_mfa_recovery_codes')
            ->where('provider_user_id', $providerId)->where('code_hash', $this->recoveryHash(strtoupper($code)))
            ->whereNull('used_at')->first(['id']);
        if (! $row) {
            throw ProviderAccessException::mfaInvalid();
        }
        $connection->table('provider_mfa_recovery_codes')->where('id', $row->id)
            ->whereNull('used_at')->update(['used_at' => now('UTC'), 'updated_at' => now('UTC')]);
        $this->audit->appendProviderMutation($providerId, $requestId,
            AuditEventType::PROVIDER_RECOVERY_CODE_USED, $providerId);
    }

    private function recoveryHash(string $code): string
    {
        // Codes have 128 random bits; keyed SHA-256 permits an indexed, constant-shape lookup.
        return hash_hmac('sha256', $code, (string) config('app.key'));
    }
}
