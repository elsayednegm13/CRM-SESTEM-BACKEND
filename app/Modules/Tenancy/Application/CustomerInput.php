<?php

declare(strict_types=1);

namespace App\Modules\Tenancy\Application;

use App\Modules\Tenancy\Domain\CustomerInputException;

/** Pure normalization shared by runtime services and source-only tests. */
final class CustomerInput
{
    /** @param array<string,mixed> $input @return array<string,mixed> */
    public static function normalizeCustomer(array $input): array
    {
        $type = $input['type'] ?? 'PERSON';
        if (! in_array($type, ['PERSON', 'ORGANIZATION'], true)) {
            self::invalid('type', 'Customer type is invalid.');
        }
        $displayName = self::required($input['display_name'] ?? null, 'display_name', 160);
        $legalName = self::nullable($input['legal_name'] ?? null, 'legal_name', 200);
        if ($type === 'ORGANIZATION' && $legalName === null) {
            self::invalid('legal_name', 'An organization requires a legal name.');
        }
        $country = self::nullable($input['country_code'] ?? null, 'country_code', 2);
        if ($country !== null && preg_match('/^[A-Z]{2}$/D', $country) !== 1) {
            self::invalid('country_code', 'Country must use ISO-3166-1 alpha-2.');
        }

        $status = $input['status'] ?? 'ACTIVE';
        if (! in_array($status, ['ACTIVE', 'INACTIVE'], true)) {
            self::invalid('status', 'Customer status is invalid.');
        }
        return [
            'type' => $type,
            'display_name' => $displayName,
            'legal_name' => $legalName,
            'email' => self::normalizedEmail($input['email'] ?? null),
            'phone' => self::normalizedPhone($input['phone'] ?? null),
            'country_code' => $country,
            'status' => $status,
        ];
    }

    /** @param array<string,mixed> $input @return array<string,mixed> */
    public static function normalizeContact(array $input): array
    {
        return [
            'display_name' => self::required($input['display_name'] ?? null, 'display_name', 160),
            'email' => self::normalizedEmail($input['email'] ?? null),
            'phone' => self::normalizedPhone($input['phone'] ?? null),
            'job_title' => self::nullable($input['job_title'] ?? null, 'job_title', 120),
            'note' => self::nullable($input['note'] ?? null, 'note', 1000),
            'is_primary' => (bool) ($input['is_primary'] ?? false),
        ];
    }

    /** @param array<string,mixed> $input @return array<string,mixed> */
    public static function normalizeAddress(array $input): array
    {
        $kind = $input['kind'] ?? 'GENERAL';
        if (! in_array($kind, ['GENERAL', 'BILLING', 'SHIPPING'], true)) {
            self::invalid('kind', 'Address kind is invalid.');
        }

        $country = self::nullable($input['country_code'] ?? null, 'country_code', 2);
        if ($country !== null && preg_match('/^[A-Z]{2}$/D', $country) !== 1) {
            self::invalid('country_code', 'Country must use ISO-3166-1 alpha-2.');
        }

        return [
            'kind' => $kind,
            'line1' => self::required($input['line1'] ?? null, 'line1', 200),
            'line2' => self::nullable($input['line2'] ?? null, 'line2', 200),
            'city' => self::nullable($input['city'] ?? null, 'city', 100),
            'region' => self::nullable($input['region'] ?? null, 'region', 100),
            'postal_code' => self::nullable($input['postal_code'] ?? null, 'postal_code', 32),
            'country_code' => $country,
        ];
    }

    /** @param array<string,mixed> $customer @param array<string,mixed> $contact */
    public static function conversionFingerprint(array $customer, ?array $contact): string
    {
        $value = ['customer' => $customer, 'contact' => $contact];
        return hash('sha256', json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE));
    }

    private static function required(mixed $value, string $field, int $max): string
    {
        $value = self::nullable($value, $field, $max);
        if ($value === null) {
            self::invalid($field, 'This field is required.');
        }
        return $value;
    }

    private static function nullable(mixed $value, string $field, int $max): ?string
    {
        if ($value === null) return null;
        if (! is_string($value)) self::invalid($field, 'This field is invalid.');
        $value = trim($value);
        if ($value === '') return null;
        if (mb_strlen($value) > $max) self::invalid($field, 'This field is too long.');
        return $field === 'country_code' ? strtoupper($value) : $value;
    }

    private static function normalizedEmail(mixed $value): ?string
    {
        $email = self::nullable($value, 'email', 254);
        if ($email !== null && filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            self::invalid('email', 'Email is invalid.');
        }
        return $email === null ? null : mb_strtolower($email);
    }

    private static function normalizedPhone(mixed $value): ?string
    {
        $phone = self::nullable($value, 'phone', 32);
        if ($phone !== null && preg_match('/^\+?[0-9][0-9() .-]{5,31}$/D', $phone) !== 1) {
            self::invalid('phone', 'Phone is invalid.');
        }
        return $phone;
    }

    private static function invalid(string $field, string $message): never
    {
        throw new CustomerInputException([$field => [$message]]);
    }
}
