<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use InvalidArgumentException;

final class F3AcceptanceFixtureInput
{
    /** @param mixed $input @return array<string,mixed> */
    public function validate(mixed $input, string $expectedRunId, string $expectedDatabase): array
    {
        if (! is_array($input) || array_keys($input) !== ['run_id','expected_database','permit_id','provider','tenants']
            || ! is_string($input['run_id']) || ! hash_equals($expectedRunId, $input['run_id'])
            || ! is_string($input['expected_database']) || ! hash_equals($expectedDatabase, $input['expected_database'])
            || ! is_string($input['permit_id']) || preg_match('/\A[a-f0-9]{64}\z/D', $input['permit_id']) !== 1
            || ! is_array($input['provider']) || array_keys($input['provider']) !== ['bootstrap_secret','email','password']
            || ! preg_match('/\A[a-f0-9]{64}\z/D', (string) ($input['provider']['bootstrap_secret'] ?? ''))
            || ! $this->email($input['provider']['email'] ?? null) || ! $this->password($input['provider']['password'] ?? null)
            || ! is_array($input['tenants']) || array_keys($input['tenants']) !== ['A','B']) {
            throw new InvalidArgumentException('F3_FIXTURE_INPUT_INVALID');
        }
        foreach (['A','B'] as $key) {
            $tenant = $input['tenants'][$key] ?? null;
            if (! is_array($tenant) || array_keys($tenant) !== [
                'display_name','slug','timezone','admin_email','initial_password','password','observer_email','observer_password',
            ] || ! is_string($tenant['display_name']) || trim($tenant['display_name']) === ''
                || ! is_string($tenant['slug']) || preg_match('/\A[a-z0-9][a-z0-9-]{4,40}\z/D', $tenant['slug']) !== 1
                || ! is_string($tenant['timezone']) || ! in_array($tenant['timezone'], timezone_identifiers_list(), true)
                || ! $this->email($tenant['admin_email']) || ! $this->email($tenant['observer_email'])
                || hash_equals($tenant['admin_email'], $tenant['observer_email'])
                || ! $this->password($tenant['initial_password']) || ! $this->password($tenant['password'])
                || ! $this->password($tenant['observer_password'])
                || hash_equals($tenant['initial_password'], $tenant['password'])
                || hash_equals($tenant['password'], $tenant['observer_password'])) {
                throw new InvalidArgumentException('F3_FIXTURE_INPUT_INVALID');
            }
        }
        if (hash_equals($input['tenants']['A']['slug'], $input['tenants']['B']['slug'])
            || hash_equals($input['tenants']['A']['admin_email'], $input['tenants']['B']['admin_email'])
            || hash_equals($input['tenants']['A']['observer_email'], $input['tenants']['B']['observer_email'])
            || hash_equals($input['tenants']['A']['observer_email'], $input['tenants']['B']['admin_email'])
            || hash_equals($input['tenants']['B']['observer_email'], $input['tenants']['A']['admin_email'])) {
            throw new InvalidArgumentException('F3_FIXTURE_INPUT_NOT_DISTINCT');
        }

        return $input;
    }

    private function email(mixed $value): bool
    {
        return is_string($value) && strlen($value) <= 254 && filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }

    private function password(mixed $value): bool
    {
        return is_string($value) && strlen($value) >= 14 && strlen($value) <= 72
            && preg_match('/[a-z]/', $value) && preg_match('/[A-Z]/', $value)
            && preg_match('/[0-9]/', $value) && preg_match('/[^a-zA-Z0-9]/', $value);
    }
}
