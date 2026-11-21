<?php

namespace App\Modules\Identity\Domain;

/** Pure positive-union resolver. Null means the entire authorization snapshot must be denied. */
final class EffectivePermissions
{
    private const VALID_SCOPES = ['ALL_TENANT', 'TEAM', 'ASSIGNED', 'SELF', 'NONE'];

    /**
     * @param array<int, array{permission_key:string,scope:?string}> $roleGrants
     * @param array<int, array{permission_key:string,scope:?string}> $directGrants
     * @param array<string, array{status:string,scopeable:bool,allowed_scopes:array<int,string>,delegable:bool}> $catalog
     * @return array<string, array<int,string>>|null Sorted permission keys and sorted unique scopes, or null for invalid source data.
     */
    public function resolve(array $roleGrants, array $directGrants, array $catalog): ?array
    {
        $effective = [];

        foreach ([['grants' => $roleGrants, 'direct' => false], ['grants' => $directGrants, 'direct' => true]] as $source) {
            foreach ($source['grants'] as $grant) {
                if (! is_array($grant)) {
                    return null;
                }
                $permission = $grant['permission_key'] ?? null;
                $scope = $grant['scope'] ?? null;
                $metadata = is_string($permission) ? ($catalog[$permission] ?? null) : null;

                if (! is_array($metadata)
                    || ($metadata['status'] ?? null) !== 'ACTIVE'
                    || ! is_bool($metadata['scopeable'] ?? null)
                    || ! is_array($metadata['allowed_scopes'] ?? null)
                    || ! is_bool($metadata['delegable'] ?? null)
                    || ($source['direct'] && $metadata['delegable'] !== true)
                    || ! $this->scopeIsValid($metadata, $scope)) {
                    return null;
                }

                if ($scope === 'NONE') {
                    continue;
                }

                $effective[$permission] ??= [];
                if (! in_array($scope, $effective[$permission], true)) {
                    $effective[$permission][] = $scope;
                }
            }
        }

        ksort($effective);
        foreach ($effective as &$scopes) {
            if (in_array('ALL_TENANT', $scopes, true)) {
                $scopes = ['ALL_TENANT'];
            } else {
                sort($scopes);
            }
        }
        unset($scopes);

        return $effective;
    }

    /** @param array{scopeable:bool,allowed_scopes:array<int,string>} $metadata */
    private function scopeIsValid(array $metadata, mixed $scope): bool
    {
        if (! is_array($metadata['allowed_scopes'])
            || array_diff($metadata['allowed_scopes'], self::VALID_SCOPES) !== []) {
            return false;
        }

        if ($metadata['scopeable']) {
            return is_string($scope)
                && in_array($scope, self::VALID_SCOPES, true)
                && in_array($scope, $metadata['allowed_scopes'], true);
        }

        return $scope === null && $metadata['allowed_scopes'] === [];
    }
}
