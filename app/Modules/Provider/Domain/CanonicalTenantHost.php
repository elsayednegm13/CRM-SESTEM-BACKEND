<?php

namespace App\Modules\Provider\Domain;

use InvalidArgumentException;

/** A platform-generated tenant host; custom domains are not representable here. */
final readonly class CanonicalTenantHost
{
    private const RESERVED_SLUGS = [
        'admin', 'api', 'assets', 'auth', 'billing', 'cdn', 'docs', 'help',
        'legacy', 'mail', 'marketing', 'platform', 'root', 'static', 'status', 'superadmin', 'support', 'www',
    ];

    private function __construct(
        private string $slug,
        private string $baseDomain,
        private string $value,
    ) {}

    public static function forSlug(
        string $slug,
        ?string $baseDomain,
        string $environment = 'production',
        bool $allowLocalhostBaseDomain = false,
        ?string $localTestBaseDomain = null,
    ): self
    {
        if ($baseDomain === null || $baseDomain === '' || $baseDomain !== strtolower($baseDomain)
            || strlen($baseDomain) > 253 || filter_var($baseDomain, FILTER_VALIDATE_IP) !== false) {
            throw new InvalidArgumentException('A canonical configured base domain is required.');
        }

        $labels = explode('.', $baseDomain);
        if (count($labels) < 2 || preg_match('/[a-z]/', end($labels)) !== 1) {
            throw new InvalidArgumentException('The configured base domain is not a canonical DNS name.');
        }

        foreach ($labels as $label) {
            if (strlen($label) > 63 || preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/D', $label) !== 1) {
                throw new InvalidArgumentException('The configured base domain is not a canonical DNS name.');
            }
        }

        if (str_ends_with($baseDomain, '.localhost')
            && (! in_array($environment, ['local', 'testing'], true)
                || ! $allowLocalhostBaseDomain
                || $localTestBaseDomain === null
                || $baseDomain !== $localTestBaseDomain)) {
            throw new InvalidArgumentException('The configured local test domain is not permitted in this environment.');
        }

        if (preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug) !== 1
            || strlen($slug) > 100 || in_array($slug, self::RESERVED_SLUGS, true)) {
            throw new InvalidArgumentException('The tenant slug is invalid or reserved.');
        }

        $hostname = $slug.'.'.$baseDomain;
        if (strlen($hostname) > 253) {
            throw new InvalidArgumentException('The resulting tenant hostname is too long.');
        }

        return new self($slug, $baseDomain, $hostname);
    }

    public function slug(): string
    {
        return $this->slug;
    }

    public function baseDomain(): string
    {
        return $this->baseDomain;
    }

    public function value(): string
    {
        return $this->value;
    }
}
