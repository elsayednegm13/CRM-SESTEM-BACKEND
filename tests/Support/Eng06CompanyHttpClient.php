<?php

namespace Tests\Support;

use CurlHandle;
use RuntimeException;

/** Pinned HTTP client for the private ENG-06 container network. */
final class Eng06CompanyHttpClient
{
    private static ?string $canarySecret = null;

    private CurlHandle $handle;

    public function __construct(
        private readonly string $host,
        private readonly string $origin,
        string $serverIp,
    ) {
        $this->handle = curl_init();
        curl_setopt_array($this->handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_COOKIEFILE => '',
            CURLOPT_NOPROXY => '*',
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 35,
            CURLOPT_RESOLVE => ["{$host}:8000:{$serverIp}"],
        ]);
    }

    /**
     * @return array{status:int,data:mixed,meta:array,error_code:?string,error_fields:array,raw_body:string,elapsed_ms:float,canary_secret_present:false,canary_surfaces_scanned:int,safe_provider_diagnostic_present:bool}
     */
    public function request(
        string $method,
        string $path,
        ?array $body = null,
        array $headers = [],
        bool $withCsrf = true,
    ): array {
        $headerNames = array_map('strtolower', array_keys($headers));
        $requestHeaders = ['Accept: application/json', 'Host: '.$this->host];
        if (! in_array('origin', $headerNames, true)) {
            $requestHeaders[] = 'Origin: '.$this->origin;
        }
        if ($body !== null) {
            $requestHeaders[] = 'Content-Type: application/json';
        }
        if ($method !== 'GET' && $withCsrf && ($token = $this->xsrfToken()) !== null) {
            $requestHeaders[] = 'X-XSRF-TOKEN: '.$token;
        }
        foreach ($headers as $key => $value) {
            $requestHeaders[] = "{$key}: {$value}";
        }

        curl_setopt($this->handle, CURLOPT_URL, 'http://'.$this->host.':8000'.$path);
        curl_setopt($this->handle, CURLOPT_CUSTOMREQUEST, strtoupper($method));
        curl_setopt($this->handle, CURLOPT_HTTPHEADER, $requestHeaders);
        curl_setopt($this->handle, CURLOPT_POSTFIELDS, $body === null
            ? null
            : json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

        $raw = curl_exec($this->handle);
        if ($raw === false) {
            throw new RuntimeException('Private HTTP transport failed: '.curl_errno($this->handle));
        }

        $headerSize = (int) curl_getinfo($this->handle, CURLINFO_HEADER_SIZE);
        $rawBody = substr($raw, $headerSize);
        $json = json_decode($rawBody, true);
        $surfacesScanned = $this->assertCanaryAbsent($raw);

        return [
            'status' => (int) curl_getinfo($this->handle, CURLINFO_HTTP_CODE),
            'data' => is_array($json) ? ($json['data'] ?? null) : null,
            'meta' => is_array($json) ? ($json['meta'] ?? []) : [],
            'error_code' => is_array($json) ? ($json['error']['code'] ?? null) : null,
            'error_fields' => is_array($json) ? ($json['error']['fields'] ?? []) : [],
            'raw_body' => $rawBody,
            'elapsed_ms' => round((float) curl_getinfo($this->handle, CURLINFO_TOTAL_TIME) * 1000, 3),
            'canary_secret_present' => false,
            'canary_surfaces_scanned' => $surfacesScanned,
            'safe_provider_diagnostic_present' => $this->hasSafeProviderDiagnostic(),
        ];
    }

    private function assertCanaryAbsent(string $response): int
    {
        $canary = self::$canarySecret ??= trim((string) @file_get_contents('/fixture/eng06a_canary_password'));
        if (strlen($canary) < 12) {
            throw new RuntimeException('ENG-06A canary guard is unavailable; STOP.');
        }

        if (str_contains($response, $canary)) {
            throw new RuntimeException('CANARY_SECRET_PRESENT=true in HTTP response; STOP.');
        }

        $surfaces = 1;
        foreach (['/evidence_a/logs', '/evidence_b/logs', '/evidence_c/logs'] as $root) {
            if (! is_dir($root) || ! is_readable($root)) {
                throw new RuntimeException('ENG-06A log capture is unavailable; STOP.');
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
            );
            foreach ($iterator as $file) {
                if (! $file->isFile() || ! preg_match('/\\.log(?:\\.\\d+)?$/i', $file->getFilename())) {
                    continue;
                }

                $contents = @file_get_contents($file->getPathname());
                if (! is_string($contents)) {
                    throw new RuntimeException('ENG-06A log capture could not be read; STOP.');
                }
                $surfaces++;
                if (str_contains($contents, $canary)) {
                    throw new RuntimeException('CANARY_SECRET_PRESENT=true in private log; STOP.');
                }
            }
        }

        return $surfaces;
    }

    private function hasSafeProviderDiagnostic(): bool
    {
        $found = false;
        foreach (['/evidence_a/logs', '/evidence_b/logs', '/evidence_c/logs'] as $root) {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
            );
            foreach ($iterator as $file) {
                if (! $file->isFile() || ! preg_match('/\\.log(?:\\.\\d+)?$/i', $file->getFilename())) {
                    continue;
                }

                $contents = @file_get_contents($file->getPathname());
                if (is_string($contents)
                    && str_contains($contents, 'Provider provisioning persistence failure; details sanitized.')
                    && str_contains($contents, 'POSTGRES_PRIVILEGE_OR_RLS_DENIAL')
                    && str_contains($contents, '42501')) {
                    $found = true;
                }
            }
        }

        return $found;
    }

    public function cookieHeader(): string
    {
        $cookies = [];
        foreach (curl_getinfo($this->handle, CURLINFO_COOKIELIST) ?: [] as $line) {
            $fields = explode("\t", $line);
            if (isset($fields[5], $fields[6])) {
                $cookies[] = $fields[5].'='.$fields[6];
            }
        }

        return implode('; ', $cookies);
    }

    public function cookieValue(string $name): ?string
    {
        foreach (curl_getinfo($this->handle, CURLINFO_COOKIELIST) ?: [] as $line) {
            $fields = explode("\t", $line);
            if (($fields[5] ?? null) === $name) {
                return $fields[6] ?? null;
            }
        }

        return null;
    }

    private function xsrfToken(): ?string
    {
        $value = $this->cookieValue('XSRF-TOKEN');

        return is_string($value) ? urldecode($value) : null;
    }
}
