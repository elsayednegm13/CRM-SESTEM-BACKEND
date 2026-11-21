<?php

namespace Tests\Support;

use CurlHandle;
use RuntimeException;

/** Real HTTP client for the pinned, private ENG-03A application runner. */
final class Eng03ProviderFixture
{
    private CurlHandle $handle;

    public function __construct(private readonly string $host, private readonly string $origin, string $serverIp)
    {
        $this->handle = curl_init();
        curl_setopt_array($this->handle, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_COOKIEFILE => '',
            CURLOPT_NOPROXY => '*',
            CURLOPT_TIMEOUT => 90,
            CURLOPT_RESOLVE => ["{$host}:8000:{$serverIp}"],
        ]);
    }

    /** @return array{status:int,data:mixed,error_code:?string,has_xsrf_cookie:bool} */
    public function request(string $method, string $path, ?array $body = null, array $headers = [], bool $withCsrf = true): array
    {
        $requestHeaders = ['Accept: application/json', 'Origin: '.$this->origin];
        if ($body !== null) {
            $requestHeaders[] = 'Content-Type: application/json';
        }
        if ($method !== 'GET' && $withCsrf && ($token = $this->xsrfToken()) !== null) {
            $requestHeaders[] = 'X-XSRF-TOKEN: '.$token;
        }
        foreach ($headers as $key => $value) {
            $requestHeaders[] = "{$key}: {$value}";
        }
        curl_setopt($this->handle, CURLOPT_URL, "http://{$this->host}:8000{$path}");
        curl_setopt($this->handle, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($this->handle, CURLOPT_HTTPHEADER, $requestHeaders);
        curl_setopt($this->handle, CURLOPT_POSTFIELDS, $body === null ? null : json_encode($body, JSON_THROW_ON_ERROR));
        $raw = curl_exec($this->handle);
        if ($raw === false) {
            throw new RuntimeException('Private HTTP transport failed: '.curl_error($this->handle));
        }
        $json = json_decode(substr($raw, curl_getinfo($this->handle, CURLINFO_HEADER_SIZE)), true);

        return [
            'status' => curl_getinfo($this->handle, CURLINFO_HTTP_CODE),
            'data' => is_array($json) ? ($json['data'] ?? null) : null,
            'error_code' => is_array($json) ? ($json['error']['code'] ?? null) : null,
            'has_xsrf_cookie' => $this->xsrfToken() !== null,
        ];
    }

    private function xsrfToken(): ?string
    {
        foreach (curl_getinfo($this->handle, CURLINFO_COOKIELIST) ?: [] as $line) {
            $fields = explode("\t", $line);
            if (($fields[5] ?? null) === 'XSRF-TOKEN') {
                return urldecode($fields[6] ?? '');
            }
        }

        return null;
    }
}
