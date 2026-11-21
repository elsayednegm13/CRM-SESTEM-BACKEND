<?php

namespace App\Modules\Tenancy\Infrastructure\Persistence;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use InvalidArgumentException;

final class Tenant extends Model
{
    use HasUuids;

    protected $fillable = ['display_name', 'legal_name', 'slug', 'timezone', 'default_locale'];

    public function newUniqueId(): string
    {
        return (string) Str::uuid7();
    }

    public function setTimezoneAttribute(string $value): void
    {
        if (! in_array($value, timezone_identifiers_list(), true)) {
            throw new InvalidArgumentException('A valid IANA timezone is required.');
        }
        $this->attributes['timezone'] = $value;
    }

    public function setDefaultLocaleAttribute(string $value): void
    {
        if (! in_array($value, config('tenancy.supported_locales'), true)) {
            throw new InvalidArgumentException('A supported locale is required.');
        }
        $this->attributes['default_locale'] = $value;
    }
}
