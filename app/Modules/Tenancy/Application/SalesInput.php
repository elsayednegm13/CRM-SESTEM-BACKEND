<?php

declare(strict_types=1);

namespace App\Modules\Tenancy\Application;

use App\Modules\Tenancy\Domain\CustomerInputException;

/** Pure W3 validation used by source-only tests and runtime services. */
final class SalesInput
{
    /** @param array<string,mixed> $input @return array<string,mixed> */
    public static function deal(array $input): array
    {
        $title = self::required($input['title'] ?? null, 'title', 160);
        $currency = strtoupper((string) ($input['currency_code'] ?? ''));
        if (preg_match('/^[A-Z]{3}$/D', $currency) !== 1) self::invalid('currency_code', 'Currency must use ISO-4217.');
        $value = (string) ($input['value_amount'] ?? '');
        if (preg_match('/^\d{1,16}(?:\.\d{1,4})?$/D', $value) !== 1) self::invalid('value_amount', 'Value must be a non-negative decimal.');
        return ['title' => $title, 'customer_id' => self::uuid($input['customer_id'] ?? null, 'customer_id'),
            'contact_id' => self::nullableUuid($input['contact_id'] ?? null, 'contact_id'),
            'pipeline_id' => self::uuid($input['pipeline_id'] ?? null, 'pipeline_id'),
            'stage_id' => self::uuid($input['stage_id'] ?? null, 'stage_id'),
            'value_amount' => $value, 'currency_code' => $currency,
            'owner_membership_id' => self::nullableUuid($input['owner_membership_id'] ?? null, 'owner_membership_id')];
    }

    /** @param array<string,mixed> $input @return array<string,mixed> */
    public static function task(array $input): array
    {
        $customer = self::nullableUuid($input['customer_id'] ?? null, 'customer_id');
        $deal = self::nullableUuid($input['deal_id'] ?? null, 'deal_id');
        if (($customer === null) === ($deal === null)) self::invalid('relation', 'Task requires exactly one customer or deal.');
        $status = $input['status'] ?? 'TODO';
        if (!in_array($status, ['TODO', 'IN_PROGRESS', 'DONE', 'CANCELLED'], true)) self::invalid('status', 'Task status is invalid.');
        $priority = $input['priority'] ?? 'NORMAL';
        if (!in_array($priority, ['LOW', 'NORMAL', 'HIGH'], true)) self::invalid('priority', 'Task priority is invalid.');
        return ['title' => self::required($input['title'] ?? null, 'title', 160),
            'description' => self::nullable($input['description'] ?? null, 'description', 2000), 'customer_id' => $customer, 'deal_id' => $deal,
            'assignee_membership_id' => self::nullableUuid($input['assignee_membership_id'] ?? null, 'assignee_membership_id'),
            'due_at' => self::nullableTimestamp($input['due_at'] ?? null), 'status' => $status, 'priority' => $priority];
    }

    /** @param array<string,mixed> $input @return array{from_stage_id:string,to_stage_id:string,version:int} */
    public static function transition(array $input): array
    {
        $version = $input['version'] ?? null;
        if (!is_int($version) || $version < 1) self::invalid('version', 'Version is invalid.');
        return ['from_stage_id' => self::uuid($input['from_stage_id'] ?? null, 'from_stage_id'), 'to_stage_id' => self::uuid($input['to_stage_id'] ?? null, 'to_stage_id'), 'version' => $version];
    }

    private static function required(mixed $value, string $field, int $max): string { $value=self::nullable($value,$field,$max); if($value===null) self::invalid($field,'This field is required.'); return $value; }
    private static function nullable(mixed $value, string $field, int $max): ?string { if($value===null)return null; if(!is_string($value))self::invalid($field,'This field is invalid.'); $value=trim($value); if($value==='')return null; if(mb_strlen($value)>$max)self::invalid($field,'This field is too long.'); return $value; }
    private static function uuid(mixed $value,string $field): string { $value=self::nullableUuid($value,$field); if($value===null)self::invalid($field,'This field is required.'); return $value; }
    private static function nullableUuid(mixed $value,string $field): ?string { $value=self::nullable($value,$field,36); if($value!==null && preg_match('/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/Di',$value)!==1)self::invalid($field,'This field must be a UUID.'); return $value; }
    private static function nullableTimestamp(mixed $value): ?string { $value=self::nullable($value,'due_at',64); if($value===null)return null; try { return (new \DateTimeImmutable($value))->setTimezone(new \DateTimeZone('UTC'))->format(DATE_ATOM); } catch(\Exception){self::invalid('due_at','Due time is invalid.');} }
    private static function invalid(string $field,string $message): never { throw new CustomerInputException([$field=>[$message]]); }
}
