<?php

namespace App\Modules\Identity\Domain;

use InvalidArgumentException;
use Normalizer;

final class EmailAddressNormalizer
{
    public function normalize(string $value): string
    {
        $email = preg_replace('/^\s+|\s+$/u', '', $value);
        if (! is_string($email) || $email === '') {
            throw new InvalidArgumentException('Invalid email address.');
        }

        if (class_exists(Normalizer::class)) {
            $normalized = Normalizer::normalize($email, Normalizer::FORM_C);
            if (! is_string($normalized)) {
                throw new InvalidArgumentException('Invalid email address.');
            }
            $email = $normalized;
        } elseif (preg_match('/[^\x00-\x7F]/', $email)) {
            throw new InvalidArgumentException('Unicode email normalization is unavailable.');
        }

        if (substr_count($email, '@') !== 1) {
            throw new InvalidArgumentException('Invalid email address.');
        }

        [$local, $domain] = explode('@', $email, 2);
        if ($local === '' || $domain === '') {
            throw new InvalidArgumentException('Invalid email address.');
        }

        if (function_exists('idn_to_ascii')) {
            $asciiDomain = idn_to_ascii($domain, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if (! is_string($asciiDomain)) {
                throw new InvalidArgumentException('Invalid internationalized email domain.');
            }
            $domain = $asciiDomain;
        } elseif (preg_match('/[^\x00-\x7F]/', $domain)) {
            throw new InvalidArgumentException('Internationalized email domains are unavailable.');
        }

        $canonical = mb_convert_case($local, MB_CASE_FOLD, 'UTF-8').'@'.strtolower($domain);

        if (strlen($canonical) > 254 || filter_var($canonical, FILTER_VALIDATE_EMAIL) === false) {
            throw new InvalidArgumentException('Invalid email address.');
        }

        return $canonical;
    }
}
