<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

/** Retain the command name/required email so existing callers fail explicitly. */
final class BootstrapProviderRoot extends Command
{
    protected $signature = 'provider:bootstrap-root {email : Deprecated; no account will be created}';

    protected $description = 'Deprecated: use the protected one-time Provider setup flow';

    public function handle(): int
    {
        $this->error('Provider CLI bootstrap is disabled. Use the protected first-install setup flow. No account was created.');
        return self::FAILURE;
    }
}
