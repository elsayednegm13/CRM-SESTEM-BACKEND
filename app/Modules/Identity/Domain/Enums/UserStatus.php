<?php

namespace App\Modules\Identity\Domain\Enums;

enum UserStatus: string
{
    case ACTIVE = 'ACTIVE';
    case DISABLED = 'DISABLED';
}
