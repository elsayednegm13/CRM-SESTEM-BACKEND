<?php

namespace App\Modules\Tenancy\Domain;

enum ResourceScope: string
{
    case ALL_TENANT = 'ALL_TENANT';
    case TEAM = 'TEAM';
    case ASSIGNED = 'ASSIGNED';
    case SELF = 'SELF';
    case NONE = 'NONE';
}
