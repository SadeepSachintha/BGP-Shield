<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AlertPolicy extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'monitored_prefixes',
        'monitored_asns',
        'severity_threshold',
        'webhook_url',
        'webhook_channel',
        'is_active',
    ];

    protected $casts = [
        'monitored_prefixes' => 'array',
        'monitored_asns' => 'array',
        'is_active' => 'boolean',
    ];
}
