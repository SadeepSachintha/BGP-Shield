<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Incident extends Model
{
    use HasFactory;

    public $incrementing = false;
    protected $keyType = 'string';

    protected $fillable = [
        'id',
        'incident_type',
        'severity',
        'target_prefix',
        'victim_asn',
        'victim_name',
        'attacker_asn',
        'attacker_name',
        'status',
        'detected_at',
        'mitigated_at',
        'evidence',
    ];

    protected $casts = [
        'evidence' => 'array',
        'detected_at' => 'datetime',
        'mitigated_at' => 'datetime',
    ];

    public function mitigationActions()
    {
        return $this->hasMany(MitigationAction::class, 'incident_id');
    }
}
