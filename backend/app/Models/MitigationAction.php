<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class MitigationAction extends Model
{
    use HasFactory;

    protected $fillable = [
        'incident_id',
        'action_type',
        'router_target',
        'config_payload',
        'status',
        'applied_at',
    ];

    protected $casts = [
        'applied_at' => 'datetime',
    ];

    public function incident()
    {
        return $this->belongsTo(Incident::class, 'incident_id');
    }
}
