<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\IncidentController;
use App\Http\Controllers\AlertPolicyController;
use App\Http\Controllers\MitigationController;
use App\Http\Controllers\TelemetryController;

Route::prefix('v1')->group(function () {
    // Incident Lifecycle
    Route::get('/incidents', [IncidentController::class, 'index']);
    Route::get('/incidents/{id}', [IncidentController::class, 'show']);
    Route::post('/incidents', [IncidentController::class, 'store']);
    Route::patch('/incidents/{id}/status', [IncidentController::class, 'updateStatus']);

    // Alert Policies
    Route::get('/policies', [AlertPolicyController::class, 'index']);
    Route::post('/policies', [AlertPolicyController::class, 'store']);
    Route::put('/policies/{id}', [AlertPolicyController::class, 'update']);
    Route::delete('/policies/{id}', [AlertPolicyController::class, 'destroy']);

    // Automated Mitigation
    Route::post('/mitigation/generate', [MitigationController::class, 'generate']);
    Route::post('/mitigation/{id}/apply', [MitigationController::class, 'apply']);

    // Telemetry & Engine Bridge
    Route::get('/telemetry/status', [TelemetryController::class, 'status']);
    Route::get('/telemetry/events', [TelemetryController::class, 'events']);
    Route::get('/telemetry/topology', [TelemetryController::class, 'topology']);
    Route::get('/telemetry/netflow', [TelemetryController::class, 'netflow']);
    Route::post('/telemetry/simulate/{scenario}', [TelemetryController::class, 'simulate']);
});
