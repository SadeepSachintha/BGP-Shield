<?php

namespace App\Services;

use App\Models\Incident;
use App\Models\AlertPolicy;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class WebhookDispatcher
{
    /**
     * Dispatch incident notification according to configured alert policies.
     */
    public function dispatchIncident(Incident $incident): array
    {
        $policies = AlertPolicy::where('is_active', true)->get();
        $dispatched = [];

        foreach ($policies as $policy) {
            // Check severity match
            if ($this->shouldTrigger($policy, $incident)) {
                $payload = $this->formatPayload($policy->webhook_channel, $incident);
                if ($policy->webhook_url) {
                    try {
                        $res = Http::timeout(3)->post($policy->webhook_url, $payload);
                        $dispatched[] = [
                            'policy' => $policy->name,
                            'status' => $res->status(),
                            'success' => $res->successful(),
                        ];
                    } catch (\Exception $e) {
                        Log::error("Webhook dispatch failed for policy {$policy->name}: " . $e->getMessage());
                        $dispatched[] = [
                            'policy' => $policy->name,
                            'status' => 'ERROR',
                            'error' => $e->getMessage(),
                        ];
                    }
                }
            }
        }

        return $dispatched;
    }

    protected function shouldTrigger(AlertPolicy $policy, Incident $incident): bool
    {
        $severities = ['LOW' => 1, 'MEDIUM' => 2, 'HIGH' => 3, 'CRITICAL' => 4];
        $policyLevel = $severities[$policy->severity_threshold] ?? 3;
        $incidentLevel = $severities[$incident->severity] ?? 3;

        return $incidentLevel >= $policyLevel;
    }

    protected function formatPayload(string $channel, Incident $incident): array
    {
        if (strtoupper($channel) === 'SLACK') {
            return [
                'text' => "🚨 *BGP-Shield Alert: {$incident->incident_type} Detected!*",
                'attachments' => [
                    [
                        'color' => $incident->severity === 'CRITICAL' ? '#ef4444' : '#f59e0b',
                        'fields' => [
                            ['title' => 'Target Prefix', 'value' => $incident->target_prefix, 'short' => true],
                            ['title' => 'Severity', 'value' => $incident->severity, 'short' => true],
                            ['title' => 'Victim', 'value' => "AS{$incident->victim_asn} ({$incident->victim_name})", 'short' => true],
                            ['title' => 'Attacker / Leaker', 'value' => "AS{$incident->attacker_asn} ({$incident->attacker_name})", 'short' => true],
                            ['title' => 'Incident ID', 'value' => $incident->id, 'short' => false],
                        ],
                        'footer' => 'BGP-Shield Route Leak Sentinel',
                        'ts' => time(),
                    ]
                ]
            ];
        }

        if (strtoupper($channel) === 'PAGERDUTY') {
            return [
                'routing_key' => 'bgp-shield-sentinel',
                'event_action' => 'trigger',
                'payload' => [
                    'summary' => "[{$incident->severity}] {$incident->incident_type} on {$incident->target_prefix}",
                    'severity' => strtolower($incident->severity) === 'critical' ? 'critical' : 'error',
                    'source' => 'BGP-Shield Sentinel',
                    'custom_details' => [
                        'victim_asn' => $incident->victim_asn,
                        'attacker_asn' => $incident->attacker_asn,
                        'incident_id' => $incident->id,
                    ]
                ]
            ];
        }

        // Generic webhook payload
        return [
            'event' => 'BGP_SECURITY_INCIDENT',
            'incident' => $incident->toArray(),
            'timestamp' => now()->toISOString(),
        ];
    }
}
