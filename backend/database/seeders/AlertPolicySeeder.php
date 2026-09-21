<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\AlertPolicy;

class AlertPolicySeeder extends Seeder
{
    public function run(): void
    {
        AlertPolicy::create([
            'name' => 'Critical Prefix Hijack & Route Leak Guard',
            'monitored_prefixes' => ['8.8.8.0/24', '1.1.1.0/24', '208.67.222.0/24', '13.32.0.0/15'],
            'monitored_asns' => [15169, 13335, 36692, 16509],
            'severity_threshold' => 'HIGH',
            'webhook_url' => 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
            'webhook_channel' => 'SLACK',
            'is_active' => true,
        ]);

        AlertPolicy::create([
            'name' => 'PagerDuty 24/7 Tier-1 Transit Emergency',
            'monitored_prefixes' => ['8.8.8.0/24', '1.1.1.0/24'],
            'monitored_asns' => [15169, 13335],
            'severity_threshold' => 'CRITICAL',
            'webhook_url' => 'https://events.pagerduty.com/v2/enqueue',
            'webhook_channel' => 'PAGERDUTY',
            'is_active' => true,
        ]);
    }
}
