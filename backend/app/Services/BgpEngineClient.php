<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class BgpEngineClient
{
    protected string $engineUrl;

    public function __construct()
    {
        $this->engineUrl = config('services.bgp_engine.url', 'http://127.0.0.1:8000');
    }

    public function getStatus(): array
    {
        try {
            $response = Http::timeout(3)->get("{$this->engineUrl}/api/status");
            return $response->successful() ? $response->json() : ['status' => 'OFFLINE'];
        } catch (\Exception $e) {
            Log::warning("Failed to connect to BGP engine: " . $e->getMessage());
            return ['status' => 'OFFLINE', 'error' => $e->getMessage()];
        }
    }

    public function getEvents(int $limit = 50, bool $threatsOnly = false): array
    {
        try {
            $response = Http::timeout(3)->get("{$this->engineUrl}/api/events", [
                'limit' => $limit,
                'threats_only' => $threatsOnly ? 'true' : 'false',
            ]);
            return $response->successful() ? $response->json() : [];
        } catch (\Exception $e) {
            return [];
        }
    }

    public function getTopology(): array
    {
        try {
            $response = Http::timeout(3)->get("{$this->engineUrl}/api/topology");
            return $response->successful() ? $response->json() : ['nodes' => [], 'links' => []];
        } catch (\Exception $e) {
            return ['nodes' => [], 'links' => []];
        }
    }

    public function getNetFlow(): array
    {
        try {
            $response = Http::timeout(3)->get("{$this->engineUrl}/api/netflow");
            return $response->successful() ? $response->json() : [];
        } catch (\Exception $e) {
            return [];
        }
    }

    public function triggerSimulation(string $scenario): array
    {
        try {
            $response = Http::timeout(5)->post("{$this->engineUrl}/api/simulate/{$scenario}");
            return $response->successful() ? $response->json() : ['status' => 'FAILED'];
        } catch (\Exception $e) {
            return ['status' => 'ERROR', 'message' => $e->getMessage()];
        }
    }
}
