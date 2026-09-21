<?php

namespace App\Http\Controllers;

use App\Services\BgpEngineClient;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class TelemetryController extends Controller
{
    protected BgpEngineClient $engineClient;

    public function __construct(BgpEngineClient $engineClient)
    {
        $this->engineClient = $engineClient;
    }

    public function status(): JsonResponse
    {
        return response()->json($this->engineClient->getStatus());
    }

    public function events(Request $request): JsonResponse
    {
        $limit = (int) $request->query('limit', 50);
        $threatsOnly = filter_var($request->query('threats_only', false), FILTER_VALIDATE_BOOLEAN);
        return response()->json($this->engineClient->getEvents($limit, $threatsOnly));
    }

    public function topology(): JsonResponse
    {
        return response()->json($this->engineClient->getTopology());
    }

    public function netflow(): JsonResponse
    {
        return response()->json($this->engineClient->getNetFlow());
    }

    public function simulate(Request $request, string $scenario): JsonResponse
    {
        return response()->json($this->engineClient->triggerSimulation($scenario));
    }
}
