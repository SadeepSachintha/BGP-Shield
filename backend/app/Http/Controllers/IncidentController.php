<?php

namespace App\Http\Controllers;

use App\Models\Incident;
use App\Services\WebhookDispatcher;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class IncidentController extends Controller
{
    protected WebhookDispatcher $webhookDispatcher;

    public function __construct(WebhookDispatcher $webhookDispatcher)
    {
        $this->webhookDispatcher = $webhookDispatcher;
    }

    public function index(Request $request): JsonResponse
    {
        $limit = $request->query('limit', 20);
        $status = $request->query('status');

        $query = Incident::with('mitigationActions')->orderBy('detected_at', 'desc');

        if ($status) {
            $query->where('status', $status);
        }

        return response()->json($query->limit($limit)->get());
    }

    public function show(string $id): JsonResponse
    {
        $incident = Incident::with('mitigationActions')->findOrFail($id);
        return response()->json($incident);
    }

    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'id' => 'required|string|unique:incidents,id',
            'incident_type' => 'required|string',
            'severity' => 'required|string',
            'target_prefix' => 'required|string',
            'victim_asn' => 'nullable|integer',
            'victim_name' => 'nullable|string',
            'attacker_asn' => 'nullable|integer',
            'attacker_name' => 'nullable|string',
            'status' => 'nullable|string',
            'evidence' => 'nullable|array',
        ]);

        $incident = Incident::create($validated);

        // Dispatch webhooks
        $dispatchResult = $this->webhookDispatcher->dispatchIncident($incident);

        return response()->json([
            'incident' => $incident,
            'webhooks' => $dispatchResult,
        ], 201);
    }

    public function updateStatus(Request $request, string $id): JsonResponse
    {
        $incident = Incident::findOrFail($id);
        $status = $request->input('status');

        if (!in_array($status, ['DETECTED', 'INVESTIGATING', 'MITIGATED', 'RESOLVED'])) {
            return response()->json(['error' => 'Invalid status'], 422);
        }

        $incident->status = $status;
        if (in_array($status, ['MITIGATED', 'RESOLVED'])) {
            $incident->mitigated_at = now();
        }
        $incident->save();

        return response()->json($incident);
    }
}
