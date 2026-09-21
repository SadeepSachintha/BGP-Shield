<?php

namespace App\Http\Controllers;

use App\Models\AlertPolicy;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class AlertPolicyController extends Controller
{
    public function index(): JsonResponse
    {
        return response()->json(AlertPolicy::all());
    }

    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string',
            'monitored_prefixes' => 'nullable|array',
            'monitored_asns' => 'nullable|array',
            'severity_threshold' => 'required|in:LOW,MEDIUM,HIGH,CRITICAL',
            'webhook_url' => 'nullable|url',
            'webhook_channel' => 'required|in:SLACK,PAGERDUTY,WEBHOOK',
            'is_active' => 'boolean',
        ]);

        $policy = AlertPolicy::create($validated);
        return response()->json($policy, 201);
    }

    public function update(Request $request, int $id): JsonResponse
    {
        $policy = AlertPolicy::findOrFail($id);
        $policy->update($request->all());
        return response()->json($policy);
    }

    public function destroy(int $id): JsonResponse
    {
        $policy = AlertPolicy::findOrFail($id);
        $policy->delete();
        return response()->json(['message' => 'Policy deleted']);
    }
}
