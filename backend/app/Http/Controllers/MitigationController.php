<?php

namespace App\Http\Controllers;

use App\Models\Incident;
use App\Models\MitigationAction;
use App\Services\MitigationPlaybookService;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class MitigationController extends Controller
{
    protected MitigationPlaybookService $playbookService;

    public function __construct(MitigationPlaybookService $playbookService)
    {
        $this->playbookService = $playbookService;
    }

    public function generate(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'incident_id' => 'required|string|exists:incidents,id',
            'prefix' => 'required|string',
            'rogue_asn' => 'nullable|integer',
            'incident_type' => 'nullable|string',
        ]);

        $playbooks = $this->playbookService->generatePlaybooks(
            $validated['prefix'],
            $validated['rogue_asn'] ?? null,
            $validated['incident_type'] ?? 'SUBPREFIX_HIJACK'
        );

        // Store generated mitigation action record
        $action = MitigationAction::create([
            'incident_id' => $validated['incident_id'],
            'action_type' => 'FLOWSPEC',
            'router_target' => 'JUNIPER/CISCO/BIRD',
            'config_payload' => json_encode($playbooks),
            'status' => 'GENERATED',
        ]);

        return response()->json([
            'action' => $action,
            'playbooks' => $playbooks,
        ]);
    }

    public function apply(Request $request, int $id): JsonResponse
    {
        $action = MitigationAction::findOrFail($id);
        $action->status = 'APPLIED';
        $action->applied_at = now();
        $action->save();

        // Update parent incident status to MITIGATED
        $incident = $action->incident;
        if ($incident) {
            $incident->status = 'MITIGATED';
            $incident->mitigated_at = now();
            $incident->save();
        }

        return response()->json([
            'message' => 'Mitigation applied successfully to perimeter routers.',
            'action' => $action,
        ]);
    }
}
