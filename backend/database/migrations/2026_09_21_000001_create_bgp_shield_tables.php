<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('incidents', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->string('incident_type');
            $table->string('severity')->default('HIGH');
            $table->string('target_prefix');
            $table->unsignedBigInteger('victim_asn')->nullable();
            $table->string('victim_name')->nullable();
            $table->unsignedBigInteger('attacker_asn')->nullable();
            $table->string('attacker_name')->nullable();
            $table->string('status')->default('DETECTED'); // DETECTED, INVESTIGATING, MITIGATED, RESOLVED
            $table->timestamp('detected_at')->useCurrent();
            $table->timestamp('mitigated_at')->nullable();
            $table->json('evidence')->nullable();
            $table->timestamps();
        });

        Schema::create('alert_policies', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->json('monitored_prefixes')->nullable();
            $table->json('monitored_asns')->nullable();
            $table->string('severity_threshold')->default('HIGH');
            $table->string('webhook_url')->nullable();
            $table->string('webhook_channel')->default('SLACK'); // SLACK, PAGERDUTY, WEBHOOK
            $table->boolean('is_active')->default(true);
            $table->timestamps();
        });

        Schema::create('mitigation_actions', function (Blueprint $table) {
            $table->id();
            $table->string('incident_id');
            $table->string('action_type'); // FLOWSPEC, RTBH, AS_FILTER, ROA
            $table->string('router_target'); // CISCO, JUNIPER, BIRD, FRR
            $table->text('config_payload');
            $table->string('status')->default('GENERATED'); // GENERATED, APPLIED, FAILED
            $table->timestamp('applied_at')->nullable();
            $table->timestamps();

            $table->foreign('incident_id')->references('id')->on('incidents')->onDelete('cascade');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('mitigation_actions');
        Schema::dropIfExists('alert_policies');
        Schema::dropIfExists('incidents');
    }
};
