import React, { useState, useEffect, useRef } from 'react';
import { Play, Pause, RotateCcw, ChevronLeft, ChevronRight, Clock, ShieldAlert, ShieldCheck, Activity, Zap } from 'lucide-react';

export default function TimeTravelScrubber({ snapshots, onStepChange }) {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1); // 1x, 2x, 5x
  const timerRef = useRef(null);

  const steps = snapshots?.steps || [];
  const currentStep = steps[currentStepIndex] || {};

  // Auto-advance when playing
  useEffect(() => {
    if (isPlaying) {
      const intervalMs = 2500 / playbackSpeed;
      timerRef.current = setInterval(() => {
        setCurrentStepIndex((prev) => {
          if (prev >= steps.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          const next = prev + 1;
          if (onStepChange && steps[next]) {
            onStepChange(steps[next]);
          }
          return next;
        });
      }, intervalMs);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, playbackSpeed, steps, onStepChange]);

  const handleStepSelect = (idx) => {
    setCurrentStepIndex(idx);
    if (onStepChange && steps[idx]) {
      onStepChange(steps[idx]);
    }
  };

  const handlePlayPause = () => {
    if (currentStepIndex >= steps.length - 1 && !isPlaying) {
      setCurrentStepIndex(0);
      if (onStepChange && steps[0]) onStepChange(steps[0]);
    }
    setIsPlaying(!isPlaying);
  };

  const handleReset = () => {
    setIsPlaying(false);
    handleStepSelect(0);
  };

  const handleStepBack = () => {
    if (currentStepIndex > 0) {
      handleStepSelect(currentStepIndex - 1);
    }
  };

  const handleStepForward = () => {
    if (currentStepIndex < steps.length - 1) {
      handleStepSelect(currentStepIndex + 1);
    }
  };

  if (!steps.length) return null;

  return (
    <div className="glass-panel p-4 border border-cyan-500/30 bg-slate-900/90 shadow-2xl backdrop-blur-xl">
      {/* Top Details Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-2.5 py-1 rounded-md bg-slate-800/80 border border-slate-700">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-xs font-mono font-bold text-white">
              {currentStep.time_offset || 'T+0s'}
            </span>
          </div>

          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-xs font-bold font-mono text-white">
                Step {currentStepIndex + 1}/{steps.length}: {currentStep.title}
              </h4>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                currentStep.alert_level === 'CRITICAL'
                  ? 'bg-red-500/20 text-red-300 border border-red-500/40 animate-pulse'
                  : currentStep.alert_level === 'WARNING'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                  : currentStep.alert_level === 'RESOLVED'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
              }`}>
                {currentStep.alert_level}
              </span>
            </div>
            <p className="text-[11px] text-slate-300 mt-0.5">
              {currentStep.description}
            </p>
          </div>
        </div>

        {/* Telemetry Metrics in Snapshot */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-950 border border-slate-800">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">Flow Bandwidth:</span>
            <span className={`font-bold ${currentStep.traffic_volume_gbps < 0.5 ? 'text-red-400 animate-pulse' : 'text-emerald-300'}`}>
              {currentStep.traffic_volume_gbps} Gbps
            </span>
          </div>

          <div className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-950 border border-slate-800">
            <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-slate-400">RPKI:</span>
            <span className={`font-bold ${currentStep.rpki_state === 'VALID' ? 'text-emerald-400' : 'text-red-400'}`}>
              {currentStep.rpki_state}
            </span>
          </div>
        </div>
      </div>

      {/* Scrubber Progress Slider */}
      <div className="relative mb-4">
        {/* Step markers */}
        <div className="flex justify-between mb-1.5 px-1">
          {steps.map((s, idx) => (
            <button
              key={idx}
              onClick={() => handleStepSelect(idx)}
              className={`text-[10px] font-mono transition-colors ${
                idx === currentStepIndex
                  ? 'text-cyan-300 font-bold'
                  : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {s.time_offset}
            </button>
          ))}
        </div>

        {/* Range Slider */}
        <input
          type="range"
          min="0"
          max={steps.length - 1}
          value={currentStepIndex}
          onChange={(e) => handleStepSelect(parseInt(e.target.value))}
          className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400 focus:outline-none"
        />
      </div>

      {/* Transport Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <button
            onClick={handlePlayPause}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-mono font-bold shadow-lg shadow-cyan-500/20 transition-all"
          >
            {isPlaying ? (
              <>
                <Pause className="w-3.5 h-3.5 fill-current" /> Pause
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" /> Play Incident
              </>
            )}
          </button>

          <button
            onClick={handleStepBack}
            disabled={currentStepIndex === 0}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 transition-colors"
            title="Step Back"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>

          <button
            onClick={handleStepForward}
            disabled={currentStepIndex === steps.length - 1}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 transition-colors"
            title="Step Forward"
          >
            <ChevronRight className="w-4 h-4" />
          </button>

          <button
            onClick={handleReset}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
            title="Reset Timeline"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>

        {/* Speed Multiplier */}
        <div className="flex items-center gap-1.5 bg-slate-950 px-2 py-1 rounded-lg border border-slate-800 text-xs font-mono">
          <span className="text-slate-500 text-[10px]">Speed:</span>
          {[1, 2, 5].map((speed) => (
            <button
              key={speed}
              onClick={() => setPlaybackSpeed(speed)}
              className={`px-2 py-0.5 rounded text-[10px] font-bold transition-colors ${
                playbackSpeed === speed
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {speed}x
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
