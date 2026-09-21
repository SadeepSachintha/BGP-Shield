import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { ShieldAlert, ZoomIn, ZoomOut, RotateCcw, Activity, Server, Radio } from 'lucide-react';

export default function TopologyGraph({ topologyData, activeThreats = [], onSelectAsn }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const zoomBehaviorRef = useRef(null);

  useEffect(() => {
    if (!topologyData || !topologyData.nodes || topologyData.nodes.length === 0) return;

    const width = containerRef.current?.clientWidth || 800;
    const height = containerRef.current?.clientHeight || 550;

    // Clear previous SVG contents
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Defs for glowing filters and markers
    const defs = svg.append('defs');

    // Glow filter for links
    const filter = defs.append('filter')
      .attr('id', 'glow')
      .attr('x', '-50%').attr('y', '-50%')
      .attr('width', '200%').attr('height', '200%');
    filter.append('feGaussianBlur')
      .attr('stdDeviation', '4')
      .attr('result', 'coloredBlur');
    const feMerge = filter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Threat glow filter
    const threatFilter = defs.append('filter')
      .attr('id', 'threat-glow')
      .attr('x', '-50%').attr('y', '-50%')
      .attr('width', '200%').attr('height', '200%');
    threatFilter.append('feGaussianBlur')
      .attr('stdDeviation', '6')
      .attr('result', 'threatBlur');
    const threatMerge = threatFilter.append('feMerge');
    threatMerge.append('feMergeNode').attr('in', 'threatBlur');
    threatMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Arrow markers for directed links
    defs.append('marker')
      .attr('id', 'arrow-normal')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 28)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#38bdf8')
      .attr('opacity', 0.6);

    defs.append('marker')
      .attr('id', 'arrow-threat')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 30)
      .attr('refY', 0)
      .attr('markerWidth', 8)
      .attr('markerHeight', 8)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#ef4444');

    // Container group for zooming
    const g = svg.append('g').attr('class', 'main-container');

    // Setup zoom
    const zoom = d3.zoom()
      .scaleExtent([0.3, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });
    svg.call(zoom);
    zoomBehaviorRef.current = zoom;

    // Build robust node map ensuring every link endpoint exists in nodes
    const nodeMap = new Map();
    (topologyData.nodes || []).forEach(d => nodeMap.set(d.id, { ...d }));

    (topologyData.links || []).forEach(l => {
      const src = typeof l.source === 'object' ? l.source.id : l.source;
      const tgt = typeof l.target === 'object' ? l.target.id : l.target;
      if (src && !nodeMap.has(src)) {
        const asn = parseInt(String(src).replace('AS', '')) || 0;
        nodeMap.set(src, { id: src, asn, name: src, tier: 'Transit / Peer', country: 'Global' });
      }
      if (tgt && !nodeMap.has(tgt)) {
        const asn = parseInt(String(tgt).replace('AS', '')) || 0;
        nodeMap.set(tgt, { id: tgt, asn, name: tgt, tier: 'Transit / Peer', country: 'Global' });
      }
    });

    const nodes = Array.from(nodeMap.values());
    const links = (topologyData.links || []).map(d => ({ ...d }));

    // Identify rogue/threat ASNs from activeThreats
    const threatAsns = new Set(
      activeThreats.flatMap(t => [t.attacker_asn, t.origin_asn, t.leak_as]).filter(Boolean)
    );

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(110))
      .force('charge', d3.forceManyBody().strength(-350))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide().radius(45));

    // Draw Links
    const link = g.append('g')
      .attr('class', 'links')
      .selectAll('line')
      .data(links)
      .enter().append('line')
      .attr('stroke', (d) => {
        const srcAsn = typeof d.source === 'object' ? d.source.asn : parseInt(d.source.replace('AS', ''));
        const tgtAsn = typeof d.target === 'object' ? d.target.asn : parseInt(d.target.replace('AS', ''));
        if (threatAsns.has(srcAsn) || threatAsns.has(tgtAsn)) {
          return '#ef4444';
        }
        return d.type === 'P2P' ? '#06b6d4' : '#38bdf8';
      })
      .attr('stroke-width', (d) => {
        const srcAsn = typeof d.source === 'object' ? d.source.asn : parseInt(d.source.replace('AS', ''));
        const tgtAsn = typeof d.target === 'object' ? d.target.asn : parseInt(d.target.replace('AS', ''));
        return (threatAsns.has(srcAsn) || threatAsns.has(tgtAsn)) ? 3 : 1.5;
      })
      .attr('stroke-dasharray', d => d.type === 'P2P' ? '4,4' : null)
      .attr('stroke-opacity', 0.6)
      .attr('marker-end', (d) => {
        const srcAsn = typeof d.source === 'object' ? d.source.asn : parseInt(d.source.replace('AS', ''));
        const tgtAsn = typeof d.target === 'object' ? d.target.asn : parseInt(d.target.replace('AS', ''));
        return (threatAsns.has(srcAsn) || threatAsns.has(tgtAsn)) ? 'url(#arrow-threat)' : 'url(#arrow-normal)';
      })
      .attr('filter', (d) => {
        const srcAsn = typeof d.source === 'object' ? d.source.asn : parseInt(d.source.replace('AS', ''));
        const tgtAsn = typeof d.target === 'object' ? d.target.asn : parseInt(d.target.replace('AS', ''));
        return (threatAsns.has(srcAsn) || threatAsns.has(tgtAsn)) ? 'url(#threat-glow)' : 'url(#glow)';
      });

    // Draw Nodes
    const node = g.append('g')
      .attr('class', 'nodes')
      .selectAll('g')
      .data(nodes)
      .enter().append('g')
      .attr('class', 'node-group')
      .style('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on('drag', (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        })
      )
      .on('click', (event, d) => {
        setSelectedNode(d);
        if (onSelectAsn) onSelectAsn(d);
      });

    // Radar pulse ring for threat nodes
    node.each(function(d) {
      if (threatAsns.has(d.asn)) {
        d3.select(this).append('circle')
          .attr('r', 32)
          .attr('fill', 'none')
          .attr('stroke', '#ef4444')
          .attr('stroke-width', 2)
          .attr('opacity', 0.8)
          .attr('class', 'animate-pulse-glow');
      }
    });

    // Main node circle
    node.append('circle')
      .attr('r', (d) => {
        if (threatAsns.has(d.asn)) return 24;
        if (d.tier?.includes('Tier-1')) return 22;
        return 17;
      })
      .attr('fill', (d) => {
        if (threatAsns.has(d.asn)) return '#7f1d1d';
        if (d.tier?.includes('Tier-1')) return '#0f172a';
        if (d.tier?.includes('Peer')) return '#064e3b';
        return '#1e1b4b';
      })
      .attr('stroke', (d) => {
        if (threatAsns.has(d.asn)) return '#ef4444';
        if (d.tier?.includes('Tier-1')) return '#06b6d4';
        if (d.tier?.includes('Peer')) return '#10b981';
        return '#818cf8';
      })
      .attr('stroke-width', (d) => threatAsns.has(d.asn) ? 3 : 2)
      .attr('filter', (d) => threatAsns.has(d.asn) ? 'url(#threat-glow)' : 'url(#glow)');

    // Node icon / symbol
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '0.35em')
      .attr('fill', '#f8fafc')
      .attr('font-size', '10px')
      .attr('font-weight', 'bold')
      .attr('font-family', 'JetBrains Mono')
      .text(d => d.id);

    // Node Label (Org name)
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '2.8em')
      .attr('fill', '#94a3b8')
      .attr('font-size', '10px')
      .attr('font-weight', '500')
      .attr('font-family', 'Inter')
      .text(d => {
        const shortName = d.name?.length > 18 ? d.name.substring(0, 16) + '…' : d.name;
        return shortName || `AS${d.asn}`;
      });

    // Simulation tick
    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    return () => {
      simulation.stop();
    };
  }, [topologyData, activeThreats]);

  const handleZoom = (scaleFactor) => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(300)
      .call(zoomBehaviorRef.current.scaleBy, scaleFactor);
  };

  const handleReset = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(400)
      .call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
    setSelectedNode(null);
  };

  return (
    <div ref={containerRef} className="relative w-full h-full min-h-[500px] glass-panel cyber-grid overflow-hidden border border-cyan-500/20">
      {/* HUD Header Overlay */}
      <div className="absolute top-4 left-4 z-10 flex items-center gap-3">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-cyan-500/40 backdrop-blur-md">
          <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
          <span className="text-xs font-mono text-cyan-300 font-semibold uppercase tracking-wider">
            AS-Path Mesh Topology
          </span>
        </div>
        {activeThreats.length > 0 && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-950/80 border border-red-500/50 backdrop-blur-md animate-pulse">
            <ShieldAlert className="w-4 h-4 text-red-400" />
            <span className="text-xs font-mono text-red-300 font-bold uppercase tracking-wider">
              {activeThreats.length} Active Routing Threat{activeThreats.length > 1 ? 's' : ''}
            </span>
          </div>
        )}
      </div>

      {/* D3 SVG Canvas */}
      <svg ref={svgRef} className="w-full h-full cursor-grab active:cursor-grabbing"></svg>

      {/* Control Tools */}
      <div className="absolute bottom-4 right-4 z-10 flex flex-col gap-2">
        <button
          onClick={() => handleZoom(1.3)}
          title="Zoom In"
          className="p-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-cyan-500/30 text-cyan-400 hover:text-cyan-200 transition-colors shadow-lg"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={() => handleZoom(0.7)}
          title="Zoom Out"
          className="p-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-cyan-500/30 text-cyan-400 hover:text-cyan-200 transition-colors shadow-lg"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          onClick={handleReset}
          title="Reset View"
          className="p-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-cyan-500/30 text-cyan-400 hover:text-cyan-200 transition-colors shadow-lg"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
      </div>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="absolute top-4 right-4 z-10 w-72 p-4 rounded-xl bg-slate-900/95 border border-cyan-500/40 backdrop-blur-lg shadow-2xl transition-all">
          <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-700">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <span className="font-mono text-sm font-bold text-white">AS{selectedNode.asn}</span>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-xs text-slate-400 hover:text-white px-1.5 py-0.5 rounded bg-slate-800"
            >
              ✕
            </button>
          </div>
          <div className="space-y-2 text-xs">
            <div>
              <span className="text-slate-400">Organization:</span>
              <p className="font-semibold text-slate-200">{selectedNode.name}</p>
            </div>
            <div>
              <span className="text-slate-400">Hierarchy Tier:</span>
              <p className="font-mono text-cyan-300">{selectedNode.tier || 'Transit / Stub'}</p>
            </div>
            <div>
              <span className="text-slate-400">Region:</span>
              <p className="text-slate-300">{selectedNode.country || 'Global'}</p>
            </div>
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="absolute bottom-4 left-4 z-10 flex items-center gap-4 px-3 py-2 rounded-lg bg-slate-900/90 border border-slate-700/60 backdrop-blur-md text-[11px] font-mono text-slate-300">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_#06b6d4]"></span>
          <span>Tier-1 Transit</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#10b981]"></span>
          <span>Content / Peer</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_8px_#ef4444] animate-pulse"></span>
          <span>Rogue / Threat Origin</span>
        </div>
      </div>
    </div>
  );
}
