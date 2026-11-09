import React, { useEffect, useRef, useState } from 'react';
import { Network } from 'vis-network';
import { DataSet } from 'vis-data';
import { GraphTopology, GraphNode, BlastRadiusResponse } from '../../types';
import { request } from '../../services/api';
import { ZoomIn, ZoomOut, Maximize2, ShieldAlert, Server, User, Globe, AlertTriangle } from 'lucide-react';
import { Badge } from '../common/Badge';

interface ThreatGraphViewProps {
  topology: GraphTopology;
  onRefresh?: () => void;
}

export const ThreatGraphView: React.FC<ThreatGraphViewProps> = ({ topology, onRefresh }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const networkRef = useRef<Network | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [blastRadius, setBlastRadius] = useState<BlastRadiusResponse | null>(null);
  const [isLoadingBlast, setIsLoadingBlast] = useState(false);

  useEffect(() => {
    if (!containerRef.current) return;

    // Map nodes to vis-network format
    const visNodes = topology.nodes.map((n) => {
      let color = { background: '#1e293b', border: '#475569' };
      let shape = 'dot';
      let size = 18;

      if (n.type === 'IP') {
        const isMalicious = n.properties?.is_external || n.label.startsWith('185.') || n.label.startsWith('45.') || n.label.startsWith('194.');
        color = isMalicious 
          ? { background: '#ef4444', border: '#b91c1c' }
          : { background: '#06b6d4', border: '#0891b2' };
        size = isMalicious ? 22 : 16;
      } else if (n.type === 'User') {
        color = { background: '#f59e0b', border: '#d97706' };
        size = 18;
      } else if (n.type === 'Server') {
        color = { background: '#8b5cf6', border: '#6d28d9' };
        shape = 'box';
        size = 24;
      } else if (n.type === 'Alert') {
        color = { background: '#f43f5e', border: '#be123c' };
        shape = 'diamond';
        size = 24;
      }

      return {
        id: n.id,
        label: n.label,
        shape,
        size,
        color,
        font: { color: '#f8fafc', size: 12, face: 'monospace' },
        borderWidth: 2,
        shadow: true,
        title: `${n.type}: ${n.label}`
      };
    });

    // Map edges
    const visEdges = topology.edges.map((e, idx) => ({
      id: `edge-${idx}`,
      from: e.source,
      to: e.target,
      label: e.type,
      font: { color: '#64748b', size: 9, align: 'middle' },
      arrows: 'to',
      color: { color: '#334155', highlight: '#06b6d4' },
      smooth: { type: 'continuous' }
    }));

    const data = {
      nodes: new DataSet(visNodes),
      edges: new DataSet(visEdges)
    };

    const options = {
      physics: {
        solver: 'forceAtlas2Based',
        forceAtlas2Based: {
          gravitationalConstant: -50,
          centralGravity: 0.01,
          springLength: 100,
          springConstant: 0.08,
          damping: 0.4
        },
        stabilization: { iterations: 150 }
      },
      interaction: {
        hover: true,
        tooltipDelay: 200,
        navigationButtons: false,
        zoomView: true
      }
    };

    const network = new Network(containerRef.current, data, options);
    networkRef.current = network;

    network.on('selectNode', async (params) => {
      const nodeId = params.nodes[0];
      const found = topology.nodes.find((n) => n.id === nodeId);
      if (found) {
        setSelectedNode(found);
        // Fetch blast radius from backend
        setIsLoadingBlast(true);
        try {
          const res = await request<BlastRadiusResponse>(`/graph/blast-radius/${encodeURIComponent(found.label)}`);
          setBlastRadius(res);
        } catch (e) {
          setBlastRadius(null);
        } finally {
          setIsLoadingBlast(false);
        }
      }
    });

    network.on('deselectNode', () => {
      setSelectedNode(null);
      setBlastRadius(null);
    });

    return () => {
      network.destroy();
    };
  }, [topology]);

  const handleZoomIn = () => {
    if (networkRef.current) {
      const scale = networkRef.current.getScale();
      networkRef.current.moveTo({ scale: scale * 1.3 });
    }
  };

  const handleZoomOut = () => {
    if (networkRef.current) {
      const scale = networkRef.current.getScale();
      networkRef.current.moveTo({ scale: scale / 1.3 });
    }
  };

  const handleFit = () => {
    if (networkRef.current) {
      networkRef.current.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
    }
  };

  return (
    <div className="relative w-full h-[680px] bg-[#0b0f19] border border-slate-800 rounded-2xl overflow-hidden flex shadow-2xl">
      {/* Interactive Graph Canvas */}
      <div className="flex-1 h-full relative">
        <div ref={containerRef} className="w-full h-full" />

        {/* Floating Controls */}
        <div className="absolute bottom-4 left-4 flex items-center gap-1.5 bg-slate-900/90 border border-slate-700/80 p-1.5 rounded-xl backdrop-blur shadow-lg z-10">
          <button
            onClick={handleZoomIn}
            className="p-2 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 transition"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-2 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 transition"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={handleFit}
            className="p-2 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 transition"
            title="Fit to Screen"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>

        {/* Legend */}
        <div className="absolute top-4 left-4 bg-slate-900/90 border border-slate-800/90 p-3 rounded-xl backdrop-blur text-xs space-y-1.5 shadow-lg z-10">
          <p className="font-semibold text-slate-300 uppercase tracking-wider text-[10px] pb-1 border-b border-slate-800">
            Graph Legend (Cypher Model)
          </p>
          <div className="flex items-center gap-2 text-slate-400">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
            <span>Malicious / Rogue IP</span>
          </div>
          <div className="flex items-center gap-2 text-slate-400">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
            <span>Internal / Trusted IP</span>
          </div>
          <div className="flex items-center gap-2 text-slate-400">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
            <span>User Account</span>
          </div>
          <div className="flex items-center gap-2 text-slate-400">
            <span className="w-2.5 h-2.5 rounded-sm bg-purple-500" />
            <span>Server Asset</span>
          </div>
          <div className="flex items-center gap-2 text-slate-400">
            <span className="w-2.5 h-2.5 rotate-45 bg-rose-500" />
            <span>Security Alert</span>
          </div>
        </div>
      </div>

      {/* Node & Blast Radius Details Drawer */}
      {selectedNode && (
        <div className="w-80 bg-slate-900/95 border-l border-slate-800 p-5 overflow-y-auto space-y-4 backdrop-blur z-20 flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <span className="text-xs font-mono uppercase text-slate-400">Entity Inspector</span>
              <Badge variant="INFO" label={selectedNode.type} size="sm" />
            </div>

            <div>
              <h4 className="text-base font-bold text-white break-all">{selectedNode.label}</h4>
              <p className="text-xs text-slate-400 font-mono mt-1">ID: {selectedNode.id}</p>
            </div>

            {/* Blast Radius Section */}
            <div className="p-3.5 bg-slate-950/80 border border-slate-800 rounded-xl space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-rose-400">
                <AlertTriangle className="w-4 h-4" />
                <span>Blast Radius Assessment</span>
              </div>
              {isLoadingBlast ? (
                <p className="text-xs text-slate-500">Traversing Neo4j Cypher hops...</p>
              ) : blastRadius ? (
                <div className="space-y-1.5 text-xs text-slate-300">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Impacted Entities:</span>
                    <span className="font-bold text-white">{blastRadius.impacted_nodes}</span>
                  </div>
                  {blastRadius.connected_servers.length > 0 && (
                    <div>
                      <span className="text-slate-500">Exposed Servers:</span>
                      <p className="font-mono text-[11px] text-cyan-300 mt-0.5">
                        {blastRadius.connected_servers.join(', ')}
                      </p>
                    </div>
                  )}
                  {blastRadius.connected_users.length > 0 && (
                    <div>
                      <span className="text-slate-500">Targeted Users:</span>
                      <p className="font-mono text-[11px] text-amber-300 mt-0.5">
                        {blastRadius.connected_users.join(', ')}
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-xs text-slate-500">No active incident links.</p>
              )}
            </div>

            {/* Raw Properties */}
            <div className="space-y-1.5">
              <p className="text-xs font-semibold text-slate-400">Graph Properties:</p>
              <pre className="text-[11px] font-mono bg-slate-950 p-3 rounded-lg border border-slate-800 text-slate-300 overflow-x-auto">
                {JSON.stringify(selectedNode.properties, null, 2)}
              </pre>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800 text-center">
            <p className="text-[11px] text-slate-500">Click canvas to deselect</p>
          </div>
        </div>
      )}
    </div>
  );
};
