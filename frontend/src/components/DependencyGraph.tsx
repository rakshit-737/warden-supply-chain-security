import { useEffect, useRef, useState, useMemo, useCallback } from "react";
import type { GraphAnalysis, GraphNode } from "../api/types";
import { palette } from "../theme/palette";
import { formatPercent } from "../lib/format";

interface Particle {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  node: GraphNode;
  isDragging?: boolean;
}

interface Link {
  source: Particle;
  target: Particle;
  type: string;
}

interface DependencyGraphProps {
  data: GraphAnalysis;
  onSelectNode?: (node: GraphNode | null) => void;
  height?: number;
}

function getNodeColor(node: GraphNode): string {
  if (node.type === "project") return "#38BDF8"; // Vibrant sky blue
  if (node.type === "vulnerability") return palette.severity.critical;
  if (node.decision === "block") return palette.decision.block;
  if (node.decision === "warn") return palette.decision.warn;

  if (node.risk !== null) {
    if (node.risk >= 80) return palette.severity.critical;
    if (node.risk >= 60) return palette.severity.high;
    if (node.risk >= 30) return palette.severity.medium;
    if (node.risk > 0) return palette.severity.low;
    return palette.decision.allow;
  }
  return palette.severity.info;
}

function getNodeRadius(node: GraphNode): number {
  if (node.type === "project") return 22;
  if (node.type === "vulnerability") return 14;
  const blast = node.blast_radius ?? 0;
  // Radius scales between 8 and 22 based on blast radius
  return Math.max(8, Math.min(22, 9 + blast * 20));
}

export function DependencyGraph({ data, onSelectNode, height = 520 }: DependencyGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hoveredNode, setHoveredNode] = useState<{ node: GraphNode; x: number; y: number } | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [showLabels, setShowLabels] = useState(true);
  const [filterSinglePoints, setFilterSinglePoints] = useState(false);

  // Transform state for Pan & Zoom
  const transformRef = useRef({ x: 0, y: 0, scale: 1.0 });
  const isPanningRef = useRef(false);
  const panStartRef = useRef({ x: 0, y: 0 });
  const draggedParticleRef = useRef<Particle | null>(null);

  // Graph particles & links
  const particlesRef = useRef<Particle[]>([]);
  const linksRef = useRef<Link[]>([]);
  const animFrameRef = useRef<number | null>(null);
  const alphaRef = useRef(1.0);

  // Build connected paths for highlighting
  const connectedNodeIds = useMemo(() => {
    if (!selectedId) return null;
    const connected = new Set<string>([selectedId]);

    // Upstream (dependents)
    const queue = [selectedId];
    while (queue.length > 0) {
      const curr = queue.shift()!;
      for (const e of data.edges) {
        if (e.target === curr && !connected.has(e.source)) {
          connected.add(e.source);
          queue.push(e.source);
        }
      }
    }
    // Downstream (dependencies)
    const downQueue = [selectedId];
    while (downQueue.length > 0) {
      const curr = downQueue.shift()!;
      for (const e of data.edges) {
        if (e.source === curr && !connected.has(e.target)) {
          connected.add(e.target);
          downQueue.push(e.target);
        }
      }
    }
    return connected;
  }, [selectedId, data.edges]);

  // Initialize simulation nodes
  useEffect(() => {
    const width = containerRef.current?.clientWidth || 800;
    const h = height;

    const nodeMap = new Map<string, Particle>();
    const particles: Particle[] = [];

    data.nodes.forEach((node, i) => {
      // Circular / radial starting layout
      const angle = (i / data.nodes.length) * 2 * Math.PI;
      const dist = node.type === "project" ? 0 : 80 + (node.depth ?? 1) * 65;
      const x = width / 2 + Math.cos(angle) * dist + (Math.random() - 0.5) * 40;
      const y = h / 2 + Math.sin(angle) * dist + (Math.random() - 0.5) * 40;

      const p: Particle = {
        id: node.id,
        x,
        y,
        vx: 0,
        vy: 0,
        radius: getNodeRadius(node),
        node,
      };
      nodeMap.set(node.id, p);
      particles.push(p);
    });

    const links: Link[] = [];
    for (const edge of data.edges) {
      const src = nodeMap.get(edge.source);
      const tgt = nodeMap.get(edge.target);
      if (src && tgt) {
        links.push({ source: src, target: tgt, type: edge.type });
      }
    }

    particlesRef.current = particles;
    linksRef.current = links;
    alphaRef.current = 1.0;
  }, [data, height]);

  // Main force-directed step & render loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let isRunning = true;

    const stepSimulation = () => {
      const particles = particlesRef.current;
      const links = linksRef.current;
      const alpha = alphaRef.current;

      if (alpha > 0.005) {
        const width = canvas.width / (window.devicePixelRatio || 1);
        const h = canvas.height / (window.devicePixelRatio || 1);
        const cx = width / 2;
        const cy = h / 2;

        // 1. Repulsion between particles (Coulomb)
        for (let i = 0; i < particles.length; i++) {
          const p1 = particles[i];
          if (!p1) continue;
          for (let j = i + 1; j < particles.length; j++) {
            const p2 = particles[j];
            if (!p2) continue;
            const dx = p2.x - p1.x;
            const dy = p2.y - p1.y;
            const distSq = dx * dx + dy * dy || 1;
            const dist = Math.sqrt(distSq);
            if (dist < 320) {
              const force = (350 * alpha) / distSq;
              const fx = (dx / dist) * force;
              const fy = (dy / dist) * force;
              if (!p1.isDragging) {
                p1.vx -= fx;
                p1.vy -= fy;
              }
              if (!p2.isDragging) {
                p2.vx += fx;
                p2.vy += fy;
              }
            }
          }

          // 2. Center gravity
          if (!p1.isDragging) {
            p1.vx += (cx - p1.x) * 0.0018 * alpha;
            p1.vy += (cy - p1.y) * 0.0018 * alpha;
          }
        }

        // 3. Link spring attraction
        for (const link of links) {
          const dx = link.target.x - link.source.x;
          const dy = link.target.y - link.source.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const idealDist = 65;
          const force = (dist - idealDist) * 0.035 * alpha;
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;

          if (!link.source.isDragging) {
            link.source.vx += fx;
            link.source.vy += fy;
          }
          if (!link.target.isDragging) {
            link.target.vx -= fx;
            link.target.vy -= fy;
          }
        }

        // 4. Integrate velocities & damp
        for (const p of particles) {
          if (!p.isDragging) {
            p.x += p.vx;
            p.y += p.vy;
            p.vx *= 0.82;
            p.vy *= 0.82;
          }
        }

        alphaRef.current *= 0.985;
      }

      // --- Draw Scene ---
      ctx.save();
      const dpr = window.devicePixelRatio || 1;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.scale(dpr, dpr);

      // Pan & Zoom
      const { x: tx, y: ty, scale } = transformRef.current;
      ctx.translate(tx, ty);
      ctx.scale(scale, scale);

      // Draw Edges
      for (const link of links) {
        const isConnected =
          !connectedNodeIds || (connectedNodeIds.has(link.source.id) && connectedNodeIds.has(link.target.id));
        const alphaEdge = connectedNodeIds ? (isConnected ? 0.85 : 0.08) : 0.35;

        ctx.beginPath();
        ctx.moveTo(link.source.x, link.source.y);
        ctx.lineTo(link.target.x, link.target.y);
        ctx.strokeStyle = isConnected && connectedNodeIds ? palette.accent : palette.line;
        ctx.globalAlpha = alphaEdge;
        ctx.lineWidth = isConnected && connectedNodeIds ? 2.0 : 1.0;
        ctx.stroke();
      }

      // Draw Nodes
      for (const p of particles) {
        const isMatched =
          !searchTerm || p.node.name.toLowerCase().includes(searchTerm.toLowerCase());
        const isSinglePointMatch = !filterSinglePoints || p.node.is_single_point;
        const isConnected = !connectedNodeIds || connectedNodeIds.has(p.id);
        const isSelected = p.id === selectedId;

        let nodeAlpha = 1.0;
        if (connectedNodeIds && !isConnected) nodeAlpha = 0.15;
        if (!isMatched || !isSinglePointMatch) nodeAlpha = 0.12;

        ctx.globalAlpha = nodeAlpha;

        // Halo / Outer ring for Single Points of Failure or Selection
        if (isSelected || p.node.is_single_point) {
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.radius + (isSelected ? 6 : 4), 0, 2 * Math.PI);
          ctx.strokeStyle = isSelected ? palette.accent : palette.decision.warn;
          ctx.lineWidth = isSelected ? 2.5 : 1.5;
          ctx.setLineDash(p.node.is_single_point && !isSelected ? [3, 3] : []);
          ctx.stroke();
          ctx.setLineDash([]);
        }

        // Draw node body
        ctx.beginPath();
        if (p.node.type === "vulnerability") {
          // Diamond
          const r = p.radius;
          ctx.moveTo(p.x, p.y - r);
          ctx.lineTo(p.x + r, p.y);
          ctx.lineTo(p.x, p.y + r);
          ctx.lineTo(p.x - r, p.y);
          ctx.closePath();
        } else {
          // Circle
          ctx.arc(p.x, p.y, p.radius, 0, 2 * Math.PI);
        }
        ctx.fillStyle = getNodeColor(p.node);
        ctx.fill();
        ctx.strokeStyle = isSelected ? "#FFFFFF" : palette.lineStrong;
        ctx.lineWidth = isSelected ? 2.0 : 1.0;
        ctx.stroke();

        // Node Label
        if (showLabels && (scale > 0.65 || isSelected || p.node.type === "project")) {
          ctx.font = `${isSelected ? "600" : "400"} ${Math.max(10, 11 / scale)}px sans-serif`;
          ctx.fillStyle = isSelected ? "#FFFFFF" : palette.inkSecondary;
          ctx.textAlign = "center";
          ctx.textBaseline = "top";
          const label = p.node.name.length > 18 ? p.node.name.slice(0, 16) + "…" : p.node.name;
          ctx.fillText(label, p.x, p.y + p.radius + 4);
        }
      }

      ctx.restore();

      if (isRunning) {
        animFrameRef.current = requestAnimationFrame(stepSimulation);
      }
    };

    animFrameRef.current = requestAnimationFrame(stepSimulation);

    return () => {
      isRunning = false;
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [data, selectedId, connectedNodeIds, searchTerm, showLabels, filterSinglePoints]);

  // Canvas size sync
  useEffect(() => {
    const handleResize = () => {
      const canvas = canvasRef.current;
      const container = containerRef.current;
      if (!canvas || !container) return;
      const dpr = window.devicePixelRatio || 1;
      const w = container.clientWidth;
      canvas.width = w * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${w}px`;
      canvas.style.height = `${height}px`;
    };
    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, [height]);

  // Coordinate transforms
  const screenToWorld = useCallback((clientX: number, clientY: number) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };
    const rect = canvas.getBoundingClientRect();
    const sx = clientX - rect.left;
    const sy = clientY - rect.top;
    const { x: tx, y: ty, scale } = transformRef.current;
    return {
      x: (sx - tx) / scale,
      y: (sy - ty) / scale,
    };
  }, []);

  const findNodeAt = useCallback(
    (clientX: number, clientY: number): Particle | null => {
      const { x, y } = screenToWorld(clientX, clientY);
      for (let i = particlesRef.current.length - 1; i >= 0; i--) {
        const p = particlesRef.current[i];
        if (!p) continue;
        const dx = p.x - x;
        const dy = p.y - y;
        if (dx * dx + dy * dy <= (p.radius + 4) * (p.radius + 4)) {
          return p;
        }
      }
      return null;
    },
    [screenToWorld]
  );

  // Mouse Handlers: Pan, Zoom, Drag, Click
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const hit = findNodeAt(e.clientX, e.clientY);
    if (hit) {
      draggedParticleRef.current = hit;
      hit.isDragging = true;
      alphaRef.current = Math.max(alphaRef.current, 0.25);
    } else {
      isPanningRef.current = true;
      panStartRef.current = { x: e.clientX - transformRef.current.x, y: e.clientY - transformRef.current.y };
    }
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (draggedParticleRef.current) {
      const { x, y } = screenToWorld(e.clientX, e.clientY);
      draggedParticleRef.current.x = x;
      draggedParticleRef.current.y = y;
      alphaRef.current = Math.max(alphaRef.current, 0.15);
      return;
    }

    if (isPanningRef.current) {
      transformRef.current.x = e.clientX - panStartRef.current.x;
      transformRef.current.y = e.clientY - panStartRef.current.y;
      return;
    }

    const hit = findNodeAt(e.clientX, e.clientY);
    if (hit) {
      setHoveredNode({ node: hit.node, x: e.clientX, y: e.clientY });
    } else {
      setHoveredNode(null);
    }
  };

  const handleMouseUp = () => {
    if (draggedParticleRef.current) {
      draggedParticleRef.current.isDragging = false;
      draggedParticleRef.current = null;
    }
    isPanningRef.current = false;
  };

  const handleClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const hit = findNodeAt(e.clientX, e.clientY);
    if (hit) {
      const nextId = hit.id === selectedId ? null : hit.id;
      setSelectedId(nextId);
      onSelectNode?.(nextId ? hit.node : null);
    } else {
      setSelectedId(null);
      onSelectNode?.(null);
    }
  };

  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const current = transformRef.current;
    const newScale = Math.min(3.5, Math.max(0.25, current.scale * zoomFactor));

    current.x = mouseX - (mouseX - current.x) * (newScale / current.scale);
    current.y = mouseY - (mouseY - current.y) * (newScale / current.scale);
    current.scale = newScale;
  };

  const resetView = () => {
    transformRef.current = { x: 0, y: 0, scale: 1.0 };
    alphaRef.current = 0.5;
    setSelectedId(null);
    onSelectNode?.(null);
  };

  const reheatSimulation = () => {
    alphaRef.current = 0.8;
  };

  return (
    <div ref={containerRef} className="relative w-full rounded-lg border border-line bg-page overflow-hidden">
      {/* Top Controls Toolbar */}
      <div className="absolute top-3 left-3 z-10 flex flex-wrap items-center gap-2 bg-panel/90 backdrop-blur-md px-3 py-1.5 rounded-md border border-line text-xs shadow-md">
        <input
          type="text"
          placeholder="Filter package..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="bg-sunken border border-line text-ink rounded px-2 py-0.5 text-xs outline-none focus:border-accent w-32 md:w-44"
        />
        <div className="h-4 w-[1px] bg-line mx-1" />
        <button
          onClick={() => setShowLabels((v) => !v)}
          className={`px-2 py-0.5 rounded border ${
            showLabels ? "bg-accent/20 border-accent text-accent" : "bg-sunken border-line text-inkMuted"
          }`}
          title="Toggle Labels"
        >
          Labels
        </button>
        <button
          onClick={() => setFilterSinglePoints((v) => !v)}
          className={`px-2 py-0.5 rounded border ${
            filterSinglePoints ? "bg-decision-warn/20 border-decision-warn text-decision-warn" : "bg-sunken border-line text-inkMuted"
          }`}
          title="Highlight Single Points of Failure"
        >
          Single Points ({data.metrics.single_points?.length || 0})
        </button>
        <div className="h-4 w-[1px] bg-line mx-1" />
        <button
          onClick={reheatSimulation}
          className="px-2 py-0.5 rounded bg-sunken border border-line text-inkSecondary hover:text-ink hover:border-lineStrong"
          title="Re-layout Simulation"
        >
          ⚡ Re-layout
        </button>
        <button
          onClick={resetView}
          className="px-2 py-0.5 rounded bg-sunken border border-line text-inkSecondary hover:text-ink hover:border-lineStrong"
          title="Reset View"
        >
          ⟲ Reset
        </button>
      </div>

      {/* Canvas */}
      <canvas
        ref={canvasRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onClick={handleClick}
        onWheel={handleWheel}
        className="w-full cursor-grab active:cursor-grabbing block"
      />

      {/* Floating Hover Tooltip */}
      {hoveredNode && (
        <div
          className="fixed pointer-events-none z-30 bg-panel/95 border border-lineStrong rounded-md p-2.5 shadow-xl text-xs max-w-xs backdrop-blur-md"
          style={{ left: hoveredNode.x + 14, top: hoveredNode.y + 14 }}
        >
          <div className="font-mono font-semibold text-ink text-sm flex items-center justify-between gap-3">
            <span>{hoveredNode.node.name}</span>
            {hoveredNode.node.version && (
              <span className="text-inkMuted text-xs">v{hoveredNode.node.version}</span>
            )}
          </div>
          <div className="mt-1.5 flex flex-col gap-1 text-[0.75rem] text-inkSecondary">
            <div className="flex justify-between">
              <span>Type:</span>
              <span className="capitalize font-medium text-ink">{hoveredNode.node.type}</span>
            </div>
            {hoveredNode.node.risk !== null && (
              <div className="flex justify-between">
                <span>Risk Score:</span>
                <span className="font-semibold" style={{ color: getNodeColor(hoveredNode.node) }}>
                  {hoveredNode.node.risk}/100
                </span>
              </div>
            )}
            {hoveredNode.node.blast_radius !== null && (
              <div className="flex justify-between">
                <span>Blast Radius:</span>
                <span className="font-medium text-ink">{formatPercent(hoveredNode.node.blast_radius)}</span>
              </div>
            )}
            <div className="flex justify-between">
              <span>Dependents:</span>
              <span className="font-medium text-ink">{hoveredNode.node.transitive_dependents}</span>
            </div>
            {hoveredNode.node.is_single_point && (
              <div className="mt-1 text-decision-warn font-medium flex items-center gap-1">
                ⚠️ Single Point of Failure (dominates {hoveredNode.node.dominated} pkgs)
              </div>
            )}
          </div>
        </div>
      )}

      {/* Bottom Legend */}
      <div className="absolute bottom-3 right-3 z-10 flex items-center gap-3 bg-panel/90 border border-line px-3 py-1.5 rounded-md text-[0.7rem] text-inkSecondary backdrop-blur-sm shadow-md">
        <div className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full bg-[#38BDF8] inline-block" />
          <span>Root</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ backgroundColor: palette.decision.allow }} />
          <span>Low Risk</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ backgroundColor: palette.severity.medium }} />
          <span>Med</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ backgroundColor: palette.severity.critical }} />
          <span>High / Block</span>
        </div>
        <div className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full border border-dashed border-decision-warn inline-block" />
          <span>Single Point</span>
        </div>
      </div>
    </div>
  );
}
