import {
  X,
  ChevronDown,
  ChevronRight,
  Shield,
  AlertTriangle,
  Globe,
  Server,
  Layers,
  Copy,
  Check,
  Maximize2,
  Minimize2,
} from "lucide-react";
import { useState, useCallback, useEffect } from "react";

interface PacketDetailProps {
  packet: any;
  onClose: () => void;
}

type Tab = "overview" | "protocol" | "tree" | "hex";

export default function PacketDetail({ packet, onClose }: PacketDetailProps) {
  const [tab, setTab] = useState<Tab>("overview");
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(["header", "decoded", "errors", "identity", "session", "network", "qos"])
  );
  const [fullscreen, setFullscreen] = useState(false);

  const metadata = parseJSON(packet.metadata_json, {});
  const errors = parseJSONArray(packet.errors_json);
  const proto = packet.app_protocol || packet.protocol;

  const toggleSection = (section: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  };

  const { identityFields, sessionFields, networkFields, qosFields, otherFields } =
    categorizeMetadata(metadata, proto);

  const complexFields = Object.entries(metadata).filter(
    ([, v]) => Array.isArray(v) || (typeof v === "object" && v !== null)
  );

  const containerClass = fullscreen
    ? "fixed inset-0 z-50 bg-slate-900 flex flex-col"
    : "bg-slate-800 border border-slate-700/50 rounded-xl overflow-hidden flex flex-col";

  return (
    <div className={containerClass}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700/50 bg-slate-800/90 flex-shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <h3 className="text-sm font-bold text-white whitespace-nowrap">
            Packet #{packet.frame_number}
          </h3>
          <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium flex-shrink-0 ${protocolBadge(proto)}`}>
            {proto}
          </span>
          <span className="text-xs text-slate-500 font-mono truncate">{formatTimestamp(packet.timestamp)}</span>
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">
          <button
            onClick={() => setFullscreen((v) => !v)}
            title={fullscreen ? "Exit fullscreen" : "Fullscreen"}
            className="text-slate-400 hover:text-white transition-colors p-1.5 rounded hover:bg-slate-700"
          >
            {fullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors p-1.5 rounded hover:bg-slate-700"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-700/50 flex-shrink-0 bg-slate-800">
        {(["overview", "protocol", "tree", "hex"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-xs font-medium uppercase tracking-wider transition-colors ${
              tab === t
                ? "text-emerald-400 border-b-2 border-emerald-400"
                : "text-slate-500 hover:text-slate-300"
            }`}
          >
            {t === "overview" ? "Overview" : t === "protocol" ? "Decoded" : t === "tree" ? "Tree" : "Hex"}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="overflow-y-auto flex-1">
        {tab === "overview" && (
          <OverviewTab
            packet={packet}
            proto={proto}
            errors={errors}
            expandedSections={expandedSections}
            toggleSection={toggleSection}
          />
        )}
        {tab === "protocol" && (
          <ProtocolTab
            identityFields={identityFields}
            sessionFields={sessionFields}
            networkFields={networkFields}
            qosFields={qosFields}
            otherFields={otherFields}
            complexFields={complexFields}
            expandedSections={expandedSections}
            toggleSection={toggleSection}
          />
        )}
        {tab === "tree" && <TreeTab packet={packet} metadata={metadata} proto={proto} />}
        {tab === "hex" && <HexTab packetId={packet.id} packetLength={packet.length} />}
      </div>
    </div>
  );
}

/* ============ Tab: Overview ============ */

function OverviewTab({
  packet,
  proto,
  errors,
  expandedSections,
  toggleSection,
}: {
  packet: any;
  proto: string;
  errors: any[];
  expandedSections: Set<string>;
  toggleSection: (s: string) => void;
}) {
  return (
    <>
      <Section
        title="Packet Header"
        icon={<Layers className="w-3.5 h-3.5" />}
        expanded={expandedSections.has("header")}
        onToggle={() => toggleSection("header")}
      >
        <div className="space-y-1.5">
          <FieldRow label="Source" value={`${packet.src_ip}:${packet.src_port}`} mono copyable />
          <FieldRow label="Destination" value={`${packet.dst_ip}:${packet.dst_port}`} mono copyable />
          <FieldRow label="Transport" value={packet.protocol} />
          <FieldRow label="App Protocol" value={proto} highlight />
          <FieldRow label="Length" value={`${packet.length} bytes`} />
          <FieldRow label="Frame #" value={`${packet.frame_number}`} />
          {packet.job_id && <FieldRow label="Job ID" value={`${packet.job_id}`} />}
          {packet.session_id && <FieldRow label="Session" value={packet.session_id} mono copyable />}
        </div>
        {packet.summary && (
          <div className="mt-2 pt-2 border-t border-slate-700/30">
            <span className="text-xs text-slate-500 uppercase tracking-wider">Summary</span>
            <p className="text-sm text-white mt-1 break-all font-mono leading-relaxed">{packet.summary}</p>
          </div>
        )}
      </Section>

      {errors.length > 0 && (
        <Section
          title={`Errors & Alerts (${errors.length})`}
          icon={<AlertTriangle className="w-3.5 h-3.5 text-orange-400" />}
          expanded={expandedSections.has("errors")}
          onToggle={() => toggleSection("errors")}
          headerClass="text-orange-400"
        >
          <div className="space-y-2">
            {errors.map((err: any, i: number) => (
              <div key={i} className="bg-orange-500/10 border border-orange-500/20 rounded-lg p-2.5">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={err.severity} />
                  <span className="text-xs font-mono text-slate-500">{err.code}</span>
                </div>
                <p className="text-sm text-white font-medium">{err.title}</p>
                <p className="text-xs text-slate-400 mt-0.5">{err.description}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {errors.length === 0 && (
        <div className="px-4 py-3 border-b border-slate-700/30">
          <span className="inline-flex items-center gap-1.5 text-xs text-emerald-500">
            <Check className="w-3 h-3" /> No errors detected
          </span>
        </div>
      )}
    </>
  );
}

/* ============ Tab: Protocol / Decoded ============ */

function ProtocolTab({
  identityFields,
  sessionFields,
  networkFields,
  qosFields,
  otherFields,
  complexFields,
  expandedSections,
  toggleSection,
}: {
  identityFields: [string, any][];
  sessionFields: [string, any][];
  networkFields: [string, any][];
  qosFields: [string, any][];
  otherFields: [string, any][];
  complexFields: [string, any][];
  expandedSections: Set<string>;
  toggleSection: (s: string) => void;
}) {
  const allEmpty =
    identityFields.length === 0 &&
    sessionFields.length === 0 &&
    networkFields.length === 0 &&
    qosFields.length === 0 &&
    otherFields.length === 0 &&
    complexFields.length === 0;

  if (allEmpty) {
    return (
      <div className="p-8 text-center text-slate-500 text-xs">
        No decoded protocol data available for this packet.
      </div>
    );
  }

  return (
    <>
      {identityFields.length > 0 && (
        <Section
          title="Subscriber / Identity"
          icon={<Shield className="w-3.5 h-3.5 text-blue-400" />}
          expanded={expandedSections.has("identity")}
          onToggle={() => toggleSection("identity")}
        >
          <FieldGrid fields={identityFields} />
        </Section>
      )}

      {sessionFields.length > 0 && (
        <Section
          title="Session Details"
          icon={<Globe className="w-3.5 h-3.5 text-emerald-400" />}
          expanded={expandedSections.has("session")}
          onToggle={() => toggleSection("session")}
        >
          <FieldGrid fields={sessionFields} />
        </Section>
      )}

      {networkFields.length > 0 && (
        <Section
          title="Network / Tunnel"
          icon={<Server className="w-3.5 h-3.5 text-purple-400" />}
          expanded={expandedSections.has("network")}
          onToggle={() => toggleSection("network")}
        >
          <FieldGrid fields={networkFields} />
        </Section>
      )}

      {qosFields.length > 0 && (
        <Section
          title="QoS / Performance"
          icon={<Layers className="w-3.5 h-3.5 text-yellow-400" />}
          expanded={expandedSections.has("qos")}
          onToggle={() => toggleSection("qos")}
        >
          <FieldGrid fields={qosFields} />
        </Section>
      )}

      {otherFields.length > 0 && (
        <Section
          title="Other Decoded Fields"
          expanded={expandedSections.has("decoded")}
          onToggle={() => toggleSection("decoded")}
        >
          <FieldGrid fields={otherFields} />
        </Section>
      )}

      {complexFields.map(([key, value]) => (
        <Section
          key={key}
          title={formatLabel(key)}
          expanded={expandedSections.has(key)}
          onToggle={() => toggleSection(key)}
        >
          <NestedDisplay data={value} />
        </Section>
      ))}
    </>
  );
}

/* ============ Tab: Hex Dump (Wireshark-style) ============ */

interface HexRow {
  offset: string;
  hex: string;
  ascii: string;
}

interface HexData {
  total_bytes: number;
  has_raw: boolean;
  rows: HexRow[];
}

function HexTab({ packetId }: { packetId: number; packetLength: number }) {
  const [hexData, setHexData] = useState<HexData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hoveredOffset, setHoveredOffset] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetch(`/api/v1/packets/${packetId}/hex`)
      .then((r) => r.json())
      .then((d) => { setHexData(d); setLoading(false); })
      .catch((e) => { setError(e.message); setLoading(false); });
  }, [packetId]);

  const copyHex = useCallback(() => {
    if (!hexData) return;
    const text = hexData.rows
      .map((r) => `${r.offset}  ${r.hex}  ${r.ascii}`)
      .join("\n");
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, [hexData]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-32 text-slate-500 text-xs">
        Loading hex dump…
      </div>
    );
  }
  if (error) {
    return (
      <div className="p-4 text-xs text-red-400">Failed to load hex data: {error}</div>
    );
  }
  if (!hexData || !hexData.rows || hexData.rows.length === 0) {
    return (
      <div className="p-8 text-center text-slate-500 text-xs">
        No raw packet bytes available for this packet.
        <p className="mt-1 text-slate-600">Raw bytes are captured for packets processed after the hex-dump upgrade.</p>
      </div>
    );
  }

  return (
    <div className="p-3 space-y-2">
      {/* Header bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3 text-xs text-slate-500">
          <span className="font-mono">{hexData.total_bytes} bytes</span>
          {!hexData.has_raw && (
            <span className="text-amber-500/80 text-[10px]">
              ⚠ showing summary bytes (raw not captured)
            </span>
          )}
        </div>
        <button
          onClick={copyHex}
          className="flex items-center gap-1 text-xs text-slate-400 hover:text-white transition-colors px-2 py-1 rounded hover:bg-slate-700"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>

      {/* Column headers */}
      <div className="font-mono text-[10px] text-slate-600 flex gap-0 border-b border-slate-700/30 pb-1 select-none">
        <span className="w-12">Offset</span>
        <span className="flex-1">
          {"00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f"}
        </span>
        <span className="ml-4 w-16">ASCII</span>
      </div>

      {/* Hex rows */}
      <div className="font-mono text-xs leading-5 overflow-x-auto">
        {hexData.rows.map((row, i) => (
          <div
            key={i}
            className={`flex gap-0 rounded transition-colors cursor-default ${
              hoveredOffset === i ? "bg-slate-700/50" : "hover:bg-slate-700/20"
            }`}
            onMouseEnter={() => setHoveredOffset(i)}
            onMouseLeave={() => setHoveredOffset(null)}
          >
            {/* Offset */}
            <span className="w-12 text-slate-600 flex-shrink-0 select-none">
              {row.offset}
            </span>
            {/* Hex bytes */}
            <span className="flex-1 text-cyan-300 tracking-wide whitespace-pre">
              {row.hex}
            </span>
            {/* ASCII */}
            <span className="ml-4 w-16 text-emerald-400/80 break-all whitespace-pre flex-shrink-0">
              {row.ascii}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ============ Sub-components ============ */

function Section({
  title,
  icon,
  expanded,
  onToggle,
  children,
  headerClass,
}: {
  title: string;
  icon?: React.ReactNode;
  expanded: boolean;
  onToggle: () => void;
  children: React.ReactNode;
  headerClass?: string;
}) {
  return (
    <div className="border-b border-slate-700/30">
      <button
        onClick={onToggle}
        className={`w-full flex items-center gap-2 px-4 py-2.5 text-xs font-medium uppercase tracking-wider hover:bg-slate-700/30 transition-colors ${
          headerClass || "text-slate-400"
        }`}
      >
        {expanded ? (
          <ChevronDown className="w-3 h-3 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-3 h-3 flex-shrink-0" />
        )}
        {icon}
        {title}
      </button>
      {expanded && <div className="px-4 pb-3 pt-1">{children}</div>}
    </div>
  );
}

function FieldGrid({ fields }: { fields: [string, any][] }) {
  return (
    <div className="space-y-1.5">
      {fields.map(([key, value]) => (
        <FieldRow
          key={key}
          label={formatLabel(key)}
          value={formatValue(value)}
          mono
          copyable={typeof value === "string" && value.length > 4}
        />
      ))}
    </div>
  );
}

function FieldRow({
  label,
  value,
  mono,
  highlight,
  copyable,
}: {
  label: string;
  value: string;
  mono?: boolean;
  highlight?: boolean;
  copyable?: boolean;
}) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  };

  return (
    <div className="flex items-start gap-2 text-xs group">
      <span className="text-slate-500 w-32 flex-shrink-0 pt-0.5 leading-relaxed">{label}</span>
      <span
        className={`break-all flex-1 leading-relaxed ${
          highlight
            ? "text-emerald-400 font-medium"
            : mono
            ? "text-cyan-300 font-mono"
            : "text-slate-200"
        }`}
      >
        {value || "-"}
      </span>
      {copyable && value && value !== "-" && (
        <button
          onClick={copy}
          className="opacity-0 group-hover:opacity-100 transition-opacity text-slate-500 hover:text-slate-300 flex-shrink-0 pt-0.5"
          title="Copy"
        >
          {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
        </button>
      )}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === "critical"
      ? "bg-red-500/30 text-red-300"
      : severity === "error"
      ? "bg-red-500/20 text-red-400"
      : "bg-amber-500/20 text-amber-400";
  return (
    <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${cls}`}>{severity}</span>
  );
}

function NestedDisplay({ data }: { data: any }) {
  if (Array.isArray(data)) {
    return (
      <div className="space-y-2">
        {data.map((item, idx) => (
          <div key={idx} className="bg-slate-900/50 rounded-lg p-2.5 border border-slate-700/30">
            <div className="text-xs text-slate-500 mb-1.5 font-medium">[{idx}]</div>
            {typeof item === "object" && item !== null ? (
              <div className="space-y-1">
                {Object.entries(item).map(([k, v]) => (
                  <FieldRow key={k} label={formatLabel(k)} value={formatValue(v)} mono />
                ))}
              </div>
            ) : (
              <span className="text-xs text-slate-300 font-mono">{String(item)}</span>
            )}
          </div>
        ))}
      </div>
    );
  }

  if (typeof data === "object" && data !== null) {
    return (
      <div className="space-y-1">
        {Object.entries(data).map(([k, v]) => (
          <FieldRow key={k} label={formatLabel(k)} value={formatValue(v)} mono />
        ))}
      </div>
    );
  }

  return <span className="text-xs text-slate-300 font-mono">{String(data)}</span>;
}

/* ============ Tab: Protocol Tree (Wireshark-style) ============ */

interface TreeNode {
  label: string;
  value?: string;
  color?: string;
  children?: TreeNode[];
}

interface ServerLayer {
  name: string;
  color: string;
  fields: { name: string; value: string }[];
}

function TreeTab({ packet, metadata, proto }: { packet: any; metadata: any; proto: string }) {
  const [serverLayers, setServerLayers] = useState<ServerLayer[] | null>(null);

  useEffect(() => {
    fetch(`/api/v1/packets/${packet.id}/layers`)
      .then((r) => r.json())
      .then((d) => setServerLayers(Array.isArray(d.layers) ? d.layers : []))
      .catch(() => setServerLayers(null));
  }, [packet.id]);

  // Use server-side layer data if available, otherwise fall back to client-side tree
  if (serverLayers && serverLayers.length > 0) {
    return (
      <div className="p-3 font-mono text-xs overflow-x-auto">
        {serverLayers.map((layer, i) => (
          <ServerLayerRow key={i} layer={layer} defaultOpen={i < 4} />
        ))}
      </div>
    );
  }

  // Client-side fallback
  const tree = buildProtocolTree(packet, metadata, proto);
  return (
    <div className="p-3 font-mono text-xs overflow-x-auto">
      {tree.map((node, i) => (
        <TreeRow key={i} node={node} depth={0} defaultOpen />
      ))}
    </div>
  );
}

function ServerLayerRow({ layer, defaultOpen }: { layer: ServerLayer; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="mb-0.5">
      <div
        className="flex items-center gap-1.5 py-0.5 px-1.5 rounded hover:bg-slate-700/40 cursor-pointer select-none"
        onClick={() => setOpen((v) => !v)}
      >
        <span className="w-3 text-slate-500 text-[10px] flex-shrink-0">
          {open ? "▼" : "▶"}
        </span>
        <span className="font-semibold" style={{ color: layer.color }}>
          {layer.name}
        </span>
      </div>
      {open && (
        <div className="ml-5 border-l border-slate-700/40 pl-3 space-y-0">
          {layer.fields.map((f, i) => (
            <div key={i} className="flex items-baseline gap-2 py-0.5 px-1 rounded hover:bg-slate-700/20 group">
              <span className="text-slate-400 w-40 flex-shrink-0 truncate" title={f.name}>{f.name}</span>
              <span className="text-cyan-300 break-all">{f.value}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TreeRow({ node, depth, defaultOpen }: { node: TreeNode; depth: number; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(!!defaultOpen);
  const hasChildren = !!node.children?.length;
  const indent = depth * 16;

  return (
    <div>
      <div
        className="flex items-baseline gap-1.5 py-0.5 hover:bg-slate-700/30 rounded cursor-pointer select-none"
        style={{ paddingLeft: `${indent + 6}px` }}
        onClick={() => hasChildren && setOpen((v) => !v)}
      >
        <span className="w-3 flex-shrink-0 text-slate-500">
          {hasChildren ? (open ? "▼" : "▶") : " "}
        </span>
        <span style={{ color: node.color || "#94a3b8" }} className="font-semibold">
          {node.label}
        </span>
        {node.value !== undefined && (
          <>
            <span className="text-slate-600">:</span>
            <span className="text-cyan-300 break-all">{node.value}</span>
          </>
        )}
      </div>
      {open && hasChildren && node.children!.map((child, i) => (
        <TreeRow key={i} node={child} depth={depth + 1} defaultOpen={depth < 1} />
      ))}
    </div>
  );
}

const LAYER_COLORS: Record<string, string> = {
  frame:    "#94a3b8",
  ethernet: "#64748b",
  ip:       "#818cf8",
  tcp:      "#38bdf8",
  udp:      "#38bdf8",
  sctp:     "#38bdf8",
  SIP:      "#34d399",
  RTP:      "#22d3ee",
  HTTP:     "#f59e0b",
  HTTPS:    "#84cc16",
  DNS:      "#818cf8",
  TLS:      "#84cc16",
  Diameter: "#f472b6",
  GTP:      "#fb923c",
  "GTP-C":  "#fb923c",
  "GTP-U":  "#fbbf24",
  PFCP:     "#a78bfa",
  S1AP:     "#38bdf8",
  NGAP:     "#4ade80",
  default:  "#94a3b8",
};

function buildProtocolTree(packet: any, metadata: any, proto: string): TreeNode[] {
  const nodes: TreeNode[] = [];

  // Frame
  nodes.push({
    label: `Frame ${packet.frame_number}`,
    color: LAYER_COLORS.frame,
    children: [
      { label: "Arrival Time", value: packet.timestamp },
      { label: "Frame Length", value: `${packet.length} bytes` },
      { label: "Capture Length", value: `${packet.length} bytes` },
    ],
  });

  // IP layer
  const ttlHint = packet.protocol === "UDP" ? "64" : "128";
  nodes.push({
    label: "Internet Protocol Version 4",
    color: LAYER_COLORS.ip,
    children: [
      { label: "Source Address", value: packet.src_ip },
      { label: "Destination Address", value: packet.dst_ip },
      { label: "Protocol", value: packet.protocol || "Unknown" },
      { label: "Time to Live", value: (metadata.ttl ?? ttlHint).toString() },
    ],
  });

  // Transport layer
  const transportProto = packet.protocol || "TCP";
  const transportColor = LAYER_COLORS[transportProto.toLowerCase()] ?? LAYER_COLORS.tcp;
  const transportChildren: TreeNode[] = [
    { label: "Source Port", value: `${packet.src_port}` },
    { label: "Destination Port", value: `${packet.dst_port}` },
  ];
  if (transportProto === "TCP") {
    const flags: string[] = [];
    if (metadata.syn) flags.push("SYN");
    if (metadata.ack) flags.push("ACK");
    if (metadata.fin) flags.push("FIN");
    if (metadata.rst) flags.push("RST");
    if (flags.length) transportChildren.push({ label: "Flags", value: flags.join(", ") });
    if (metadata.sequence !== undefined) transportChildren.push({ label: "Sequence", value: String(metadata.sequence) });
  }
  nodes.push({
    label: transportProto === "SCTP" ? "Stream Control Transmission Protocol" :
           transportProto === "UDP" ? "User Datagram Protocol" : "Transmission Control Protocol",
    color: transportColor,
    children: transportChildren,
  });

  // Application/protocol layer
  if (proto && proto !== transportProto) {
    const appColor = LAYER_COLORS[proto] ?? LAYER_COLORS.default;
    const appChildren = metadataToTreeNodes(metadata, proto);
    nodes.push({
      label: protoFullName(proto),
      color: appColor,
      children: appChildren.length ? appChildren : [{ label: "(no decoded fields)", color: "#475569" }],
    });
  }

  if (packet.summary) {
    nodes[0].children!.push({ label: "Info", value: packet.summary });
  }

  return nodes;
}

function metadataToTreeNodes(metadata: Record<string, any>, proto: string): TreeNode[] {
  const nodes: TreeNode[] = [];

  // SIP-specific tree grouping
  if (proto === "SIP") {
    const requestLine = metadata.method
      ? `${metadata.method} ${metadata.uri ?? ""}`
      : metadata.status_code
      ? `${metadata.status_code} ${metadata.status_text ?? ""}`
      : null;
    if (requestLine) nodes.push({ label: "Request/Status Line", value: requestLine.trim(), color: "#34d399" });
    const headerFields = ["from", "to", "call_id", "via", "contact", "content_type", "content_length", "user_agent"];
    const headerChildren: TreeNode[] = [];
    for (const k of headerFields) {
      if (metadata[k] !== undefined) headerChildren.push({ label: formatLabel(k), value: formatValue(metadata[k]) });
    }
    if (headerChildren.length) nodes.push({ label: "Message Header", color: "#34d399", children: headerChildren });
    const bodyKeys = Object.keys(metadata).filter(k => !headerFields.includes(k) && k !== "method" && k !== "uri" && k !== "status_code" && k !== "status_text");
    const bodyChildren = bodyKeys.map(k => ({ label: formatLabel(k), value: typeof metadata[k] === "object" ? JSON.stringify(metadata[k]) : formatValue(metadata[k]) }));
    if (bodyChildren.length) nodes.push({ label: "Message Body / Other", color: "#34d399", children: bodyChildren });
    return nodes;
  }

  // Diameter-specific
  if (proto === "Diameter") {
    if (metadata.command_code) nodes.push({ label: "Command Code", value: `${metadata.command_code} (${metadata.command ?? ""})`, color: "#f472b6" });
    if (metadata.app_id) nodes.push({ label: "Application ID", value: String(metadata.app_id), color: "#f472b6" });
    if (metadata.is_request !== undefined) nodes.push({ label: "Type", value: metadata.is_request ? "Request" : "Answer", color: "#f472b6" });
    if (metadata.origin_host) nodes.push({ label: "Origin Host", value: metadata.origin_host });
    if (metadata.result_code) nodes.push({ label: "Result Code", value: String(metadata.result_code) });
    const avpKeys = Object.keys(metadata).filter(k => !["command_code", "command", "app_id", "is_request", "origin_host", "result_code"].includes(k));
    if (avpKeys.length) {
      nodes.push({ label: "AVPs", color: "#f472b6", children: avpKeys.map(k => ({ label: formatLabel(k), value: typeof metadata[k] === "object" ? JSON.stringify(metadata[k]) : formatValue(metadata[k]) })) });
    }
    return nodes;
  }

  // NGAP/5G-specific
  if (proto === "NGAP" || proto === "S1AP") {
    if (metadata.procedure_name) nodes.push({ label: "Procedure", value: metadata.procedure_name, color: "#4ade80" });
    if (metadata.pdu_type) nodes.push({ label: "PDU Type", value: metadata.pdu_type, color: "#4ade80" });
    if (metadata.cause) nodes.push({ label: "Cause", value: metadata.cause });
    const rest = Object.entries(metadata).filter(([k]) => !["procedure_name", "pdu_type", "cause"].includes(k));
    if (rest.length) nodes.push({ label: "IEs", color: "#4ade80", children: rest.map(([k, v]) => ({ label: formatLabel(k), value: typeof v === "object" ? JSON.stringify(v) : formatValue(v) })) });
    return nodes;
  }

  // GTP
  if (proto === "GTP" || proto === "GTP-C" || proto === "GTP-U") {
    if (metadata.message_type) nodes.push({ label: "Message Type", value: metadata.message_type, color: "#fb923c" });
    if (metadata.teid !== undefined) nodes.push({ label: "TEID", value: `0x${Number(metadata.teid).toString(16).toUpperCase()}` });
    if (metadata.imsi) nodes.push({ label: "IMSI", value: metadata.imsi });
    if (metadata.apn) nodes.push({ label: "APN", value: metadata.apn });
    const rest = Object.entries(metadata).filter(([k]) => !["message_type", "teid", "imsi", "apn"].includes(k));
    if (rest.length) nodes.push({ label: "IEs", color: "#fb923c", children: rest.map(([k, v]) => ({ label: formatLabel(k), value: typeof v === "object" ? JSON.stringify(v) : formatValue(v) })) });
    return nodes;
  }

  // Generic fallback: flat list
  for (const [key, value] of Object.entries(metadata)) {
    if (Array.isArray(value)) {
      nodes.push({
        label: formatLabel(key),
        children: value.map((item, idx) => ({
          label: `[${idx}]`,
          value: typeof item === "object" ? undefined : String(item),
          children: typeof item === "object" ? Object.entries(item).map(([k, v]) => ({ label: formatLabel(k), value: formatValue(v) })) : undefined,
        })),
      });
    } else if (typeof value === "object" && value !== null) {
      nodes.push({
        label: formatLabel(key),
        children: Object.entries(value as Record<string, any>).map(([k, v]) => ({ label: formatLabel(k), value: formatValue(v) })),
      });
    } else {
      nodes.push({ label: formatLabel(key), value: formatValue(value) });
    }
  }

  return nodes;
}

function protoFullName(proto: string): string {
  const names: Record<string, string> = {
    SIP: "Session Initiation Protocol",
    RTP: "Real-time Transport Protocol",
    HTTP: "Hypertext Transfer Protocol",
    HTTPS: "HTTP over TLS",
    DNS: "Domain Name System",
    TLS: "Transport Layer Security",
    Diameter: "Diameter Protocol",
    GTP: "GPRS Tunnelling Protocol",
    "GTP-C": "GTP Control Plane",
    "GTP-U": "GTP User Plane",
    PFCP: "Packet Forwarding Control Protocol",
    S1AP: "S1 Application Protocol (LTE)",
    NGAP: "NG Application Protocol (5G)",
    SCTP: "Stream Control Transmission Protocol",
    WebSocket: "WebSocket Protocol",
  };
  return names[proto] ?? proto;
}

/* ============ Helpers ============ */

function parseJSON(raw: any, fallback: any): any {
  if (!raw) return fallback;
  try {
    return typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    return fallback;
  }
}

function parseJSONArray(raw: any): any[] {
  const parsed = parseJSON(raw, []);
  return Array.isArray(parsed) ? parsed : [];
}

function categorizeMetadata(metadata: Record<string, any>, _proto: string) {
  const identityKeys = new Set([
    "imsi", "msisdn", "mei", "user_name", "from", "to",
    "session_id", "call_id", "sni", "cert_subject", "cert_issuer",
  ]);
  const sessionKeys = new Set([
    "method", "uri", "host", "command", "command_code", "app_id", "app_name",
    "is_request", "response", "status_code", "status_text", "result_code",
    "message_type", "pdu_type", "procedure_name", "procedure_code",
    "handshake_type", "handshake_messages",
    "content_type", "content_length", "user_agent", "server",
    "has_auth", "has_cookie", "body_preview",
    "query_name", "query_type", "reply_code", "answers",
    "direction", "media_ip", "media_port",
    "apn", "pdn_type", "pdn_address", "rat_type", "serving_network",
    "tls_version", "cipher_suite", "alpn",
    "origin_host",
  ]);
  const networkKeys = new Set([
    "teid", "seid", "ssrc", "cause_code", "cause",
    "is_gtpu", "is_error", "is_response",
    "tai", "ecgi", "recovery", "charging_id",
    "sequence", "version", "message_count",
  ]);
  const qosKeys = new Set([
    "jitter_ms", "packet_count", "max_seq_gap", "latency_ms",
    "ambr_uplink_kbps", "ambr_downlink_kbps",
    "bearer_count", "hold_count", "hold_events", "setup_latency_ms",
  ]);

  const identityFields: [string, any][] = [];
  const sessionFields: [string, any][] = [];
  const networkFields: [string, any][] = [];
  const qosFields: [string, any][] = [];
  const otherFields: [string, any][] = [];

  for (const [key, value] of Object.entries(metadata)) {
    if (Array.isArray(value) || (typeof value === "object" && value !== null)) continue;
    if (identityKeys.has(key)) identityFields.push([key, value]);
    else if (sessionKeys.has(key)) sessionFields.push([key, value]);
    else if (networkKeys.has(key)) networkFields.push([key, value]);
    else if (qosKeys.has(key)) qosFields.push([key, value]);
    else otherFields.push([key, value]);
  }

  return { identityFields, sessionFields, networkFields, qosFields, otherFields };
}

function formatLabel(key: string): string {
  return key
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .replace(/Imsi/g, "IMSI").replace(/Msisdn/g, "MSISDN").replace(/Mei/g, "MEI")
    .replace(/Teid/g, "TEID").replace(/Seid/g, "SEID").replace(/Apn/g, "APN")
    .replace(/Sni/g, "SNI").replace(/Tls/g, "TLS").replace(/Alpn/g, "ALPN")
    .replace(/Qci/g, "QCI").replace(/Pdn/g, "PDN").replace(/Ip /g, "IP ")
    .replace(/Ipv4/g, "IPv4").replace(/Ipv6/g, "IPv6").replace(/Mbr /g, "MBR ")
    .replace(/Gbr /g, "GBR ").replace(/Ambr/g, "AMBR").replace(/Rat /g, "RAT ")
    .replace(/Ebi/g, "EBI").replace(/Uri/g, "URI").replace(/Ssrc/g, "SSRC")
    .replace(/Ecgi/g, "ECGI").replace(/Tai/g, "TAI").replace(/Fteids/g, "F-TEIDs")
    .replace(/Fteid/g, "F-TEID");
}

function formatValue(value: any): string {
  if (value === null || value === undefined) return "-";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toISOString().replace("T", " ").replace("Z", " UTC");
  } catch {
    return ts;
  }
}

function protocolBadge(proto: string): string {
  const colors: Record<string, string> = {
    SIP: "bg-blue-500/20 text-blue-400",
    RTP: "bg-purple-500/20 text-purple-400",
    DNS: "bg-cyan-500/20 text-cyan-400",
    HTTP: "bg-emerald-500/20 text-emerald-400",
    TLS: "bg-lime-500/20 text-lime-400",
    HTTPS: "bg-lime-500/20 text-lime-400",
    Diameter: "bg-orange-500/20 text-orange-400",
    GTP: "bg-yellow-500/20 text-yellow-400",
    "GTP-C": "bg-yellow-500/20 text-yellow-400",
    "GTP-U": "bg-yellow-500/20 text-yellow-300",
    PFCP: "bg-pink-500/20 text-pink-400",
    S1AP: "bg-teal-500/20 text-teal-400",
    NGAP: "bg-indigo-500/20 text-indigo-400",
    WebSocket: "bg-violet-500/20 text-violet-400",
    SCTP: "bg-slate-500/20 text-slate-400",
    TCP: "bg-slate-500/20 text-slate-400",
    UDP: "bg-slate-500/20 text-slate-400",
  };
  return colors[proto] || "bg-slate-500/20 text-slate-400";
}
