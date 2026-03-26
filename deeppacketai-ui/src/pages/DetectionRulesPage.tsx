import { useEffect, useState } from "react";
import { api } from "../api/client";
import {
  ShieldCheck, Plus, Trash2, Pencil, Save, X, ChevronDown, ChevronUp,
  ToggleLeft, ToggleRight, Info,
} from "lucide-react";
import { clsx } from "clsx";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Condition {
  field: string;
  operator: ">" | ">=" | "<" | "<=" | "==" | "!=";
  value: number;
}

interface RuleCondition {
  conditions: Condition[];
  match: "any" | "all";
}

interface UserRule {
  id: number;
  name: string;
  description: string;
  protocol: string;
  severity: "info" | "warning" | "error" | "critical";
  condition_json: string;
  enabled: boolean;
  created_at: string;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const PROTOCOLS = ["ANY", "SIP", "RTP", "DNS", "GTP", "NGAP", "TLS", "Diameter", "PFCP", "HTTP", "WebSocket"];

const SEVERITY_BADGE: Record<string, string> = {
  info:     "text-sky-400 bg-sky-400/10",
  warning:  "text-yellow-400 bg-yellow-400/10",
  error:    "text-orange-400 bg-orange-400/10",
  critical: "text-red-400 bg-red-400/10",
};

// Available fields grouped by category
const FIELD_GROUPS = [
  {
    label: "Volume",
    fields: [
      { value: "total_flows",         label: "Total Flows" },
      { value: "total_packets",       label: "Total Packets" },
      { value: "capture_window_secs", label: "Capture Window (secs)" },
    ],
  },
  {
    label: "Protocol Flow Counts",
    fields: [
      { value: "flow_count.SIP",      label: "SIP Flows" },
      { value: "flow_count.RTP",      label: "RTP Flows" },
      { value: "flow_count.DNS",      label: "DNS Flows" },
      { value: "flow_count.GTP",      label: "GTP Flows" },
      { value: "flow_count.NGAP",     label: "NGAP Flows" },
      { value: "flow_count.TLS",      label: "TLS Flows" },
      { value: "flow_count.Diameter", label: "Diameter Flows" },
    ],
  },
  {
    label: "SIP Behaviour",
    fields: [
      { value: "sip_401_max",      label: "Max 401s from single IP" },
      { value: "sip_register_max", label: "Max REGISTERs from single IP" },
      { value: "sip_invite_max",   label: "Max INVITEs from single IP" },
      { value: "sip_options_max",  label: "Max OPTIONS from single IP" },
    ],
  },
  {
    label: "Network",
    fields: [
      { value: "source_fan_out_max", label: "Max Destinations from single source" },
      { value: "dns_query_max",      label: "Max DNS queries for single domain" },
    ],
  },
];

const ALL_FIELDS = FIELD_GROUPS.flatMap((g) => g.fields);

function fieldLabel(value: string) {
  return ALL_FIELDS.find((f) => f.value === value)?.label ?? value;
}

const OPERATORS = [">", ">=", "<", "<=", "==", "!="] as const;

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseCondition(json: string): RuleCondition {
  try {
    const parsed = JSON.parse(json);
    if (parsed && Array.isArray(parsed.conditions)) return parsed;
  } catch { /* ignore */ }
  return { conditions: [], match: "any" };
}

function emptyRule(): Omit<UserRule, "id" | "created_at"> {
  return {
    name: "",
    description: "",
    protocol: "ANY",
    severity: "warning",
    condition_json: JSON.stringify({ conditions: [{ field: "total_flows", operator: ">", value: 100 }], match: "any" }),
    enabled: true,
  };
}

// ── Condition Builder ─────────────────────────────────────────────────────────

function ConditionBuilder({
  value,
  onChange,
}: {
  value: RuleCondition;
  onChange: (rc: RuleCondition) => void;
}) {
  const set = (rc: RuleCondition) => onChange(rc);

  const addCondition = () =>
    set({ ...value, conditions: [...value.conditions, { field: "total_flows", operator: ">", value: 100 }] });

  const removeCondition = (i: number) =>
    set({ ...value, conditions: value.conditions.filter((_, idx) => idx !== i) });

  const updateCondition = (i: number, partial: Partial<Condition>) =>
    set({
      ...value,
      conditions: value.conditions.map((c, idx) => (idx === i ? { ...c, ...partial } : c)),
    });

  return (
    <div className="space-y-2">
      {/* Match mode */}
      <div className="flex items-center gap-2 text-xs text-slate-400">
        <span>Fire when</span>
        <select
          className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-emerald-500"
          value={value.match}
          onChange={(e) => set({ ...value, match: e.target.value as "any" | "all" })}
        >
          <option value="any">ANY condition matches</option>
          <option value="all">ALL conditions match</option>
        </select>
      </div>

      {/* Conditions list */}
      {value.conditions.map((cond, i) => (
        <div key={i} className="flex items-center gap-2 flex-wrap">
          {/* Field */}
          <select
            className="flex-1 min-w-[200px] bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
            value={cond.field}
            onChange={(e) => updateCondition(i, { field: e.target.value })}
          >
            {FIELD_GROUPS.map((g) => (
              <optgroup key={g.label} label={g.label}>
                {g.fields.map((f) => (
                  <option key={f.value} value={f.value}>{f.label}</option>
                ))}
              </optgroup>
            ))}
          </select>

          {/* Operator */}
          <select
            className="w-16 bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
            value={cond.operator}
            onChange={(e) => updateCondition(i, { operator: e.target.value as Condition["operator"] })}
          >
            {OPERATORS.map((op) => <option key={op} value={op}>{op}</option>)}
          </select>

          {/* Value */}
          <input
            type="number"
            className="w-24 bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
            value={cond.value}
            onChange={(e) => updateCondition(i, { value: Number(e.target.value) })}
          />

          <button
            onClick={() => removeCondition(i)}
            className="p-1 text-slate-600 hover:text-red-400 transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      ))}

      <button
        onClick={addCondition}
        className="flex items-center gap-1 text-xs text-emerald-500 hover:text-emerald-400"
      >
        <Plus className="w-3 h-3" /> Add condition
      </button>
    </div>
  );
}

// ── Rule Form ─────────────────────────────────────────────────────────────────

function RuleForm({
  initial,
  onSave,
  onCancel,
}: {
  initial: Omit<UserRule, "id" | "created_at">;
  onSave: (r: Omit<UserRule, "id" | "created_at">) => void;
  onCancel: () => void;
}) {
  const [form, setForm] = useState(initial);
  const [rc, setRc] = useState<RuleCondition>(parseCondition(initial.condition_json));

  const set = (field: keyof typeof form, val: any) => setForm((f) => ({ ...f, [field]: val }));

  const handleSave = () => {
    onSave({ ...form, condition_json: JSON.stringify(rc) });
  };

  return (
    <div className="bg-slate-800/80 border border-slate-700/60 rounded-xl p-4 space-y-4">
      <div className="grid grid-cols-2 gap-3">
        {/* Name */}
        <div className="col-span-2">
          <label className="text-xs text-slate-400 mb-1 block">Rule Name</label>
          <input
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
            placeholder="e.g. High SIP Invite Flood"
          />
        </div>

        {/* Description */}
        <div className="col-span-2">
          <label className="text-xs text-slate-400 mb-1 block">Description (optional)</label>
          <input
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
            value={form.description}
            onChange={(e) => set("description", e.target.value)}
            placeholder="Describe what this rule detects"
          />
        </div>

        {/* Protocol */}
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Protocol</label>
          <select
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
            value={form.protocol}
            onChange={(e) => set("protocol", e.target.value)}
          >
            {PROTOCOLS.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
        </div>

        {/* Severity */}
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Severity</label>
          <select
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
            value={form.severity}
            onChange={(e) => set("severity", e.target.value as UserRule["severity"])}
          >
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="error">Error</option>
            <option value="critical">Critical</option>
          </select>
        </div>

        {/* Enabled */}
        <div className="col-span-2 flex items-center gap-2">
          <input id="rule-enabled" type="checkbox" className="w-4 h-4 accent-emerald-500"
            checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />
          <label htmlFor="rule-enabled" className="text-sm text-slate-300">Enabled</label>
        </div>
      </div>

      {/* Conditions */}
      <div>
        <label className="text-xs text-slate-400 mb-2 block">Conditions</label>
        <div className="bg-slate-900/60 border border-slate-700/50 rounded-lg p-3">
          <ConditionBuilder value={rc} onChange={setRc} />
        </div>
      </div>

      <div className="flex gap-2">
        <button
          onClick={handleSave}
          className="flex items-center gap-1.5 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm rounded-lg transition-colors"
        >
          <Save className="w-3.5 h-3.5" /> Save Rule
        </button>
        <button
          onClick={onCancel}
          className="flex items-center gap-1.5 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm rounded-lg transition-colors"
        >
          <X className="w-3.5 h-3.5" /> Cancel
        </button>
      </div>
    </div>
  );
}

// ── Rule Card ─────────────────────────────────────────────────────────────────

function RuleCard({
  rule,
  onEdit,
  onDelete,
  onToggle,
}: {
  rule: UserRule;
  onEdit: () => void;
  onDelete: () => void;
  onToggle: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const rc = parseCondition(rule.condition_json);

  return (
    <div className={clsx(
      "bg-slate-800/70 border rounded-xl p-4 transition-all",
      rule.enabled ? "border-slate-700/60" : "border-slate-700/30 opacity-60"
    )}>
      <div className="flex items-start gap-3">
        <ShieldCheck className={clsx("w-4 h-4 mt-0.5 flex-shrink-0",
          rule.enabled ? "text-emerald-400" : "text-slate-600")} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-sm font-medium text-slate-200">{rule.name}</span>
            <span className={clsx("text-[10px] font-medium px-1.5 py-0.5 rounded uppercase",
              SEVERITY_BADGE[rule.severity] ?? SEVERITY_BADGE.warning)}>
              {rule.severity}
            </span>
            <span className="text-[10px] text-slate-500 bg-slate-700/50 px-1.5 py-0.5 rounded">
              {rule.protocol}
            </span>
            <span className="text-[10px] text-slate-500 ml-auto">
              {rc.conditions.length} condition{rc.conditions.length !== 1 ? "s" : ""} · match {rc.match}
            </span>
          </div>
          {rule.description && (
            <p className="text-xs text-slate-500 mb-1">{rule.description}</p>
          )}

          {/* Conditions preview */}
          {expanded && (
            <div className="mt-2 space-y-1">
              {rc.conditions.map((c, i) => (
                <div key={i} className="text-xs text-slate-400 font-mono">
                  {fieldLabel(c.field)} {c.operator} {c.value}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flex items-center gap-1 flex-shrink-0">
          <button onClick={() => setExpanded((v) => !v)}
            className="p-1.5 text-slate-500 hover:text-slate-300 hover:bg-slate-700 rounded-lg transition-colors">
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
          <button onClick={onToggle}
            className="p-1.5 text-slate-500 hover:text-emerald-400 hover:bg-slate-700 rounded-lg transition-colors"
            title={rule.enabled ? "Disable rule" : "Enable rule"}>
            {rule.enabled
              ? <ToggleRight className="w-4 h-4 text-emerald-400" />
              : <ToggleLeft className="w-4 h-4" />}
          </button>
          <button onClick={onEdit}
            className="p-1.5 text-slate-500 hover:text-sky-400 hover:bg-slate-700 rounded-lg transition-colors">
            <Pencil className="w-3.5 h-3.5" />
          </button>
          <button onClick={onDelete}
            className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-slate-700 rounded-lg transition-colors">
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function DetectionRulesPage() {
  const [rules, setRules] = useState<UserRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);

  function showToast(msg: string, ok = true) {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3000);
  }

  async function load() {
    try {
      const res = await api.get<UserRule[]>("/detection-rules");
      setRules(res.data ?? []);
    } catch {
      showToast("Failed to load detection rules", false);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleCreate(form: Omit<UserRule, "id" | "created_at">) {
    try {
      await api.post("/detection-rules", form);
      setCreating(false);
      load();
      showToast("Rule created");
    } catch (err: any) {
      showToast(err?.response?.data?.error ?? "Failed to create rule", false);
    }
  }

  async function handleUpdate(id: number, form: Omit<UserRule, "id" | "created_at">) {
    try {
      await api.put(`/detection-rules/${id}`, { ...form, id });
      setEditingId(null);
      load();
      showToast("Rule updated");
    } catch (err: any) {
      showToast(err?.response?.data?.error ?? "Failed to update rule", false);
    }
  }

  async function handleDelete(id: number) {
    if (!confirm("Delete this detection rule?")) return;
    try {
      await api.delete(`/detection-rules/${id}`);
      load();
      showToast("Rule deleted");
    } catch {
      showToast("Failed to delete rule", false);
    }
  }

  async function handleToggle(rule: UserRule) {
    try {
      await api.put(`/detection-rules/${rule.id}`, { ...rule, enabled: !rule.enabled });
      load();
    } catch {
      showToast("Failed to toggle rule", false);
    }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <h1 className="text-xl font-semibold text-slate-100">Detection Rules</h1>
        </div>
        {!creating && (
          <button
            onClick={() => setCreating(true)}
            className="flex items-center gap-1.5 px-3 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" /> New Rule
          </button>
        )}
      </div>

      {/* Info banner */}
      <div className="flex gap-2 bg-sky-500/5 border border-sky-500/20 rounded-lg p-3 text-xs text-slate-400">
        <Info className="w-4 h-4 text-sky-400 flex-shrink-0 mt-0.5" />
        <div>
          User rules run alongside all 24 built-in rules after every PCAP analysis and live capture session.
          They fire when the aggregate statistics for a capture session match the defined conditions.
        </div>
      </div>

      {/* Toast */}
      {toast && (
        <div className={clsx(
          "fixed top-4 right-4 z-50 px-4 py-2 rounded-lg text-sm shadow-lg",
          toast.ok ? "bg-emerald-600 text-white" : "bg-red-600 text-white"
        )}>
          {toast.msg}
        </div>
      )}

      {/* Create form */}
      {creating && (
        <RuleForm
          initial={emptyRule()}
          onSave={handleCreate}
          onCancel={() => setCreating(false)}
        />
      )}

      {/* Rules list */}
      {loading ? (
        <div className="text-center py-12 text-slate-500 text-sm">Loading…</div>
      ) : rules.length === 0 && !creating ? (
        <div className="flex flex-col items-center justify-center py-16 text-slate-600">
          <ShieldCheck className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm">No custom detection rules yet.</p>
          <p className="text-xs mt-1">Click "New Rule" to create a threshold-based detection rule.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {rules.map((r) =>
            editingId === r.id ? (
              <RuleForm
                key={r.id}
                initial={{ name: r.name, description: r.description, protocol: r.protocol,
                  severity: r.severity, condition_json: r.condition_json, enabled: r.enabled }}
                onSave={(form) => handleUpdate(r.id, form)}
                onCancel={() => setEditingId(null)}
              />
            ) : (
              <RuleCard
                key={r.id}
                rule={r}
                onEdit={() => setEditingId(r.id)}
                onDelete={() => handleDelete(r.id)}
                onToggle={() => handleToggle(r)}
              />
            )
          )}
        </div>
      )}
    </div>
  );
}
