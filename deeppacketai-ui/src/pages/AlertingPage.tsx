import { useEffect, useState } from "react";
import { api } from "../api/client";
import {
  Bell, Plus, Trash2, Pencil, Play, Slack, Globe, Mail,
  CheckCircle2, XCircle, ChevronDown, ChevronUp, Save, X,
} from "lucide-react";
import { clsx } from "clsx";

// ---- Types ------------------------------------------------------------------

interface AlertTarget {
  id: number;
  name: string;
  type: "slack" | "webhook" | "email";
  url: string;
  config_json: string;
  enabled: boolean;
  min_severity: "info" | "warning" | "critical";
  created_at: string;
}

const TYPE_ICON: Record<string, typeof Slack> = {
  slack: Slack,
  webhook: Globe,
  email: Mail,
};

const SEV_BADGE: Record<string, string> = {
  info:     "text-sky-400 bg-sky-400/10",
  warning:  "text-yellow-400 bg-yellow-400/10",
  critical: "text-red-400 bg-red-400/10",
};

const emptyTarget = (): Omit<AlertTarget, "id" | "created_at"> => ({
  name: "",
  type: "slack",
  url: "",
  config_json: "{}",
  enabled: true,
  min_severity: "warning",
});

// ---- Form -------------------------------------------------------------------

function TargetForm({
  initial,
  onSave,
  onCancel,
}: {
  initial: Omit<AlertTarget, "id" | "created_at">;
  onSave: (t: Omit<AlertTarget, "id" | "created_at">) => void;
  onCancel: () => void;
}) {
  const [form, setForm] = useState(initial);
  const [configExpanded, setConfigExpanded] = useState(false);

  const set = (field: keyof typeof form, value: any) =>
    setForm((f) => ({ ...f, [field]: value }));

  return (
    <div className="bg-slate-800/80 border border-slate-700/60 rounded-xl p-4 space-y-3">
      <div className="grid grid-cols-2 gap-3">
        {/* Name */}
        <div className="col-span-2">
          <label className="text-xs text-slate-400 mb-1 block">Name</label>
          <input
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
            placeholder="e.g. Slack #alerts"
          />
        </div>

        {/* Type */}
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Type</label>
          <select
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
            value={form.type}
            onChange={(e) => set("type", e.target.value as AlertTarget["type"])}
          >
            <option value="slack">Slack Webhook</option>
            <option value="webhook">Generic Webhook</option>
            <option value="email">Email (SMTP)</option>
          </select>
        </div>

        {/* Min Severity */}
        <div>
          <label className="text-xs text-slate-400 mb-1 block">Min Severity</label>
          <select
            className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
            value={form.min_severity}
            onChange={(e) => set("min_severity", e.target.value as AlertTarget["min_severity"])}
          >
            <option value="info">Info (all alerts)</option>
            <option value="warning">Warning+</option>
            <option value="critical">Critical only</option>
          </select>
        </div>

        {/* URL — hidden for email */}
        {form.type !== "email" && (
          <div className="col-span-2">
            <label className="text-xs text-slate-400 mb-1 block">
              {form.type === "slack" ? "Slack Incoming Webhook URL" : "Webhook URL"}
            </label>
            <input
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
              value={form.url}
              onChange={(e) => set("url", e.target.value)}
              placeholder="https://..."
            />
          </div>
        )}

        {/* Email fields inline */}
        {form.type === "email" && (
          <div className="col-span-2 grid grid-cols-2 gap-3">
            {[
              { key: "smtp_host", label: "SMTP Host", placeholder: "smtp.gmail.com" },
              { key: "smtp_port", label: "Port", placeholder: "587" },
              { key: "smtp_user", label: "Username", placeholder: "user@example.com" },
              { key: "smtp_pass", label: "Password", placeholder: "••••••••" },
              { key: "from", label: "From", placeholder: "noreply@example.com" },
              { key: "to", label: "To (comma-sep)", placeholder: "admin@example.com" },
            ].map(({ key, label, placeholder }) => {
              let parsed: Record<string, string> = {};
              try { parsed = JSON.parse(form.config_json) || {}; } catch { /* ignore */ }
              return (
                <div key={key}>
                  <label className="text-xs text-slate-400 mb-1 block">{label}</label>
                  <input
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-emerald-500"
                    type={key === "smtp_pass" ? "password" : "text"}
                    value={parsed[key] ?? ""}
                    placeholder={placeholder}
                    onChange={(e) => {
                      const next = { ...parsed, [key]: e.target.value };
                      set("config_json", JSON.stringify(next));
                    }}
                  />
                </div>
              );
            })}
          </div>
        )}

        {/* Webhook extra headers (optional) */}
        {form.type === "webhook" && (
          <div className="col-span-2">
            <button
              type="button"
              onClick={() => setConfigExpanded((v) => !v)}
              className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300"
            >
              {configExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              Extra headers (JSON)
            </button>
            {configExpanded && (
              <textarea
                rows={3}
                className="mt-1 w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-300 font-mono focus:outline-none focus:border-emerald-500"
                value={form.config_json}
                onChange={(e) => set("config_json", e.target.value)}
                placeholder={'{"headers": {"X-Token": "secret"}}'}
              />
            )}
          </div>
        )}

        {/* Enabled */}
        <div className="col-span-2 flex items-center gap-2">
          <input
            id="enabled-chk"
            type="checkbox"
            className="w-4 h-4 accent-emerald-500"
            checked={form.enabled}
            onChange={(e) => set("enabled", e.target.checked)}
          />
          <label htmlFor="enabled-chk" className="text-sm text-slate-300">Enabled</label>
        </div>
      </div>

      <div className="flex gap-2 pt-1">
        <button
          onClick={() => onSave(form)}
          className="flex items-center gap-1.5 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm rounded-lg transition-colors"
        >
          <Save className="w-3.5 h-3.5" /> Save
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

// ---- Card -------------------------------------------------------------------

function TargetCard({
  target,
  onEdit,
  onDelete,
  onTest,
}: {
  target: AlertTarget;
  onEdit: () => void;
  onDelete: () => void;
  onTest: () => void;
}) {
  const Icon = TYPE_ICON[target.type] ?? Globe;
  return (
    <div className={clsx(
      "bg-slate-800/70 border rounded-xl p-4 flex items-start gap-3",
      target.enabled ? "border-slate-700/60" : "border-slate-700/30 opacity-60"
    )}>
      <div className="mt-0.5 text-slate-400">
        <Icon className="w-5 h-5" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-sm font-medium text-slate-200">{target.name}</span>
          <span className={clsx(
            "text-[10px] font-medium px-1.5 py-0.5 rounded uppercase",
            SEV_BADGE[target.min_severity] ?? SEV_BADGE.warning
          )}>
            {target.min_severity}+
          </span>
          {target.enabled
            ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 ml-auto" />
            : <XCircle className="w-3.5 h-3.5 text-slate-500 ml-auto" />}
        </div>
        <p className="text-xs text-slate-500 truncate">
          {target.type} · {target.url || "(no url)"}
        </p>
      </div>
      <div className="flex items-center gap-1 flex-shrink-0">
        <button
          onClick={onTest}
          title="Send test notification"
          className="p-1.5 text-slate-500 hover:text-emerald-400 hover:bg-slate-700 rounded-lg transition-colors"
        >
          <Play className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={onEdit}
          className="p-1.5 text-slate-500 hover:text-sky-400 hover:bg-slate-700 rounded-lg transition-colors"
        >
          <Pencil className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={onDelete}
          className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-slate-700 rounded-lg transition-colors"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}

// ---- Page -------------------------------------------------------------------

export default function AlertingPage() {
  const [targets, setTargets] = useState<AlertTarget[]>([]);
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
      const res = await api.get<AlertTarget[]>("/alert-targets");
      setTargets(res.data ?? []);
    } catch {
      showToast("Failed to load alert targets", false);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleCreate(form: Omit<AlertTarget, "id" | "created_at">) {
    try {
      await api.post("/alert-targets", form);
      setCreating(false);
      load();
      showToast("Alert target created");
    } catch {
      showToast("Failed to create target", false);
    }
  }

  async function handleUpdate(id: number, form: Omit<AlertTarget, "id" | "created_at">) {
    try {
      await api.put(`/alert-targets/${id}`, { ...form, id });
      setEditingId(null);
      load();
      showToast("Alert target updated");
    } catch {
      showToast("Failed to update target", false);
    }
  }

  async function handleDelete(id: number) {
    if (!confirm("Delete this alert target?")) return;
    try {
      await api.delete(`/alert-targets/${id}`);
      load();
      showToast("Alert target deleted");
    } catch {
      showToast("Failed to delete target", false);
    }
  }

  async function handleTest(id: number) {
    try {
      await api.post(`/alert-targets/${id}/test`);
      showToast("Test notification sent");
    } catch {
      showToast("Test notification failed", false);
    }
  }

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bell className="w-5 h-5 text-violet-400" />
          <h1 className="text-xl font-semibold text-slate-100">Alert Notifications</h1>
        </div>
        {!creating && (
          <button
            onClick={() => setCreating(true)}
            className="flex items-center gap-1.5 px-3 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-sm rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" /> Add Target
          </button>
        )}
      </div>

      <p className="text-sm text-slate-400">
        Configure where DeepPacketAI sends notifications when alerts are detected.
        Supports Slack incoming webhooks, generic HTTP webhooks, and SMTP email.
      </p>

      {/* Toast */}
      {toast && (
        <div className={clsx(
          "fixed top-4 right-4 z-50 px-4 py-2 rounded-lg text-sm shadow-lg transition-all",
          toast.ok ? "bg-emerald-600 text-white" : "bg-red-600 text-white"
        )}>
          {toast.msg}
        </div>
      )}

      {/* Create form */}
      {creating && (
        <TargetForm
          initial={emptyTarget()}
          onSave={handleCreate}
          onCancel={() => setCreating(false)}
        />
      )}

      {/* List */}
      {loading ? (
        <div className="text-center py-12 text-slate-500 text-sm">Loading…</div>
      ) : targets.length === 0 && !creating ? (
        <div className="flex flex-col items-center justify-center py-16 text-slate-600">
          <Bell className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm">No alert targets configured.</p>
          <p className="text-xs mt-1">Click "Add Target" to set up Slack, webhook, or email notifications.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {targets.map((t) =>
            editingId === t.id ? (
              <TargetForm
                key={t.id}
                initial={{ name: t.name, type: t.type, url: t.url, config_json: t.config_json, enabled: t.enabled, min_severity: t.min_severity }}
                onSave={(form) => handleUpdate(t.id, form)}
                onCancel={() => setEditingId(null)}
              />
            ) : (
              <TargetCard
                key={t.id}
                target={t}
                onEdit={() => setEditingId(t.id)}
                onDelete={() => handleDelete(t.id)}
                onTest={() => handleTest(t.id)}
              />
            )
          )}
        </div>
      )}
    </div>
  );
}
