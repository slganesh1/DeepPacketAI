import { useParams } from "react-router-dom";
import { useEffect, useState } from "react";
import {
  fetchEntityDetail,
  fetchEntityEvents,
  fetchEntityMetrics,
  fetchCallFlow,
} from "../api/entityDetail";

import type {
  EntityDetail,
  EntityEvent,
  CallFlowData,
} from "../api/entityDetail";

import LadderDiagram from "../components/callflow/LadderDiagram";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";

export default function EntityDetailPage() {
  const { entityId } = useParams();

  const [detail, setDetail] = useState<EntityDetail | null>(null);
  const [events, setEvents] = useState<EntityEvent[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [callFlow, setCallFlow] = useState<CallFlowData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!entityId) return;

    Promise.all([
      fetchEntityDetail(entityId),
      fetchEntityEvents(entityId),
      fetchEntityMetrics(entityId),
      fetchCallFlow(entityId).catch(() => null),
    ])
      .then(([d, e, m, cf]) => {
        setDetail(d);
        setEvents(e);
        setMetrics(m);
        setCallFlow(cf);
      })
      .finally(() => setLoading(false));
  }, [entityId]);

  if (loading) {
    return <div className="p-6">Loading call details…</div>;
  }

  if (!detail) {
    return <div className="p-6 text-red-600">Call not found</div>;
  }
return (
  <div className="p-6 space-y-8">

    {/* Header */}
    <div>
      <h1 className="text-2xl font-semibold">
        Call {detail.entity.entity_id.replace("call:", "")}
      </h1>
      <p className="text-sm text-gray-500">
        SIP + RTP Analysis
      </p>
    </div>

    {/* Summary Cards */}
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
      <Metric
        label="MOS"
        value={detail.entity.summary.mos.toFixed(2)}
      />
      <Metric
        label="Quality"
        value={detail.entity.summary.quality}
      />
      <Metric
        label="Root Cause"
        value={detail.entity.summary.root_cause}
      />
      <Metric
        label="Confidence"
        value={`${(detail.entity.summary.confidence * 100).toFixed(0)}%`}
      />
      {detail.setup_latency_ms != null && (
        <Metric
          label="Setup Latency"
          value={
            detail.setup_latency_ms >= 1000
              ? `${(detail.setup_latency_ms / 1000).toFixed(1)}s`
              : `${Math.round(detail.setup_latency_ms)}ms`
          }
        />
      )}
    </div>


    {/* Main Content Grid */}
    <div className="grid grid-cols-3 gap-6">

      {/* LEFT SIDE (2 columns wide) */}
      <div className="col-span-2 space-y-6">

        {/* SIP Events */}
        <div className="bg-white border rounded-lg shadow-sm">
          <div className="px-4 py-3 border-b font-medium">
            SIP Events
          </div>

          <table className="w-full text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="p-3 text-left">Time</th>
                <th className="p-3">Method</th>
                <th className="p-3">Response</th>
                <th className="p-3 text-left">Raw</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e, i) => (
                <tr key={i} className="border-t hover:bg-gray-50">
                  <td className="p-3 font-mono text-xs">
                    {e.timestamp}
                  </td>
                  <td className="p-3">{e.method}</td>
                  <td className="p-3">{e.response ?? "-"}</td>
                  <td className="p-3 font-mono text-xs">
                    {e.raw_line}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Charts */}
        {metrics && (
          <div className="bg-white border rounded-lg shadow-sm p-4 space-y-6">

            <div>
              <h2 className="font-semibold mb-2">
                RTP Jitter (ms)
              </h2>
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={metrics.jitter}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" />
                  <YAxis />
                  <Tooltip />
                  <Line type="monotone" dataKey="value" stroke="#ef4444" />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div>
              <h2 className="font-semibold mb-2">
                Packet Count
              </h2>
              <ResponsiveContainer width="100%" height={250}>
                <LineChart data={metrics.packet_count}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="timestamp" />
                  <YAxis />
                  <Tooltip />
                  <Line type="monotone" dataKey="value" stroke="#3b82f6" />
                </LineChart>
              </ResponsiveContainer>
            </div>

          </div>
        )}

      </div>

      {/* Call Flow Ladder Diagram */}
      {callFlow && callFlow.events && callFlow.events.length > 0 && (
        <div className="col-span-3">
          <div className="bg-white border rounded-lg shadow-sm">
            <div className="px-4 py-3 border-b font-medium">
              Call Flow Ladder Diagram
            </div>
            <div className="p-4">
              <LadderDiagram data={callFlow} />
            </div>
          </div>
        </div>
      )}

      {/* RIGHT SIDE */}
      <div className="bg-white border rounded-lg shadow-sm">
        <div className="px-4 py-3 border-b font-medium">
          RTP Legs
        </div>

        <table className="w-full text-sm">
          <thead className="bg-gray-50">
            <tr>
              <th className="p-2 text-left">Source</th>
              <th className="p-2 text-left">Destination</th>
              <th className="p-2">Packets</th>
              <th className="p-2">Jitter</th>
            </tr>
          </thead>
          <tbody>
            {detail.rtp_legs?.map((leg: any, i: number) => (
              <tr key={i} className="border-t hover:bg-gray-50">
                <td className="p-2">
                  {leg.src_ip}:{leg.src_port}
                </td>
                <td className="p-2">
                  {leg.dst_ip}:{leg.dst_port}
                </td>
                <td className="p-2">
                  {leg.packet_count}
                </td>
                <td className="p-2">
                  {leg.jitter_ms} ms
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

    </div>
  </div>
);
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="border rounded-md p-4">
      <div className="text-xs text-gray-500">{label}</div>
      <div className="text-xl font-semibold">{value}</div>
    </div>
  );
}
