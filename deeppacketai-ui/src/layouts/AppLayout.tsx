import type { ReactNode } from "react";
import Sidebar from "../components/Sidebar";

interface Props {
  children: ReactNode;
  username: string;
  onLogout: () => void;
}

export default function AppLayout({ children, username, onLogout }: Props) {
  return (
    <div className="flex h-screen bg-slate-900 text-gray-100">
      {/* Sidebar */}
      <Sidebar />

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <div className="flex items-center justify-end gap-3 px-5 py-2.5 border-b border-slate-800/60 bg-slate-900/40 flex-shrink-0">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-full bg-blue-600/30 border border-blue-500/40 flex items-center justify-center">
              <span className="text-[10px] font-bold text-blue-300 uppercase">{username.slice(0, 2)}</span>
            </div>
            <span className="text-xs text-slate-400">{username}</span>
          </div>
          <button
            onClick={onLogout}
            className="text-xs text-slate-500 hover:text-slate-300 px-2.5 py-1 rounded-lg hover:bg-slate-800/60 transition-colors"
          >
            Sign out
          </button>
        </div>

        {/* Page Content */}
        <div className="flex-1 overflow-y-auto p-6 bg-slate-900">{children}</div>
      </div>
    </div>
  );
}
