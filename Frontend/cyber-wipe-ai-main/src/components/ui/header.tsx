import { useEffect, useState } from "react";
import { Shield, Cpu, Wifi } from "lucide-react";

interface Status {
  cpu: number;
  memory: number;
  ai_models: boolean;
  connected: boolean;
}

const Header = () => {
  const [status, setStatus] = useState<Status>({
    cpu: 24,
    memory: 0,
    ai_models: true,
    connected: true,
  });

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch("http://localhost:8000/system-status");
        const data = await res.json();
        setStatus(data);
      } catch (err) {
        console.error("Failed to fetch status:", err);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 5000); // refresh every 5s
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="glass-card p-6 mb-6">
      <div className="flex items-center justify-between">
        {/* Left Side - Logo + Title */}
        <div className="flex items-center gap-4">
          <div className="relative">
            <Shield className="w-10 h-10 text-primary animate-pulse-glow" />
            <div className="absolute inset-0 w-10 h-10 text-primary/30 animate-ping">
              <Shield className="w-10 h-10" />
            </div>
          </div>
          <div>
            <h1 className="text-3xl font-cyber font-bold text-neon">
              SecureWipeAI
            </h1>
            <p className="text-muted-foreground font-mono text-sm">
              AI-Powered Secure Data Wiping Platform
            </p>
          </div>
        </div>

        {/* Right Side - Status */}
        <div className="flex items-center gap-6">
          {/* AI Models */}
          <div className="flex items-center gap-2 text-sm">
            <div className="status-online">
              <div
                className={`w-2 h-2 rounded-full animate-pulse ${
                  status.ai_models ? "bg-success" : "bg-destructive"
                }`}
              />
              <span>
                {status.ai_models ? "AI Models Active" : "AI Models Inactive"}
              </span>
            </div>
          </div>

          {/* CPU */}
          <div className="flex items-center gap-2 text-sm">
            <Cpu className="w-4 h-4 text-primary" />
            <span className="font-mono">CPU: {status.cpu.toFixed(1)}%</span>
          </div>

          {/* Connection */}
          <div className="flex items-center gap-2 text-sm">
            <Wifi
              className={`w-4 h-4 ${
                status.connected ? "text-success" : "text-destructive"
              }`}
            />
            <span className="font-mono">
              {status.connected ? "Connected" : "Offline"}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
