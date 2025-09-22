import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { HardDrive, Usb } from "lucide-react";
import RiskGauge from "@/components/charts/RiskGauge";

interface Device {
  device?: string;
  mountpoint: string;
  total: number;
  free: number;
  analysis: {
    risk_score: number;
    files: { file: string; risk: string }[];
  };
  health: number;
}

const DeviceScanner = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [system, setSystem] = useState<Device | null>(null);
  const [scanning, setScanning] = useState(false);

  const fetchDevices = async () => {
    setScanning(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/devices");
      const data = await res.json();
      setDevices(data.devices || []);
    } catch (err) {
      console.error("Error fetching devices:", err);
    } finally {
      setScanning(false);
    }
  };

  const fetchSystem = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/system-analysis");
      const data = await res.json();
      setSystem(data.system);
    } catch (err) {
      console.error("Error fetching system analysis:", err);
    }
  };

  useEffect(() => {
    fetchSystem();
  }, []);

  return (
    <div className="p-6">
      <h2 className="text-2xl font-bold mb-6">Device Detection & Risk Analysis</h2>

      <Button onClick={fetchDevices} disabled={scanning} className="mr-4">
        {scanning ? "Scanning..." : "Detect USB Devices"}
      </Button>

      {/* ✅ System (Laptop Storage) Card */}
      {system && (
        <Card className="p-4 bg-gray-900 text-white rounded-xl shadow mt-6">
          <div className="flex items-center space-x-3 mb-2">
            <HardDrive className="text-green-400" />
            <h3 className="text-lg font-semibold">Laptop Storage</h3>
          </div>
          <p>Mountpoint: {system.mountpoint}</p>
          <p>
            Total: {(system.total / (1024 * 1024 * 1024)).toFixed(2)} GB | Free:{" "}
            {(system.free / (1024 * 1024 * 1024)).toFixed(2)} GB
          </p>
          <p>Health: {system.health}%</p>
          <div className="mt-3">
            <RiskGauge score={system.analysis.risk_score} />
          </div>
        </Card>
      )}

      {/* ✅ USB Devices */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6">
        {devices.map((d, idx) => (
          <Card
            key={idx}
            className="p-4 bg-gray-900 text-white rounded-xl shadow hover:shadow-lg transition"
          >
            <div className="flex items-center space-x-3 mb-2">
              <Usb className="text-blue-400" />
              <h3 className="text-lg font-semibold">{d.device || "USB Device"}</h3>
            </div>
            <p>Mountpoint: {d.mountpoint}</p>
            <p>
              Total: {(d.total / (1024 * 1024 * 1024)).toFixed(2)} GB | Free:{" "}
              {(d.free / (1024 * 1024 * 1024)).toFixed(2)} GB
            </p>
            <p>Health: {d.health}%</p>
            <div className="mt-3">
              <RiskGauge score={d.analysis.risk_score} />
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
};

export default DeviceScanner;
