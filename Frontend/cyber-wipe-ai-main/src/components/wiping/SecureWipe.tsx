import React, { useState } from "react";
import { auth, db } from "@/firebaseConfig";
import { addDoc, collection, serverTimestamp } from "firebase/firestore";

interface Device {
  device: string;
  mountpoint: string;
  total: number;
  free: number;
  analysis: {
    risk_score: number;
    files: { file: string; risk: string }[];
  };
}

interface SecureWipeProps {
  onWipeComplete?: (certificate: any) => Promise<void>;
}

const SecureWipe: React.FC<SecureWipeProps> = ({ onWipeComplete }) => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [passes, setPasses] = useState<{ [key: string]: number }>({});
  const [certificate, setCertificate] = useState<any | null>(null);

  const detectDevices = async () => {
    setLoading(true);
    setMessage("");
    try {
      const response = await fetch("http://127.0.0.1:8000/devices");
      const data = await response.json();
      setDevices(data.devices || []);
      if (!data.devices || data.devices.length === 0) {
        setMessage("No removable devices detected.");
      }
    } catch (error) {
      console.error("Error fetching devices:", error);
      setMessage("Unable to contact backend to fetch devices.");
    }
    setLoading(false);
  };

  const wipeDevice = async (mountpoint: string) => {
    const numPasses = passes[mountpoint] || 1;
    if (
      !window.confirm(
        `⚠️ Are you sure you want to securely wipe this USB with ${numPasses}-pass overwrite? This action is irreversible.`
      )
    ) {
      return;
    }

    try {
      const response = await fetch("http://127.0.0.1:8000/wipe-usb", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mountpoint, passes: numPasses }),
      });

      const result = await response.json();
      if (result.certificate) {
        setCertificate(result.certificate);

        // ✅ Save wipe record directly if user is logged in
        const user = auth.currentUser;
        if (user) {
          await addDoc(collection(db, "users", user.uid, "wipes"), {
            device: result.certificate.device,
            method: result.certificate.method,
            date: result.certificate.date,
            status: result.certificate.status,
            passes: numPasses,
            createdAt: serverTimestamp(),
          });
        }

        // ✅ Notify Dashboard for central logging
        if (onWipeComplete) {
          await onWipeComplete(result.certificate);
        }
      }

      alert(result.message || "Wipe complete!");
    } catch (error) {
      console.error("Error wiping device:", error);
      alert("Failed to wipe device.");
    }
  };

  return (
    <div className="p-6 text-white">
      <h1 className="text-3xl font-bold mb-6 text-cyan-400">USB Secure Wipe</h1>

      {/* Detect Button */}
      <button
        onClick={detectDevices}
        disabled={loading}
        className="bg-gradient-to-r from-blue-600 to-cyan-500 text-white px-6 py-3 rounded-xl shadow-lg hover:scale-105 transition disabled:opacity-50"
      >
        {loading ? "Detecting..." : "🔍 Detect USB Devices"}
      </button>

      {message && <p className="mt-4 text-red-400">{message}</p>}

      {/* Device List */}
      <div className="mt-8 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {devices.map((dev, idx) => (
          <div
            key={idx}
            className="p-6 bg-gray-800 rounded-2xl shadow-xl hover:shadow-cyan-500/40 hover:scale-105 transition"
          >
            <h2 className="text-xl font-semibold mb-2">
              {dev.device || "USB Device"}
            </h2>
            <p className="text-gray-400 break-all">
              <strong>Mountpoint:</strong> {dev.mountpoint}
            </p>
            <p className="text-gray-400">
              <strong>Total:</strong>{" "}
              {(dev.total / (1024 * 1024 * 1024)).toFixed(2)} GB
            </p>
            <p className="text-gray-400">
              <strong>Free:</strong>{" "}
              {(dev.free / (1024 * 1024 * 1024)).toFixed(2)} GB
            </p>

            {/* Risk Analysis */}
            <div className="mt-3">
              <p>
                <strong>Risk Score:</strong>{" "}
                <span
                  className={`px-3 py-1 rounded-lg font-semibold ${
                    dev.analysis.risk_score > 70
                      ? "bg-red-500 text-white"
                      : dev.analysis.risk_score > 40
                      ? "bg-yellow-400 text-black"
                      : "bg-green-400 text-black"
                  }`}
                >
                  {dev.analysis.risk_score}/100
                </span>
              </p>

              {dev.analysis.files.length > 0 && (
                <div className="mt-2">
                  <p className="font-semibold text-gray-300">Flagged Files:</p>
                  <ul className="list-disc pl-6 text-sm space-y-1">
                    {dev.analysis.files.map((f, i) => (
                      <li
                        key={i}
                        className={`break-all ${
                          f.risk === "high"
                            ? "text-red-400"
                            : f.risk === "medium"
                            ? "text-yellow-400"
                            : "text-gray-400"
                        }`}
                      >
                        {f.file} ({f.risk})
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Pass Selection */}
            <div className="mt-4">
              <label className="block text-sm mb-1">Wipe Method:</label>
              <select
                value={passes[dev.mountpoint] || 1}
                onChange={(e) =>
                  setPasses({
                    ...passes,
                    [dev.mountpoint]: parseInt(e.target.value),
                  })
                }
                className="bg-gray-700 text-white p-2 rounded-lg"
              >
                <option value={1}>Single-pass (Fast, Standard)</option>
                <option value={3}>3-pass (DoD 5220.22-M)</option>
              </select>
            </div>

            {/* Wipe Button */}
            <button
              onClick={() => wipeDevice(dev.mountpoint)}
              className="mt-6 w-full bg-gradient-to-r from-red-600 to-pink-500 text-white px-4 py-2 rounded-xl shadow-lg hover:scale-105 transition"
            >
              🧹 Secure Wipe
            </button>
          </div>
        ))}
      </div>

      {/* Certificate Modal */}
      {certificate && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-70 z-50">
          <div className="bg-gray-900 text-white p-6 rounded-2xl shadow-2xl max-w-md w-full">
            <h2 className="text-2xl font-bold mb-4 text-cyan-400">
              ✅ Wipe Certificate
            </h2>
            <p>
              <strong>Device:</strong> {certificate.device}
            </p>
            <p>
              <strong>Method:</strong> {certificate.method}
            </p>
            <p>
              <strong>Date:</strong> {certificate.date}
            </p>
            <p>
              <strong>Status:</strong>{" "}
              <span className="text-green-400">{certificate.status}</span>
            </p>

            <button
              onClick={() => setCertificate(null)}
              className="mt-6 w-full bg-gradient-to-r from-blue-600 to-cyan-500 text-white px-4 py-2 rounded-xl shadow hover:scale-105 transition"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default SecureWipe;
