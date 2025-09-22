import React, { useState, useEffect } from "react";

interface WipeRecord {
  id: string;
  device: string;
  method: string;
  date: string;
  status: string;
}

const ComplianceDashboard: React.FC = () => {
  const [records, setRecords] = useState<WipeRecord[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchRecords = async () => {
    setLoading(true);
    try {
      const response = await fetch("http://127.0.0.1:8000/api/certificates");
      const data = await response.json();
      setRecords(data || []);
    } catch (error) {
      console.error("Error fetching certificates:", error);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchRecords();
  }, []);

  const getComplianceBadge = (method: string) => {
    if (method.includes("3-pass")) {
      return (
        <span className="px-3 py-1 rounded-lg text-sm font-semibold bg-green-500 text-white shadow">
          ✅ DoD Compliant
        </span>
      );
    }
    return (
      <span className="px-3 py-1 rounded-lg text-sm font-semibold bg-yellow-400 text-black shadow">
        ⚠️ Standard Wipe
      </span>
    );
  };

  return (
    <div className="p-6 text-white">
      <h1 className="text-3xl font-bold mb-6 text-cyan-400">
        Compliance Dashboard
      </h1>

      {loading && <p className="text-gray-400">Loading certificates...</p>}

      {!loading && records.length === 0 && (
        <p className="text-gray-400">No certificates available.</p>
      )}

      <div className="space-y-6">
        {records.map((rec) => (
          <div
            key={rec.id}
            className="relative p-6 bg-gray-800 rounded-2xl shadow-xl border-l-4 border-cyan-500 hover:shadow-cyan-500/40 transition"
          >
            <h2 className="text-xl font-semibold text-white mb-2">
              {rec.device}
            </h2>
            <p className="text-gray-400 text-sm">
              <strong>Date:</strong>{" "}
              {new Date(rec.date).toLocaleString()}
            </p>
            <p className="text-gray-400 text-sm">
              <strong>Status:</strong>{" "}
              <span
                className={
                  rec.status === "VALID" ? "text-green-400" : "text-red-400"
                }
              >
                {rec.status}
              </span>
            </p>
            <div className="mt-3">{getComplianceBadge(rec.method)}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ComplianceDashboard;
