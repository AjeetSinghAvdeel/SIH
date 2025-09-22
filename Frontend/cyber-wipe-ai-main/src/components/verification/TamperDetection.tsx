import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { ShieldCheck } from "lucide-react";

export default function TamperDetection() {
  const [certId, setCertId] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleVerify = async () => {
    if (!certId.trim()) {
      setResult("⚠️ Please enter a certificate ID.");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const res = await fetch(`http://127.0.0.1:8000/tamper/verify/${certId}`);
      const data = await res.json();

      if (data.status === "verified") {
        setResult(`✅ Certificate ${certId} is authentic and not tampered.`);
      } else if (data.status === "tampered") {
        setResult(`❌ Certificate ${certId} has been tampered!`);
      } else if (data.status === "not_registered") {
        setResult(`⚠️ Certificate ${certId} is not registered in tamper DB.`);
      } else {
        setResult(`⚠️ Unknown response: ${data.status}`);
      }
    } catch (err) {
      console.error("Error verifying certificate:", err);
      setResult("⚠️ Error verifying certificate.");
    }

    setLoading(false);
  };

  return (
    <div className="p-6 text-center">
      <h2 className="text-2xl font-bold text-cyan-400 mb-6">
        🔒 Certificate Tamper Verification
      </h2>

      <div className="flex justify-center space-x-3 mb-6">
        <input
          type="text"
          value={certId}
          onChange={(e) => setCertId(e.target.value)}
          placeholder="Enter Certificate ID"
          className="px-4 py-2 rounded-lg bg-gray-800 text-white border border-gray-600 w-64 focus:outline-none focus:ring-2 focus:ring-cyan-400"
        />
        <Button
          onClick={handleVerify}
          disabled={loading}
          className="flex items-center space-x-2"
        >
          <ShieldCheck size={18} />
          <span>{loading ? "Verifying..." : "Verify"}</span>
        </Button>
      </div>

      {result && (
        <div className="mt-4 p-4 bg-gray-900 rounded-xl shadow text-gray-200">
          {result}
        </div>
      )}
    </div>
  );
}
