import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Eye, Download, FileText, ShieldCheck } from "lucide-react";

interface Certificate {
  id: string;
  device: string;
  method: string;
  date: string;
  status: string;
}

export default function CertificateManager() {
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [selectedCert, setSelectedCert] = useState<Certificate | null>(null);
  const [verifyResult, setVerifyResult] = useState<string | null>(null);

  // Load certificates from backend
  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/certificates")
      .then((res) => res.json())
      .then((data) => setCertificates(data));
  }, []);

  // Download PDF
  const handleDownload = (id: string) => {
    window.open(
      `http://127.0.0.1:8000/api/certificates/download/${id}`,
      "_blank"
    );
  };

  // View details modal
  const handleView = (cert: Certificate) => {
    setSelectedCert(cert);
    setVerifyResult(null);
  };

  // Verify authenticity
  const handleVerify = async (cert: Certificate) => {
    try {
      const res = await fetch(
        `http://127.0.0.1:8000/tamper/verify/${cert.id}`
      );
      const result = await res.json();

      if (result.status === "verified") {
        setVerifyResult("✅ Certificate is authentic and not tampered.");
      } else if (result.status === "tampered") {
        setVerifyResult("❌ Certificate has been tampered!");

        // 🔥 Update list dynamically
        setCertificates((prev) =>
          prev.map((c) =>
            c.id === cert.id ? { ...c, status: "TAMPERED" } : c
          )
        );
      } else if (result.status === "not_registered") {
        setVerifyResult("⚠️ Certificate is not registered in tamper DB.");
      } else {
        setVerifyResult(`⚠️ ${result.status}`);
      }
    } catch (err) {
      console.error("Tamper check failed:", err);
      setVerifyResult("⚠️ Error verifying certificate.");
    }
  };

  return (
    <div className="p-6">
      <h2 className="text-2xl font-bold mb-6 text-cyan-400">
        Wipe Certificates
      </h2>
      <div className="space-y-4">
        {certificates.map((cert) => (
          <div
            key={cert.id}
            className="flex items-center justify-between bg-gray-900 rounded-xl p-4 shadow-lg"
          >
            <div className="flex items-center space-x-4">
              <FileText className="text-cyan-400" size={28} />
              <div>
                <h3 className="text-lg font-semibold">{cert.id}</h3>
                <p className="text-sm text-gray-400">
                  {cert.device} | {cert.method} | {cert.date}
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <span
                className={`px-3 py-1 rounded-full text-xs font-bold ${
                  cert.status === "VALID"
                    ? "bg-green-600 text-white"
                    : cert.status === "TAMPERED"
                    ? "bg-red-600 text-white"
                    : "bg-yellow-600 text-white"
                }`}
              >
                {cert.status}
              </span>
              <Button
                variant="secondary"
                size="icon"
                onClick={() => handleView(cert)}
              >
                <Eye size={18} />
              </Button>
              <Button
                variant="secondary"
                size="icon"
                onClick={() => handleDownload(cert.id)}
              >
                <Download size={18} />
              </Button>
              <Button
                variant="secondary"
                size="icon"
                onClick={() => handleVerify(cert)}
              >
                <ShieldCheck size={18} />
              </Button>
            </div>
          </div>
        ))}
      </div>

      {/* Certificate Details Modal */}
      {selectedCert && (
        <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50 z-50">
          <div className="bg-gray-900 p-6 rounded-xl shadow-xl w-96">
            <h3 className="text-xl font-bold text-cyan-400 mb-4">
              Certificate Details
            </h3>
            <p className="text-gray-300">
              <strong>ID:</strong> {selectedCert.id}
            </p>
            <p className="text-gray-300">
              <strong>Device:</strong> {selectedCert.device}
            </p>
            <p className="text-gray-300">
              <strong>Method:</strong> {selectedCert.method}
            </p>
            <p className="text-gray-300">
              <strong>Date:</strong> {selectedCert.date}
            </p>
            <p className="text-gray-300">
              <strong>Status:</strong> {selectedCert.status}
            </p>
            {verifyResult && (
              <p className="mt-4 font-semibold text-yellow-400">
                {verifyResult}
              </p>
            )}
            <div className="mt-6 flex justify-end space-x-3">
              <Button variant="secondary" onClick={() => setSelectedCert(null)}>
                Close
              </Button>
              <Button onClick={() => handleDownload(selectedCert.id)}>
                Download
              </Button>
              <Button onClick={() => handleVerify(selectedCert)}>
                Verify
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
