import React, { useState, useEffect } from "react";

function CertificatesList() {
  const [certificates, setCertificates] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetch("http://localhost:8000/api/certificates")
      .then(res => res.json())
      .then(data => setCertificates(data));
  }, []);

  const handleVerify = async (certId) => {
    setLoading(true);
    try {
      const res = await fetch(`http://localhost:8000/tamper/verify/${certId}`);
      const data = await res.json();
      alert(`Certificate ${certId} verification: ${data.status}`);
    } catch (err) {
      console.error(err);
      alert("Error verifying certificate");
    }
    setLoading(false);
  };

  return (
    <div className="p-4">
      <h2 className="text-xl font-bold mb-4">Certificates</h2>
      {certificates.map(cert => (
        <div
          key={cert.id}
          className="p-3 border rounded-lg mb-2 flex justify-between items-center"
        >
          <div>
            <p><strong>ID:</strong> {cert.id}</p>
            <p><strong>Device:</strong> {cert.device}</p>
            <p><strong>Date:</strong> {cert.date}</p>
            <p><strong>Status:</strong> {cert.status}</p>
          </div>
          <button
            onClick={() => handleVerify(cert.id)}
            disabled={loading}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
          >
            {loading ? "Verifying..." : "Verify"}
          </button>
        </div>
      ))}
    </div>
  );
}

export default CertificatesList;
