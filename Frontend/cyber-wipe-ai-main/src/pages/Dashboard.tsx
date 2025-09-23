import { useState } from "react";
import Header from "@/components/ui/header";
import Navigation from "@/components/ui/navigation";
import DeviceScanner from "@/components/scanning/DeviceScanner";
import SecureWipe from "@/components/wiping/SecureWipe";
import CertificateManager from "@/components/certificates/CertificateManager";
import TamperDetection from "@/components/verification/TamperDetection";
import ComplianceDashboard from "@/components/compliance/ComplianceDashboard";
import SettingsTab from "@/components/settings/SettingsTab"; 

import { auth, db } from "@/firebaseConfig";
import { addDoc, collection } from "firebase/firestore";

const Dashboard = () => {
  const [activeTab, setActiveTab] = useState("scan");
  const user = auth.currentUser;

  // ✅ Log wipe certificate into Firestore
  const logWipe = async (certificate: any) => {
    if (!user) return;

    try {
      await addDoc(collection(db, "users", user.uid, "wipes"), {
        createdAt: new Date(),
        date: new Date().toISOString().replace("T", " ").substring(0, 19), 
        device: certificate.device,
        method: certificate.method,
        passes: certificate.passes,
        status: certificate.status,
      });
    } catch (error) {
      console.error("Error logging wipe:", error);
    }
  };

  const renderActiveComponent = () => {
    switch (activeTab) {
      case "scan":
        return <DeviceScanner />;
      case "wipe":
        return <SecureWipe onWipeComplete={logWipe} />;
      case "certificates":
        return <CertificateManager />;
      case "tamper":
        return <TamperDetection />;
      case "compliance":
        return <ComplianceDashboard />;
      case "settings":
        return <SettingsTab />; 
      default:
        return <DeviceScanner />;
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container mx-auto px-4 py-6">
        <Header />

        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          {/* Sidebar Navigation */}
          <div className="lg:col-span-1">
            <Navigation activeTab={activeTab} onTabChange={setActiveTab} />
          </div>

          {/* Main Content */}
          <div className="lg:col-span-4">{renderActiveComponent()}</div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
