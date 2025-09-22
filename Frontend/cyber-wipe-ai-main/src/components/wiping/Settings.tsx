import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { Shield, FileText, Lock, User, LogOut, Sun, Moon } from "lucide-react";
import { auth } from "@/firebaseConfig";
import { signOut } from "firebase/auth";

export default function Settings() {
  const [settings, setSettings] = useState({
    wipeMethod: "3-pass",
    generateCerts: true,
    includeQRCode: true,
    compliance: "NIST SP 800-88",
    tamperDetection: true,
  });

  const [darkMode, setDarkMode] = useState(true);

  // Fetch saved settings from backend
  useEffect(() => {
    fetch("http://127.0.0.1:8000/api/settings")
      .then(res => res.json())
      .then(data => setSettings(data))
      .catch(() => console.log("Using default settings"));
  }, []);

  const handleSave = async () => {
    await fetch("http://127.0.0.1:8000/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(settings),
    });
    alert("✅ Settings saved successfully!");
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      window.location.href = "/";
    } catch (error) {
      console.error("Logout failed:", error);
    }
  };

  const toggleTheme = () => {
    setDarkMode(!darkMode);
    document.documentElement.classList.toggle("dark");
  };

  return (
    <div className="p-6 space-y-6">
      <h2 className="text-2xl font-bold text-cyan-400 flex items-center gap-2">
        <Lock size={22} /> Settings
      </h2>

      {/* Profile Info */}
      <Card>
        <CardContent className="p-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <User size={20} className="text-cyan-400" />
            <p className="font-semibold">
              {auth.currentUser?.email || "Guest"}
            </p>
          </div>
          <Button
            onClick={handleLogout}
            className="bg-gradient-to-r from-red-600 to-pink-500 text-white hover:scale-105 transition flex gap-2"
          >
            <LogOut size={18} /> Logout
          </Button>
        </CardContent>
      </Card>

      {/* Theme Toggle */}
      <Card>
        <CardContent className="p-4 flex items-center justify-between">
          <div>
            <h3 className="font-semibold">Theme</h3>
            <p className="text-sm text-gray-400">Switch between light and dark mode</p>
          </div>
          <Button
            onClick={toggleTheme}
            className="flex items-center gap-2 bg-gradient-to-r from-indigo-600 to-purple-600 text-white hover:scale-105 transition"
          >
            {darkMode ? <Sun size={18} /> : <Moon size={18} />}
            Toggle Theme
          </Button>
        </CardContent>
      </Card>

      {/* Wipe Method */}
      <Card>
        <CardContent className="p-4 flex items-center justify-between">
          <div>
            <h3 className="font-semibold">Default Wipe Method</h3>
            <p className="text-sm text-gray-400">Choose the default wiping algorithm</p>
          </div>
          <Select
            value={settings.wipeMethod}
            onValueChange={(val) => setSettings({ ...settings, wipeMethod: val })}
          >
            <SelectTrigger className="w-40">
              <SelectValue placeholder="Select method" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="single-pass">Single Pass</SelectItem>
              <SelectItem value="3-pass">3-Pass</SelectItem>
              <SelectItem value="7-pass">7-Pass</SelectItem>
              <SelectItem value="crypto-erase">Cryptographic Erase</SelectItem>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      {/* Certificates */}
      <Card>
        <CardContent className="p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold flex items-center gap-2"><FileText size={18}/> Auto-generate Certificates</h3>
              <p className="text-sm text-gray-400">Automatically generate PDF certificates after wiping</p>
            </div>
            <Switch
              checked={settings.generateCerts}
              onCheckedChange={(val) => setSettings({ ...settings, generateCerts: val })}
            />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold">Include QR Code</h3>
              <p className="text-sm text-gray-400">Attach QR code for verification</p>
            </div>
            <Switch
              checked={settings.includeQRCode}
              onCheckedChange={(val) => setSettings({ ...settings, includeQRCode: val })}
            />
          </div>
        </CardContent>
      </Card>

      {/* Compliance */}
      <Card>
        <CardContent className="p-4 flex items-center justify-between">
          <div>
            <h3 className="font-semibold">Compliance Standard</h3>
            <p className="text-sm text-gray-400">Choose regulation to enforce</p>
          </div>
          <Select
            value={settings.compliance}
            onValueChange={(val) => setSettings({ ...settings, compliance: val })}
          >
            <SelectTrigger className="w-56">
              <SelectValue placeholder="Select compliance" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="NIST SP 800-88">NIST SP 800-88</SelectItem>
              <SelectItem value="DoD 5220.22-M">DoD 5220.22-M</SelectItem>
              <SelectItem value="GDPR">GDPR Article 17</SelectItem>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      {/* Tamper Detection */}
      <Card>
        <CardContent className="p-4 flex items-center justify-between">
          <div>
            <h3 className="font-semibold flex items-center gap-2"><Shield size={18}/> Tamper Detection</h3>
            <p className="text-sm text-gray-400">Enable AI-powered certificate tamper detection</p>
          </div>
          <Switch
            checked={settings.tamperDetection}
            onCheckedChange={(val) => setSettings({ ...settings, tamperDetection: val })}
          />
        </CardContent>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button onClick={handleSave}>Save Settings</Button>
      </div>
    </div>
  );
}
