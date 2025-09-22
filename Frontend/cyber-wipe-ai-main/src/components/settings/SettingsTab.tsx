import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { auth } from "@/firebaseConfig";
import { updateProfile, updatePassword, signOut } from "firebase/auth";

const Settings = () => {
  const user = auth.currentUser;
  const [displayName, setDisplayName] = useState(user?.displayName || "");
  const [theme, setTheme] = useState(localStorage.getItem("theme") || "dark");
  const [newPassword, setNewPassword] = useState("");

  // Apply theme on load/change
  useEffect(() => {
    if (theme === "system") {
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      document.documentElement.classList.remove("light", "dark");
      document.documentElement.classList.add(prefersDark ? "dark" : "light");
    } else {
      document.documentElement.classList.remove("light", "dark");
      document.documentElement.classList.add(theme);
    }
    localStorage.setItem("theme", theme);
  }, [theme]);

  const handleSaveProfile = async () => {
    if (user) {
      try {
        await updateProfile(user, { displayName });
        alert("Profile updated!");
      } catch (err) {
        console.error(err);
        alert("Error updating profile");
      }
    }
  };

  const handleChangePassword = async () => {
    if (user && newPassword.length >= 6) {
      try {
        await updatePassword(user, newPassword);
        alert("Password changed successfully!");
        setNewPassword("");
      } catch (err) {
        console.error(err);
        alert("Error updating password: re-login may be required.");
      }
    } else {
      alert("Password must be at least 6 characters.");
    }
  };

  const handleExportData = () => {
    const data = {
      email: user?.email,
      displayName: user?.displayName,
      theme,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "userdata.json";
    link.click();
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      window.location.href = "/login"; // redirect after logout
    } catch (error) {
      console.error("Logout failed:", error);
      alert("Logout failed. Try again.");
    }
  };

  return (
    <div className="space-y-6 p-6">
      {/* Profile */}
      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="block text-sm font-medium">Display Name</label>
            <Input
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
          </div>
          <p className="text-muted-foreground text-sm">Email: {user?.email}</p>
          <Button
            onClick={handleSaveProfile}
            className="bg-purple-500 hover:bg-purple-600"
          >
            Save Changes
          </Button>
        </CardContent>
      </Card>

      {/* Security */}
      <Card>
        <CardHeader>
          <CardTitle>Security</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="block text-sm font-medium">New Password</label>
            <Input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </div>
          <Button
            onClick={handleChangePassword}
            className="bg-purple-500 hover:bg-purple-600"
          >
            Change Password
          </Button>
        </CardContent>
      </Card>

      {/* Appearance */}
      <Card>
        <CardHeader>
          <CardTitle>Appearance</CardTitle>
        </CardHeader>
        <CardContent>
          <Select value={theme} onValueChange={setTheme}>
            <SelectTrigger>
              <SelectValue placeholder="Select theme" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="light">🌞 Light</SelectItem>
              <SelectItem value="dark">🌙 Dark</SelectItem>
              <SelectItem value="system">🖥️ System</SelectItem>
            </SelectContent>
          </Select>
        </CardContent>
      </Card>

      {/* Notifications */}
      <Card>
        <CardHeader>
          <CardTitle>Notifications</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Coming soon: email & in-app notification preferences.
          </p>
        </CardContent>
      </Card>

      {/* Data Export */}
      <Card>
        <CardHeader>
          <CardTitle>Data & Privacy</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button variant="outline" onClick={handleExportData}>
            Export My Data
          </Button>
        </CardContent>
      </Card>

      {/* Logout */}
      <Button variant="destructive" onClick={handleLogout}>
        Logout
      </Button>
    </div>
  );
};

export default Settings;
