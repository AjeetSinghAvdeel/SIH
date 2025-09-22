import { cn } from "@/lib/utils";
import { Shield, Scan, FileCheck, AlertTriangle, Settings, Activity } from "lucide-react";

interface NavigationProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
}

const Navigation = ({ activeTab, onTabChange }: NavigationProps) => {
  const tabs = [
    { id: 'scan', label: 'Device Scan', icon: Scan },
    { id: 'wipe', label: 'Secure Wipe', icon: Shield },
    { id: 'certificates', label: 'Certificates', icon: FileCheck },
    { id: 'tamper', label: 'Tamper Check', icon: AlertTriangle },
    { id: 'compliance', label: 'Compliance', icon: Activity },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <nav className="glass-card p-2">
      <div className="flex flex-col space-y-1">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={cn(
                "flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-300 text-left font-mono",
                isActive 
                  ? "bg-gradient-to-r from-primary/20 to-accent/20 text-primary border border-primary/30 glow-primary" 
                  : "text-muted-foreground hover:text-foreground hover:bg-glass/50"
              )}
            >
              <Icon className={cn("w-5 h-5", isActive && "text-primary")} />
              <span className="font-medium">{tab.label}</span>
              {isActive && (
                <div className="ml-auto w-2 h-2 bg-primary rounded-full animate-pulse-glow" />
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
};

export default Navigation;