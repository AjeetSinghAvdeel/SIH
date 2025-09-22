import { useEffect, useState } from "react";
import { Button } from '@/components/ui/button';
import { Link } from 'react-router-dom';
import { Shield, Scan, FileCheck, AlertTriangle, Activity, Zap, Lock, Award, LogIn } from 'lucide-react';
import heroImage from '@/assets/cyber-security-hero.jpg';

const Landing = () => {
  const [stats, setStats] = useState([
    { number: "...", label: "NIST SP 800-88 Compliance" },
    { number: "...", label: "GDPR Article 17 Compliance" },
    { number: "...", label: "DoD 5220.22-M Compliance" },
    { number: "...", label: "Detected Devices" }
  ]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Fetch compliance
        const complianceRes = await fetch("http://localhost:8000/compliance");
        const compliance = await complianceRes.json();

        // Fetch devices
        const devicesRes = await fetch("http://localhost:8000/devices");
        const devicesData = await devicesRes.json();

        const deviceCount = devicesData.devices?.length || 0;
        const avgHealth = deviceCount > 0 
          ? Math.round(devicesData.devices.reduce((acc: number, d: any) => acc + d.health, 0) / deviceCount)
          : 0;

        setStats([
          { number: `${compliance.nist_sp_800_88}%`, label: "NIST SP 800-88 Compliance" },
          { number: `${compliance.gdpr_article_17}%`, label: "GDPR Article 17 Compliance" },
          { number: `${compliance.dod_5220_22m}%`, label: "DoD 5220.22-M Compliance" },
          { number: `${deviceCount} / ${avgHealth}%`, label: "Devices / Avg Health" }
        ]);
      } catch (err) {
        console.error("Error fetching landing stats:", err);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 10000); // auto-refresh every 10s
    return () => clearInterval(interval);
  }, []);

  const features = [
    {
      icon: Scan,
      title: "AI Risk Analysis",
      description: "Automatically scans connected devices and assigns risk scores based on file types and metadata."
    },
    {
      icon: Activity,
      title: "Device Health Monitoring",
      description: "SMART-based diagnostics ensure your storage devices are healthy before and after wiping."
    },
    {
      icon: Shield,
      title: "Secure Multi-Pass Wipe",
      description: "Overwrite data with single or multi-pass methods for NIST, DoD, and GDPR compliance."
    },
    {
      icon: FileCheck,
      title: "PDF Certificates",
      description: "Tamper-proof certificates generated with cryptographic signatures and full audit trail."
    },
    {
      icon: Lock,
      title: "Tamper Detection",
      description: "Digital signatures verify that certificates remain unaltered and authentic."
    },
    {
      icon: Award,
      title: "Compliance Dashboard",
      description: "Track adherence to NIST SP 800-88, GDPR Article 17, and DoD 5220.22-M."
    }
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Hero Section */}
      <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
        {/* Background Image with Overlay */}
        <div className="absolute inset-0 z-0">
          <img 
            src={heroImage} 
            alt="Cybersecurity Background" 
            className="w-full h-full object-cover opacity-20"
          />
          <div className="absolute inset-0 bg-gradient-to-br from-primary/20 via-background/80 to-accent/20" />
        </div>

        {/* Hero Content */}
        <div className="relative z-20 text-center px-6 max-w-6xl mx-auto">
          <div className="inline-flex items-center gap-2 px-6 py-3 rounded-full bg-glass/30 border border-primary/20 backdrop-blur-sm mb-8 glow-subtle">
            <Lock className="w-5 h-5 text-primary" />
            <span className="text-sm font-mono text-primary">Enterprise-Grade Security</span>
          </div>
          
          <h1 className="text-6xl md:text-8xl font-cyber font-bold mb-6 bg-gradient-to-r from-primary via-primary-glow to-accent bg-clip-text text-transparent animate-glow">
            SecureWipeAI
          </h1>
          
          <p className="text-xl md:text-2xl text-muted-foreground mb-4 font-mono">
            AI-Powered Data Wiping Platform
          </p>
          
          <p className="text-lg text-muted-foreground/80 mb-12 max-w-3xl mx-auto leading-relaxed">
            Secure, cross-platform data wiping with real-time risk analysis, device health monitoring, 
            tamper-proof certificates, and compliance checking. Trusted by enterprises, compliant with 
            NIST SP 800-88, GDPR, and DoD standards.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-6 justify-center items-center">
            <Link to="/dashboard">
              <Button size="lg" className="cyber-button glow-primary group">
                <Zap className="w-5 h-5 mr-2 group-hover:animate-pulse" />
                Launch Dashboard
              </Button>
            </Link>

            {/* 👇 New Login Button */}
            <Link to="/login">
              <Button variant="outline" size="lg" className="cyber-button-outline group">
                <LogIn className="w-5 h-5 mr-2 group-hover:animate-pulse" />
                Login
              </Button>
            </Link>
            
            <Button variant="outline" size="lg" className="cyber-button-outline">
              <FileCheck className="w-5 h-5 mr-2" />
              View Documentation
            </Button>
          </div>
        </div>
      </section>

      {/* Stats Section (Dynamic) */}
      <section className="py-20 relative">
        <div className="container mx-auto px-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <div key={index} className="text-center glass-card p-6 hover:glow-subtle transition-all duration-300">
                <div className="text-3xl md:text-4xl font-cyber font-bold text-primary mb-2 animate-count-up">
                  {stat.number}
                </div>
                <div className="text-sm text-muted-foreground font-mono">
                  {stat.label}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 relative">
        <div className="container mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-4xl md:text-5xl font-cyber font-bold mb-4 bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              Advanced Security Features
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Cutting-edge AI technology meets military-grade data sanitization standards
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => {
              const Icon = feature.icon;
              return (
                <div 
                  key={index} 
                  className="glass-card p-8 hover:glow-subtle transition-all duration-300 group cursor-pointer"
                >
                  <div className="flex items-center gap-4 mb-4">
                    <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 flex items-center justify-center group-hover:glow-primary transition-all duration-300">
                      <Icon className="w-6 h-6 text-primary" />
                    </div>
                    <h3 className="text-xl font-bold font-cyber">{feature.title}</h3>
                  </div>
                  <p className="text-muted-foreground leading-relaxed">
                    {feature.description}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 relative">
        <div className="container mx-auto px-6 text-center">
          <div className="glass-card p-12 max-w-4xl mx-auto glow-subtle">
            <h2 className="text-3xl md:text-4xl font-cyber font-bold mb-6">
              Ready to Secure Your Data?
            </h2>
            <p className="text-lg text-muted-foreground mb-8 max-w-2xl mx-auto">
              Join organizations worldwide who trust SecureWipeAI 
              for their critical data sanitization and compliance needs.
            </p>
            <Link to="/dashboard">
              <Button size="lg" className="cyber-button glow-primary">
                <Shield className="w-5 h-5 mr-2" />
                Start Secure Wiping
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-border/50">
        <div className="container mx-auto px-6 text-center">
          <div className="flex items-center justify-center gap-2 mb-4">
            <Shield className="w-6 h-6 text-primary" />
            <span className="text-xl font-cyber font-bold">SecureWipeAI</span>
          </div>
          <p className="text-muted-foreground text-sm">
            © 2025 SecureWipeAI. Enterprise-grade data security solutions.
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
