import { useEffect, useRef } from 'react';
import { Chart as ChartJS, ArcElement, Tooltip } from 'chart.js';
import { Doughnut } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip);

interface RiskGaugeProps {
  score: number;
  size?: number;
}

const RiskGauge = ({ score, size = 200 }: RiskGaugeProps) => {
  const chartRef = useRef<ChartJS<"doughnut">>(null);
  
  const getRiskLevel = (score: number) => {
    if (score <= 30) return { level: 'LOW', color: '#00ff88', glow: '#00ff88' };
    if (score <= 70) return { level: 'MEDIUM', color: '#ffaa00', glow: '#ffaa00' };
    return { level: 'HIGH', color: '#ff0055', glow: '#ff0055' };
  };

  const risk = getRiskLevel(score);
  
  const data = {
    datasets: [
      {
        data: [score, 100 - score],
        backgroundColor: [
          risk.color,
          'rgba(255, 255, 255, 0.1)'
        ],
        borderWidth: 0,
        cutout: '75%',
      }
    ]
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      tooltip: {
        enabled: false,
      },
    },
    rotation: -90,
    circumference: 180,
  };

  return (
    <div className="relative flex flex-col items-center">
      <div 
        className="relative"
        style={{ width: size, height: size / 2 }}
      >
        <Doughnut ref={chartRef} data={data} options={options} />
        
        {/* Score Display */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pt-8">
          <div 
            className="text-4xl font-cyber font-bold animate-pulse-glow"
            style={{ 
              color: risk.color,
              textShadow: `0 0 20px ${risk.glow}` 
            }}
          >
            {score}
          </div>
          <div className="text-sm font-mono text-muted-foreground">
            RISK SCORE
          </div>
        </div>
      </div>
      
      {/* Risk Level Badge */}
      <div 
        className="mt-4 px-4 py-2 rounded-lg font-cyber font-bold text-sm border"
        style={{ 
          backgroundColor: `${risk.color}20`,
          borderColor: risk.color,
          color: risk.color,
          boxShadow: `0 0 20px ${risk.color}40`
        }}
      >
        {risk.level} RISK
      </div>
    </div>
  );
};

export default RiskGauge;