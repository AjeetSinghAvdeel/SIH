import React from "react";

interface RiskGaugeProps {
  score: number; // 0-100
}

const RiskGauge: React.FC<RiskGaugeProps> = ({ score }) => {
  const circumference = 2 * Math.PI * 45; // radius = 45
  const offset = circumference - (score / 100) * circumference;
  const color =
    score < 40 ? "#22c55e" : score < 70 ? "#f59e0b" : "#ef4444"; // green, orange, red

  return (
    <div className="flex flex-col items-center">
      <svg width="120" height="120">
        {/* Background circle */}
        <circle
          cx="60"
          cy="60"
          r="45"
          stroke="#e5e7eb"
          strokeWidth="10"
          fill="transparent"
        />
        {/* Progress circle */}
        <circle
          cx="60"
          cy="60"
          r="45"
          stroke={color}
          strokeWidth="10"
          fill="transparent"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 60 60)"
        />
        {/* Text */}
        <text
          x="60"
          y="65"
          textAnchor="middle"
          fontSize="18"
          fontWeight="bold"
          fill={color}
        >
          {score}%
        </text>
      </svg>
      <p className="mt-2 font-semibold">{score}% Health</p>
    </div>
  );
};

export default RiskGauge;
