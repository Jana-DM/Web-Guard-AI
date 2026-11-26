import React from 'react'
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Card } from '../common/UIPrimitives'

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#06b6d4',
  info: '#64748b',
}

const CLASS_COLORS: Record<string, string> = {
  CONFIRMED: '#10b981',
  POTENTIAL: '#f59e0b',
  'NEEDS REVIEW': '#8b5cf6',
  'NOT REPRODUCED': '#475569',
}

export const DashboardCharts: React.FC<{
  severity: Record<string, number>
  classification: Record<string, number>
}> = ({ severity, classification }) => {
  const sevData = Object.entries(severity).map(([name, count]) => ({ name: name.toUpperCase(), key: name, count }))
  const classData = Object.entries(classification).map(([name, value]) => ({ name, value }))

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <Card title="Findings by Severity" subtitle="Live breakdown across all executed scans">
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={sevData}>
              <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} />
              <YAxis stroke="#94a3b8" fontSize={12} allowDecimals={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0c1322', borderColor: '#1e293b', color: '#e2e8f0' }}
              />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {sevData.map((entry) => (
                  <Cell key={entry.key} fill={SEV_COLORS[entry.key] || '#06b6d4'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <Card title="AI Validation Classifications" subtitle="Evidence-based false-positive filtering">
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={classData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={85} label>
                {classData.map((entry) => (
                  <Cell key={entry.name} fill={CLASS_COLORS[entry.name] || '#06b6d4'} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#0c1322', borderColor: '#1e293b', color: '#e2e8f0' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </Card>
    </div>
  )
}
