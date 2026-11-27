/**
 * ScanPipelineContext
 * -------------------
 * Global state shared across the guided pipeline:
 *   Import Project → Code Scanner → Attack Surface → Vulnerability Validation
 *   → AI Security Assistant → (Yes: Remediation Center | No: Reports)
 */
import React, { createContext, useContext, useState } from 'react'
import type { ScanJob, Vulnerability } from '../types'

export type PipelineStage =
  | 'import'          // Import Project page
  | 'code-scanning'   // uploading + scanning
  | 'code-done'       // Code Scanner results ready
  | 'attack-surface'  // Attack surface analysis
  | 'validation'      // Vulnerability Validation
  | 'ai-explain'      // AI Security Assistant explain findings
  | 'fix-prompt'      // "Do you want to fix?" dialog
  | 'remediation'     // Remediation Center (Yes chosen)
  | 'reports'         // Reports (No chosen OR after remediation)

export interface ScanPipelineState {
  stage: PipelineStage
  scanJob: ScanJob | null
  vulnerabilities: Vulnerability[]
  scanJobId: string | null
  projectName: string
  setStage: (s: PipelineStage) => void
  setScanJob: (job: ScanJob | null) => void
  setVulnerabilities: (v: Vulnerability[]) => void
  setScanJobId: (id: string | null) => void
  setProjectName: (n: string) => void
  reset: () => void
}

const ScanPipelineContext = createContext<ScanPipelineState | null>(null)

export const ScanPipelineProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [stage, setStage] = useState<PipelineStage>('import')
  const [scanJob, setScanJob] = useState<ScanJob | null>(null)
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [scanJobId, setScanJobId] = useState<string | null>(null)
  const [projectName, setProjectName] = useState<string>('Web Project')

  const reset = () => {
    setStage('import')
    setScanJob(null)
    setVulnerabilities([])
    setScanJobId(null)
    setProjectName('Web Project')
  }

  return (
    <ScanPipelineContext.Provider
      value={{
        stage,
        scanJob,
        vulnerabilities,
        scanJobId,
        projectName,
        setStage,
        setScanJob,
        setVulnerabilities,
        setScanJobId,
        setProjectName,
        reset,
      }}
    >
      {children}
    </ScanPipelineContext.Provider>
  )
}

export const useScanPipeline = (): ScanPipelineState => {
  const ctx = useContext(ScanPipelineContext)
  if (!ctx) throw new Error('useScanPipeline must be used inside ScanPipelineProvider')
  return ctx
}
