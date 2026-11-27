/**
 * ScanPipelineContext
 * -------------------
 * Global state shared across the guided pipeline.
 * pendingFiles: files chosen in ImportProjectPage, consumed by PipelinePage to run the scan.
 * pendingGitHub: { url, branch } if GitHub mode.
 */
import React, { createContext, useContext, useRef, useState } from 'react'
import type { ScanJob, Vulnerability } from '../types'

export type PipelineStage =
  | 'import'          // Import Project page (default / idle)
  | 'pending-scan'    // Files ready, waiting for PipelinePage to pick up
  | 'code-scanning'   // Uploading + scanning in progress
  | 'code-done'       // Code Scanner results ready
  | 'attack-surface'  // Attack surface analysis
  | 'validation'      // Vulnerability Validation
  | 'ai-explain'      // AI Security Assistant explain findings
  | 'fix-prompt'      // "Do you want to fix?" dialog
  | 'remediation'     // Remediation Center (Yes chosen)
  | 'reports'         // Reports (No chosen OR after remediation)

export interface PendingGitHub { url: string; branch?: string }

export interface ScanPipelineState {
  stage: PipelineStage
  scanJob: ScanJob | null
  vulnerabilities: Vulnerability[]
  scanJobId: string | null
  projectName: string
  // Files stored as a ref (not state) to avoid File object serialization issues
  pendingFilesRef: React.MutableRefObject<File[]>
  pendingGitHub: PendingGitHub | null
  progressText: string
  scanError: string | null
  setStage: (s: PipelineStage) => void
  setScanJob: (job: ScanJob | null) => void
  setVulnerabilities: (v: Vulnerability[]) => void
  setScanJobId: (id: string | null) => void
  setProjectName: (n: string) => void
  setPendingGitHub: (g: PendingGitHub | null) => void
  setProgressText: (t: string) => void
  setScanError: (e: string | null) => void
  reset: () => void
}

const ScanPipelineContext = createContext<ScanPipelineState | null>(null)

export const ScanPipelineProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [stage, setStage] = useState<PipelineStage>('import')
  const [scanJob, setScanJob] = useState<ScanJob | null>(null)
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [scanJobId, setScanJobId] = useState<string | null>(null)
  const [projectName, setProjectName] = useState<string>('Web Project')
  const [pendingGitHub, setPendingGitHub] = useState<PendingGitHub | null>(null)
  const [progressText, setProgressText] = useState<string>('')
  const [scanError, setScanError] = useState<string | null>(null)

  // Files are stored in a ref (not state) so File objects aren't serialized
  const pendingFilesRef = useRef<File[]>([])

  const reset = () => {
    setStage('import')
    setScanJob(null)
    setVulnerabilities([])
    setScanJobId(null)
    setProjectName('Web Project')
    setPendingGitHub(null)
    setProgressText('')
    setScanError(null)
    pendingFilesRef.current = []
  }

  return (
    <ScanPipelineContext.Provider
      value={{
        stage,
        scanJob,
        vulnerabilities,
        scanJobId,
        projectName,
        pendingFilesRef,
        pendingGitHub,
        progressText,
        scanError,
        setStage,
        setScanJob,
        setVulnerabilities,
        setScanJobId,
        setProjectName,
        setPendingGitHub,
        setProgressText,
        setScanError,
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
