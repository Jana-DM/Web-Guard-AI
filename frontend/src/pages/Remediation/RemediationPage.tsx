import React, { useEffect, useState } from 'react'
import { Card, ErrorBanner, LoadingState } from '../../components/common/UIPrimitives'
import { DiffViewer } from '../../components/remediation/DiffViewer'
import { scannerApi } from '../../services/scanner/scannerApi'
import type { RemediationRecord } from '../../types'

export const RemediationPage: React.FC = () => {
  const [records, setRecords] = useState<RemediationRecord[]>([])
  const [verificationOutcome, setVerificationOutcome] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      setRecords(await scannerApi.listRemediations())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load remediation queue')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const handleApprove = async (id: string, approved: boolean) => {
    setError(null)
    try {
      await scannerApi.approveRemediation(id, approved)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Remediation approval failed')
    }
  }

  const handleVerify = async (id: string) => {
    setError(null)
    try {
      setVerificationOutcome(await scannerApi.verifyRemediation(id))
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed')
    }
  }

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      {verificationOutcome && (
        <Card title="Post-Remediation Verification Result">
          <pre className="bg-[#060a13] border border-emerald-500/30 rounded-lg p-3 text-xs text-emerald-300 overflow-x-auto">
            {JSON.stringify(verificationOutcome, null, 2)}
          </pre>
        </Card>
      )}

      <Card
        title="Remediation & Verification Queue"
        subtitle="Explicit approval is required before any patch is applied. Timestamped backups are created automatically."
      >
        {loading ? (
          <LoadingState />
        ) : records.length === 0 ? (
          <div className="text-sm text-slate-500 py-6">
            No remediation proposals yet. Open Vulnerability Validation and click "Generate Secure Remediation Patch" on a source-code finding.
          </div>
        ) : (
          <div className="space-y-4">
            {records.map((rec) => (
              <DiffViewer key={rec.id} record={rec} onApprove={handleApprove} onVerify={handleVerify} />
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
