/**
 * Import Project Page
 * -------------------
 * Step 0 of the guided pipeline.
 * User selects / drags a project folder → sees a "Start Security Scan" button
 * → pipeline kicks off automatically.
 */
import React, { useRef, useState } from 'react'
import { FolderOpen, GitBranch, Play, Shield, Upload } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { ErrorBanner } from '../../components/common/UIPrimitives'
import { useScanPipeline } from '../../contexts/ScanPipelineContext'
import { scannerApi } from '../../services/scanner/scannerApi'

// ── file helpers (same as CodeUploadDropzone) ─────────────────────────────────
const CODE_EXTS = new Set([
  '.html','.htm','.css','.scss','.sass','.less',
  '.js','.jsx','.mjs','.cjs','.ts','.tsx',
  '.py','.php','.vue','.svelte','.astro','.ejs','.hbs','.pug',
  '.jsp','.asp','.aspx','.java','.go','.rb','.sql',
  '.graphql','.gql','.json','.yaml','.yml','.toml','.xml',
  '.txt','.md','.gitignore','.env',
])
const CONFIG_NAMES = new Set([
  'package.json','package-lock.json','pnpm-lock.yaml','yarn.lock',
  'tsconfig.json','jsconfig.json','composer.json','requirements.txt',
  'pyproject.toml','pipfile','pom.xml','build.gradle',
  'dockerfile','docker-compose.yml','docker-compose.yaml',
  '.gitignore','.env',
])
const SKIP_DIRS = new Set([
  '.git','node_modules','.venv','venv','env','__pycache__',
  'dist','build','.next','.nuxt','site-packages','.pytest_cache','.mypy_cache','.tox','coverage',
])

function isSkipDir(seg: string) { return SKIP_DIRS.has(seg) || seg.startsWith('.venv') || seg.startsWith('venv') }
function getRelPath(file: File): string {
  return ((file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name).replace(/\\/g, '/')
}
function isScannable(file: File): boolean {
  const low = file.name.toLowerCase()
  if (CONFIG_NAMES.has(low) || low.startsWith('.env.')) return true
  const dot = low.lastIndexOf('.')
  return dot !== -1 && CODE_EXTS.has(low.slice(dot))
}
async function readEntry(entry: any, base = ''): Promise<File[]> {
  if (entry.isFile) {
    return new Promise(resolve =>
      entry.file((f: File) => {
        const full = base ? `${base}/${f.name}` : f.name
        try { Object.defineProperty(f, 'webkitRelativePath', { value: full, writable: true }) } catch {}
        resolve([f])
      }, () => resolve([]))
    )
  } else if (entry.isDirectory) {
    const reader = entry.createReader()
    const all: any[] = []
    const readBatch = async (): Promise<any[]> => {
      const batch: any[] = await new Promise(r => reader.readEntries(r, () => r([])))
      if (batch.length) { all.push(...batch); return readBatch() }
      return all
    }
    const entries = await readBatch()
    const nextBase = base ? `${base}/${entry.name}` : entry.name
    const nested = await Promise.all(entries.map(e => readEntry(e, nextBase)))
    return nested.flat()
  }
  return []
}

// ── component ─────────────────────────────────────────────────────────────────
export const ImportProjectPage: React.FC = () => {
  const navigate = useNavigate()
  const pipeline = useScanPipeline()

  const folderRef = useRef<HTMLInputElement | null>(null)
  const fileRef = useRef<HTMLInputElement | null>(null)

  const [isDragging, setIsDragging] = useState(false)
  const [files, setFiles] = useState<File[]>([])
  const [folderLabel, setFolderLabel] = useState<string | null>(null)
  const [excluded, setExcluded] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [scanning, setScanning] = useState(false)
  const [progressText, setProgressText] = useState<string>('')

  // github mode
  const [mode, setMode] = useState<'folder' | 'github'>('folder')
  const [repoUrl, setRepoUrl] = useState('')
  const [branch, setBranch] = useState('')

  // ── process dropped/picked files ──────────────────────────────────────────
  const processFiles = (all: File[], isFolder: boolean) => {
    const scannable: File[] = []
    let skip = 0
    for (const f of all) {
      const parts = getRelPath(f).split('/')
      if (isFolder && parts.slice(0, -1).some(isSkipDir)) { skip++; continue }
      if (isScannable(f)) scannable.push(f)
      else skip++
    }
    setExcluded(skip)
    if (!scannable.length) {
      setError(`No web source files found (${all.length} files scanned, ${skip} non-code skipped). Please select a web development project folder.`)
      setFiles([])
      setFolderLabel(null)
      return
    }
    const first = getRelPath(scannable[0])
    const folder = isFolder && first.includes('/') ? first.split('/')[0] : null
    setFolderLabel(folder
      ? `${folder}  ·  ${scannable.length} source files  ·  ${skip} non-code skipped`
      : `${scannable.length} file(s) selected`)
    setFiles(scannable)
    setError(null)
  }

  // drag handlers
  const onDragOver = (e: React.DragEvent) => { e.preventDefault(); if (!scanning) setIsDragging(true) }
  const onDragLeave = (e: React.DragEvent) => { e.preventDefault(); setIsDragging(false) }
  const onDrop = async (e: React.DragEvent) => {
    e.preventDefault(); setIsDragging(false)
    if (scanning) return
    const items = e.dataTransfer.items
    if (items?.length) {
      const all: File[] = []; let isFolder = false
      for (let i = 0; i < items.length; i++) {
        const entry = (items[i] as any).webkitGetAsEntry?.()
        if (entry) { if (entry.isDirectory) isFolder = true; all.push(...await readEntry(entry)) }
      }
      if (all.length) { processFiles(all, isFolder); return }
    }
    if (e.dataTransfer.files?.length) processFiles(Array.from(e.dataTransfer.files), false)
  }

  // ── START SCAN ──────────────────────────────────────────────────────────────
  const startScan = async () => {
    if (scanning) return
    setScanning(true)
    setError(null)
    pipeline.reset()

    try {
      let job: Awaited<ReturnType<typeof scannerApi.uploadCodeScan>> | null = null

      if (mode === 'github') {
        setProgressText('Cloning GitHub repository and validating web project...')
        pipeline.setStage('code-scanning')
        navigate('/pipeline')
        job = await scannerApi.scanGitHubRepo(repoUrl, branch || undefined)
      } else {
        pipeline.setStage('code-scanning')
        navigate('/pipeline')
        setProgressText(`Validating project (${files.length} files)...`)
        job = await scannerApi.uploadCodeScan(files, ({ uploaded, total, stage }) => {
          if (stage === 'uploading')
            setProgressText(`Uploading files: ${uploaded} / ${total}...`)
          else
            setProgressText(`Running 7-stage security audit across ${total} files...`)
        })
      }

      const summary = (job.summary || {}) as Record<string, any>
      pipeline.setScanJob(job)
      pipeline.setScanJobId(job.id)
      pipeline.setProjectName(summary.project_name || job.target_label || 'Web Project')
      pipeline.setStage('code-done')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed')
      pipeline.setStage('import')
      setScanning(false)
    }
  }

  const startGithubScan = async (e: React.FormEvent) => {
    e.preventDefault()
    await startScan()
  }

  // ── render ──────────────────────────────────────────────────────────────────
  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {error && <ErrorBanner message={error} onClose={() => setError(null)} />}

      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="w-12 h-12 rounded-xl bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center">
          <Shield className="w-6 h-6 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-slate-100">Import Project</h2>
          <p className="text-sm text-slate-400">Select your web project folder or GitHub repo — the full security pipeline runs automatically</p>
        </div>
      </div>

      {/* Pipeline Steps Preview */}
      <div className="flex items-center gap-0 overflow-x-auto pb-1">
        {[
          { n: 1, label: 'Import Project', active: true },
          { n: 2, label: 'Code Scanner' },
          { n: 3, label: 'Attack Surface' },
          { n: 4, label: 'Vuln Validation' },
          { n: 5, label: 'AI Explain' },
          { n: 6, label: 'Fix / Report' },
        ].map((s, i, arr) => (
          <React.Fragment key={s.n}>
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold shrink-0 ${s.active ? 'bg-cyan-500/20 border border-cyan-500/50 text-cyan-300' : 'text-slate-500 border border-slate-800 bg-[#060a13]'}`}>
              <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[11px] font-bold ${s.active ? 'bg-cyan-500 text-white' : 'bg-slate-800 text-slate-500'}`}>{s.n}</span>
              {s.label}
            </div>
            {i < arr.length - 1 && <div className="w-4 h-px bg-slate-700 shrink-0 mx-0.5" />}
          </React.Fragment>
        ))}
      </div>

      {/* Mode Toggle */}
      <div className="inline-flex rounded-lg border border-slate-800 bg-[#060a13] p-1">
        <button
          type="button"
          onClick={() => { setMode('folder'); setFiles([]); setFolderLabel(null); setError(null) }}
          className={`inline-flex items-center gap-1.5 px-4 py-2 rounded-md text-sm font-medium transition-colors ${mode === 'folder' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
        >
          <FolderOpen className="w-4 h-4" />
          Device Folder / Files
        </button>
        <button
          type="button"
          onClick={() => { setMode('github'); setFiles([]); setFolderLabel(null); setError(null) }}
          className={`inline-flex items-center gap-1.5 px-4 py-2 rounded-md text-sm font-medium transition-colors ${mode === 'github' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
        >
          <GitBranch className="w-4 h-4" />
          GitHub Repo
        </button>
      </div>

      {mode === 'folder' ? (
        <>
          {/* Drop Zone */}
          <div
            onDragOver={onDragOver}
            onDragEnter={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
            onClick={() => !scanning && folderRef.current?.click()}
            className={`border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all ${
              isDragging
                ? 'border-cyan-400 bg-cyan-950/40 scale-[1.01] shadow-2xl shadow-cyan-500/20 ring-4 ring-cyan-500/30'
                : files.length
                  ? 'border-emerald-500/60 bg-emerald-950/10'
                  : 'border-slate-700 hover:border-cyan-500/70 bg-[#060a13]/70'
            }`}
          >
            {/* Hidden inputs */}
            <input
              ref={folderRef}
              type="file"
              multiple
              className="hidden"
              {...({ webkitdirectory: '', directory: '' } as React.InputHTMLAttributes<HTMLInputElement>)}
              onChange={e => { if (e.target.files) processFiles(Array.from(e.target.files), true); e.target.value = '' }}
            />
            <input
              ref={fileRef}
              type="file"
              multiple
              accept=".html,.htm,.css,.scss,.sass,.less,.py,.js,.jsx,.mjs,.cjs,.ts,.tsx,.php,.vue,.svelte,.sql,.zip,.json,.txt,.toml,.env,.env.*,.gitignore"
              className="hidden"
              onChange={e => { if (e.target.files) processFiles(Array.from(e.target.files), false); e.target.value = '' }}
            />

            <div className={`transition-transform duration-200 ${isDragging ? 'scale-110' : ''}`}>
              {files.length > 0 ? (
                <div className="w-14 h-14 mx-auto mb-3 rounded-full bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center">
                  <Upload className="w-7 h-7 text-emerald-400" />
                </div>
              ) : (
                <FolderOpen className={`w-14 h-14 mx-auto mb-3 ${isDragging ? 'text-cyan-300 animate-bounce' : 'text-cyan-400/60'}`} />
              )}
            </div>

            {files.length > 0 ? (
              <>
                <p className="text-base font-semibold text-emerald-300">Project Ready to Scan!</p>
                <p className="text-sm text-slate-300 mt-1">{folderLabel}</p>
                {excluded > 0 && (
                  <p className="text-xs text-slate-500 mt-1">{excluded} non-code / system files auto-excluded</p>
                )}
                <div className="flex flex-wrap justify-center gap-1.5 mt-3 max-h-20 overflow-y-auto">
                  {files.slice(0, 6).map(f => (
                    <span key={getRelPath(f)} className="px-2 py-0.5 rounded bg-slate-800 text-xs text-cyan-300 font-mono">
                      {getRelPath(f).split('/').slice(-2).join('/')}
                    </span>
                  ))}
                  {files.length > 6 && (
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-xs text-slate-400">+{files.length - 6} more</span>
                  )}
                </div>
              </>
            ) : (
              <>
                <p className="text-base font-semibold text-slate-200">
                  {isDragging ? 'Drop Your Project Folder Here!' : 'Drag & Drop Your Project Folder'}
                </p>
                <p className="text-sm text-slate-400 mt-1 max-w-md mx-auto">
                  Drop your entire web project folder (React, Vue, Next.js, Node, Python, PHP…).
                  Non-code files and node_modules are automatically excluded.
                </p>
                <div className="mt-5 flex flex-wrap justify-center gap-3">
                  <button
                    type="button"
                    onClick={e => { e.stopPropagation(); folderRef.current?.click() }}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold shadow-md"
                  >
                    <FolderOpen className="w-4 h-4" />
                    Browse Project Folder
                  </button>
                  <button
                    type="button"
                    onClick={e => { e.stopPropagation(); fileRef.current?.click() }}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-sm font-medium"
                  >
                    Select Files or ZIP
                  </button>
                </div>
              </>
            )}
          </div>

          {/* SCAN BUTTON — appears once files selected */}
          {files.length > 0 && (
            <button
              type="button"
              onClick={startScan}
              disabled={scanning}
              className="w-full inline-flex items-center justify-center gap-3 px-6 py-4 rounded-xl bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white text-base font-bold shadow-lg shadow-cyan-500/30 disabled:opacity-60 transition-all"
            >
              <Play className="w-5 h-5" />
              {scanning ? progressText || 'Scanning...' : `Start Full Security Scan  (${files.length} files)`}
            </button>
          )}
        </>
      ) : (
        /* GitHub Mode */
        <form onSubmit={startGithubScan} className="space-y-4 bg-[#0c1322] border border-slate-800 rounded-2xl p-6">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">GitHub Repository URL</label>
            <input
              type="url"
              required
              value={repoUrl}
              onChange={e => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repository"
              className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3.5 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1.5">Branch (Optional)</label>
            <input
              type="text"
              value={branch}
              onChange={e => setBranch(e.target.value)}
              placeholder="main"
              className="w-full bg-[#060a13] border border-slate-700 rounded-lg px-3.5 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            disabled={scanning || !repoUrl.trim()}
            className="w-full inline-flex items-center justify-center gap-3 px-6 py-4 rounded-xl bg-gradient-to-r from-cyan-600 to-cyan-500 hover:from-cyan-500 hover:to-cyan-400 text-white text-base font-bold shadow-lg shadow-cyan-500/30 disabled:opacity-60"
          >
            <GitBranch className="w-5 h-5" />
            {scanning ? progressText || 'Cloning & Scanning...' : 'Clone & Start Full Security Scan'}
          </button>
        </form>
      )}
    </div>
  )
}
