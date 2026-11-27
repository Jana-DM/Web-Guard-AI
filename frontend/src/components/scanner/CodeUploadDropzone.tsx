import React, { useRef, useState } from 'react'
import { FileArchive, FileCode2, FolderOpen, ShieldAlert, UploadCloud } from 'lucide-react'

const WEB_EXTENSIONS = new Set([
  '.html',
  '.htm',
  '.css',
  '.scss',
  '.sass',
  '.less',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.py',
  '.php',
  '.vue',
  '.svelte',
  '.astro',
  '.ejs',
  '.hbs',
  '.pug',
  '.jsp',
  '.asp',
  '.aspx',
  '.sql',
  '.graphql',
  '.gql',
  '.zip',
])

const WEB_MANIFESTS = new Set([
  'requirements.txt',
  'pyproject.toml',
  'package.json',
  'package-lock.json',
  'composer.json',
])

const IMAGE_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.bmp',
  '.ico',
  '.tiff',
  '.tif',
  '.heic',
  '.avif',
  '.psd',
  '.raw',
  '.svg',
])
const VIDEO_EXTENSIONS = new Set(['.mp4', '.mkv', '.avi', '.mov', '.wmv', '.webm', '.flv', '.m4v', '.3gp'])
const AUDIO_EXTENSIONS = new Set(['.mp3', '.wav', '.flac', '.aac', '.ogg', '.m4a', '.wma'])
const DOCUMENT_EXTENSIONS = new Set(['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.csv', '.rtf'])

const IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  '.venv',
  'venv',
  'env',
  '__pycache__',
  'dist',
  'build',
  '.next',
  'site-packages',
  '.pytest_cache',
  '.mypy_cache',
  '.tox',
  'coverage',
])

const SENSITIVE_DIR_NAMES = new Set([
  '.ssh',
  '.gnupg',
  '.aws',
  '.azure',
  '.gcp',
  '.kube',
  '.pki',
  'secrets',
  'private',
  'credentials',
  'certs',
  'ssl',
  'keys',
  'tokens',
])

const SENSITIVE_FILENAMES = new Set([
  '.env',
  'id_rsa',
  'id_ed25519',
  'id_dsa',
  'id_ecdsa',
  '.htpasswd',
  '.netrc',
  '.npmrc',
  '.pypirc',
  '.pgpass',
  'kubeconfig',
  'wallet.dat',
  'terraform.tfstate',
  'terraform.tfvars',
  'credentials.json',
  'secrets.json',
  'secrets.yaml',
  'secrets.yml',
  '.secrets',
  'vault.yml',
  'vault.yaml',
])

const SENSITIVE_EXTENSIONS = new Set([
  '.pem',
  '.key',
  '.p12',
  '.pfx',
  '.jks',
  '.keystore',
  '.ppk',
  '.kdbx',
  '.db',
  '.sqlite',
  '.sqlite3',
  '.bak',
  '.tfvars',
  '.tfstate',
])

const WEB_SNIPPET_REGEX = /<!doctype\s+html|<html\b|<script\b|<form\b|<\?php\b|<iframe\b|@import\s+url\(/i

function isIgnoredSegment(seg: string): boolean {
  return IGNORED_DIRS.has(seg) || seg.startsWith('.venv') || seg.startsWith('venv')
}

function getRelPath(file: File): string {
  return ((file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name).replace(/\\/g, '/')
}

/**
 * Inspect path/filename ONLY — never reads file bytes for sensitive items.
 */
function checkSensitivePath(relPath: string): string | null {
  const parts = relPath.split('/').filter((p) => p && p !== '.')
  if (parts.length === 0) return null

  for (let i = 0; i < parts.length - 1; i++) {
    if (SENSITIVE_DIR_NAMES.has(parts[i].toLowerCase())) {
      return `${parts.slice(0, i + 1).join('/')}/`
    }
  }

  const fname = parts[parts.length - 1].toLowerCase()
  if (fname.endsWith('.example') || fname.endsWith('.sample') || fname.endsWith('.template')) {
    return null
  }
  if (SENSITIVE_DIR_NAMES.has(fname)) return `${relPath}/`
  if (fname === '.env' || fname.startsWith('.env.')) return relPath
  if (SENSITIVE_FILENAMES.has(fname)) return relPath
  if ((fname.includes('service_account') || fname.includes('service-account')) && fname.endsWith('.json')) {
    return relPath
  }

  const dotIdx = fname.lastIndexOf('.')
  if (dotIdx !== -1 && SENSITIVE_EXTENSIONS.has(fname.slice(dotIdx))) {
    return relPath
  }
  return null
}

function classifyExtension(filename: string): 'web' | 'text' | 'images' | 'videos' | 'audio' | 'documents' | 'other' {
  const low = filename.toLowerCase()
  if (WEB_MANIFESTS.has(low)) return 'web'
  const dotIdx = low.lastIndexOf('.')
  const ext = dotIdx !== -1 ? low.slice(dotIdx) : ''
  if (WEB_EXTENSIONS.has(ext)) return 'web'
  if (ext === '.txt') return 'text'
  if (IMAGE_EXTENSIONS.has(ext)) return 'images'
  if (VIDEO_EXTENSIONS.has(ext)) return 'videos'
  if (AUDIO_EXTENSIONS.has(ext)) return 'audio'
  if (DOCUMENT_EXTENSIONS.has(ext)) return 'documents'
  return 'other'
}

export interface UploadMetadata {
  skippedSensitive: string[]
  skippedNonWeb: Record<string, number>
}

export const CodeUploadDropzone: React.FC<{
  onUpload: (files: File[], metadata: UploadMetadata) => Promise<void>
  onValidationError?: (message: string) => void
  loading: boolean
  progressText?: string | null
}> = ({ onUpload, onValidationError, loading, progressText }) => {
  const folderInputRef = useRef<HTMLInputElement | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const [selectedLabel, setSelectedLabel] = useState<string | null>(null)
  const [selectedNames, setSelectedNames] = useState<string[]>([])
  const [sensitiveFound, setSensitiveFound] = useState<string[]>([])

  const handleFiles = async (fileList: FileList | null, isFolder: boolean) => {
    if (!fileList || fileList.length === 0) return

    const allFiles = Array.from(fileList)
    const webFiles: File[] = []
    const sensitiveSet = new Set<string>()
    const skippedNonWeb: Record<string, number> = {}

    const bumpNonWeb = (cat: string) => {
      skippedNonWeb[cat] = (skippedNonWeb[cat] || 0) + 1
    }

    for (const file of allFiles) {
      const relPath = getRelPath(file)
      const parts = relPath.split('/')
      if (isFolder && parts.slice(0, -1).some(isIgnoredSegment)) {
        continue
      }

      // 1. Sensitive check BEFORE ever reading or uploading bytes
      const sensitiveLabel = checkSensitivePath(relPath)
      if (sensitiveLabel) {
        sensitiveSet.add(sensitiveLabel)
        continue
      }

      // 2. Classify non-sensitive file
      const kind = classifyExtension(file.name)
      if (kind === 'web') {
        webFiles.push(file)
      } else if (kind === 'text') {
        // Inspect non-sensitive .txt snippet to reject plain text vs web markup
        const head = await file.slice(0, 16384).text()
        if (WEB_SNIPPET_REGEX.test(head)) {
          webFiles.push(file)
        } else {
          bumpNonWeb('plain_text')
        }
      } else {
        bumpNonWeb(kind)
      }
    }

    const skippedSensitive = Array.from(sensitiveSet)
    setSensitiveFound(skippedSensitive)

    if (webFiles.length === 0) {
      const breakdown = Object.entries(skippedNonWeb)
        .filter(([, cnt]) => cnt > 0)
        .map(([cat, cnt]) => `${cnt} ${cat.replace('_', ' ')}`)
        .join(', ')

      let errMsg = 'Invalid target: No web or source code files found to scan.'
      if (breakdown) {
        errMsg += ` Found only non-web files (${breakdown}).`
      }
      errMsg += ' Please select web files such as HTML, CSS, JavaScript, TypeScript, Python, PHP, or a ZIP archive.'
      if (skippedSensitive.length > 0) {
        const preview = skippedSensitive.slice(0, 8).join(', ')
        const extra = skippedSensitive.length > 8 ? ` (+${skippedSensitive.length - 8} more)` : ''
        errMsg += ` Sensitive file(s)/folder(s) were detected and NOT inspected or saved: ${preview}${extra}.`
      }
      setSelectedLabel(null)
      setSelectedNames([])
      onValidationError?.(errMsg)
      return
    }

    const firstRel = getRelPath(webFiles[0])
    const folderName = isFolder && firstRel.includes('/') ? firstRel.split('/')[0] : null
    setSelectedLabel(folderName ? `${folderName} (${webFiles.length} web files)` : `${webFiles.length} item(s)`)
    setSelectedNames(webFiles.map(getRelPath))

    await onUpload(webFiles, { skippedSensitive, skippedNonWeb })
  }

  return (
    <div className="space-y-4">
      <input
        ref={folderInputRef}
        type="file"
        multiple
        className="hidden"
        {...({ webkitdirectory: '', directory: '' } as React.InputHTMLAttributes<HTMLInputElement>)}
        onChange={(e) => {
          void handleFiles(e.target.files, true)
          e.target.value = ''
        }}
      />

      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept=".html,.htm,.css,.scss,.sass,.less,.py,.js,.jsx,.mjs,.cjs,.ts,.tsx,.php,.vue,.svelte,.sql,.zip,.json,.txt,.toml"
        className="hidden"
        onChange={(e) => {
          void handleFiles(e.target.files, false)
          e.target.value = ''
        }}
      />

      <div
        onClick={() => !loading && folderInputRef.current?.click()}
        className="border-2 border-dashed border-slate-700 hover:border-cyan-500/70 rounded-xl p-8 text-center cursor-pointer transition-colors bg-[#060a13]/70"
      >
        <FolderOpen className="w-11 h-11 text-cyan-400 mx-auto mb-3" />
        <p className="text-base font-semibold text-slate-100">
          {loading
            ? progressText || 'Validating content & running static security analysis...'
            : 'Click to Choose Any Folder from Your Device'}
        </p>
        <p className="text-xs text-slate-400 mt-1.5">
          Validates web files (HTML, CSS, JS, TS, Python, PHP) first — rejects media-only folders &amp; skips sensitive files without reading or saving them.
        </p>

        <div className="mt-5 flex flex-wrap items-center justify-center gap-3">
          <button
            type="button"
            disabled={loading}
            onClick={(e) => {
              e.stopPropagation()
              folderInputRef.current?.click()
            }}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold disabled:opacity-50"
          >
            <FolderOpen className="w-4 h-4" />
            Browse Folder
          </button>
          <button
            type="button"
            disabled={loading}
            onClick={(e) => {
              e.stopPropagation()
              fileInputRef.current?.click()
            }}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-sm font-medium disabled:opacity-50"
          >
            <FileArchive className="w-4 h-4 text-cyan-400" />
            Select Files / ZIP
          </button>
        </div>

        {sensitiveFound.length > 0 && (
          <div className="mt-5 p-3 rounded-lg bg-amber-950/40 border border-amber-500/40 text-left">
            <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>Sensitive File(s)/Folder(s) Excluded (Never Inspected or Saved):</span>
            </div>
            <p className="text-xs text-amber-200/90 mt-1 break-all">
              {sensitiveFound.slice(0, 12).join(', ')}
              {sensitiveFound.length > 12 ? ` (+${sensitiveFound.length - 12} more)` : ''}
            </p>
          </div>
        )}

        {selectedLabel && (
          <div className="mt-5 pt-4 border-t border-slate-800/80">
            <p className="text-xs font-medium text-cyan-300 mb-2 inline-flex items-center gap-1.5">
              <UploadCloud className="w-3.5 h-3.5" />
              Scanning: {selectedLabel}
            </p>
            <div className="flex flex-wrap justify-center gap-2">
              {selectedNames.slice(0, 6).map((name) => (
                <span key={name} className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 text-xs text-slate-300">
                  <FileCode2 className="w-3.5 h-3.5 text-cyan-400" />
                  {name}
                </span>
              ))}
              {selectedNames.length > 6 && (
                <span className="inline-flex items-center px-2.5 py-1 rounded bg-slate-800/70 text-xs text-slate-400">
                  +{selectedNames.length - 6} more
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
