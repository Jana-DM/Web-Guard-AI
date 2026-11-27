import React, { useRef, useState } from 'react'
import { FileArchive, FileCode2, FolderOpen, UploadCloud } from 'lucide-react'

// Supported text, code, and configuration extensions
const CODE_AND_CONFIG_EXTENSIONS = new Set([
  '.html', '.htm',
  '.css', '.scss', '.sass', '.less',
  '.js', '.jsx', '.mjs', '.cjs',
  '.ts', '.tsx',
  '.py',
  '.php',
  '.vue',
  '.svelte',
  '.astro',
  '.ejs', '.hbs', '.pug',
  '.jsp', '.asp', '.aspx',
  '.java', '.go', '.rb',
  '.sql',
  '.graphql', '.gql',
  '.json', '.yaml', '.yml', '.toml', '.xml',
  '.txt', '.md',
  '.gitignore', '.env',
])

const KNOWN_CONFIG_NAMES = new Set([
  'package.json',
  'package-lock.json',
  'pnpm-lock.yaml',
  'yarn.lock',
  'tsconfig.json',
  'jsconfig.json',
  'composer.json',
  'requirements.txt',
  'pyproject.toml',
  'pipfile',
  'pom.xml',
  'build.gradle',
  'dockerfile',
  'docker-compose.yml',
  'docker-compose.yaml',
  '.gitignore',
  '.env',
])

const IGNORED_SYSTEM_DIRS = new Set([
  '.git',
  'node_modules',
  '.venv',
  'venv',
  'env',
  '__pycache__',
  'dist',
  'build',
  '.next',
  '.nuxt',
  'site-packages',
  '.pytest_cache',
  '.mypy_cache',
  '.tox',
  'coverage',
])

function isIgnoredSystemSegment(seg: string): boolean {
  return IGNORED_SYSTEM_DIRS.has(seg) || seg.startsWith('.venv') || seg.startsWith('venv')
}

function getRelPath(file: File): string {
  return ((file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name).replace(/\\/g, '/')
}

function isScannableSourceOrConfig(file: File): boolean {
  const lowName = file.name.toLowerCase()
  if (KNOWN_CONFIG_NAMES.has(lowName) || lowName.startsWith('.env.')) {
    return true
  }
  const dotIdx = lowName.lastIndexOf('.')
  if (dotIdx === -1) return false
  const ext = lowName.slice(dotIdx)
  return CODE_AND_CONFIG_EXTENSIONS.has(ext)
}

export const CodeUploadDropzone: React.FC<{
  onUpload: (files: File[]) => Promise<void>
  onValidationError?: (message: string) => void
  loading: boolean
  progressText?: string | null
}> = ({ onUpload, onValidationError, loading, progressText }) => {
  const folderInputRef = useRef<HTMLInputElement | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const [selectedLabel, setSelectedLabel] = useState<string | null>(null)
  const [selectedNames, setSelectedNames] = useState<string[]>([])
  const [excludedCount, setExcludedCount] = useState<number>(0)

  const handleFiles = async (fileList: FileList | null, isFolder: boolean) => {
    if (!fileList || fileList.length === 0) return

    const allFiles = Array.from(fileList)
    const scannableFiles: File[] = []
    let excluded = 0

    for (const file of allFiles) {
      const relPath = getRelPath(file)
      const parts = relPath.split('/')
      if (isFolder && parts.slice(0, -1).some(isIgnoredSystemSegment)) {
        excluded++
        continue
      }
      if (isScannableSourceOrConfig(file)) {
        scannableFiles.push(file)
      } else {
        excluded++
      }
    }

    setExcludedCount(excluded)

    if (scannableFiles.length === 0) {
      setSelectedLabel(null)
      setSelectedNames([])
      onValidationError?.(
        `Selected folder contains ${allFiles.length} files, but none are web development source or configuration files (HTML, CSS, JS, TS, Python, PHP, .env, etc.). Non-code files (${excluded}) were skipped.`
      )
      return
    }

    const firstRel = getRelPath(scannableFiles[0])
    const folderName = isFolder && firstRel.includes('/') ? firstRel.split('/')[0] : null
    const label = folderName
      ? `${folderName} (${scannableFiles.length} source/config files, ${excluded} non-code files auto-skipped)`
      : `${scannableFiles.length} source file(s)`

    setSelectedLabel(label)
    setSelectedNames(scannableFiles.map(getRelPath))

    await onUpload(scannableFiles)
  }

  return (
    <div className="space-y-4">
      {/* Native Folder Picker */}
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

      {/* Native File / ZIP Picker */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept=".html,.htm,.css,.scss,.sass,.less,.py,.js,.jsx,.mjs,.cjs,.ts,.tsx,.php,.vue,.svelte,.sql,.zip,.json,.txt,.toml,.env,.env.*,.gitignore"
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
        <FolderOpen className="w-12 h-12 text-cyan-400 mx-auto mb-3" />
        <p className="text-base font-semibold text-slate-100">
          {loading
            ? progressText || 'Validating project technologies & scanning for security vulnerabilities...'
            : 'Select or Upload Entire Website Project Folder or ZIP'}
        </p>
        <p className="text-xs text-slate-400 mt-1.5 max-w-xl mx-auto leading-relaxed">
          Accepts any website folder or project of any size. Automatically discovers all source files and .env configurations while intelligently filtering non-code binaries.
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
            Browse Project Folder
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
            Select Files or ZIP Archive
          </button>
        </div>

        {selectedLabel && (
          <div className="mt-5 pt-4 border-t border-slate-800/80">
            <p className="text-xs font-medium text-cyan-300 mb-2 inline-flex items-center gap-1.5">
              <UploadCloud className="w-3.5 h-3.5" />
              Scanning: {selectedLabel}
            </p>
            <div className="flex flex-wrap justify-center gap-2 max-h-32 overflow-y-auto">
              {selectedNames.slice(0, 8).map((name) => (
                <span key={name} className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 text-xs text-slate-300">
                  <FileCode2 className="w-3.5 h-3.5 text-cyan-400" />
                  {name}
                </span>
              ))}
              {selectedNames.length > 8 && (
                <span className="inline-flex items-center px-2.5 py-1 rounded bg-slate-800/70 text-xs text-slate-400">
                  +{selectedNames.length - 8} more files
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
