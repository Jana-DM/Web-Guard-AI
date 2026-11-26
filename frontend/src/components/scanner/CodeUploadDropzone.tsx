import React, { useRef, useState } from 'react'
import { FileArchive, FileCode2, FolderOpen, UploadCloud } from 'lucide-react'

const SUPPORTED_EXTENSIONS = new Set(['.py', '.js', '.jsx', '.ts', '.tsx', '.zip'])
const SUPPORTED_FILENAMES = new Set(['requirements.txt', 'package.json', 'package-lock.json', 'pyproject.toml'])
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

function isIgnoredSegment(seg: string): boolean {
  return IGNORED_DIRS.has(seg) || seg.startsWith('.venv') || seg.startsWith('venv')
}

function isScannableFile(file: File): boolean {
  const relPath = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name
  const parts = relPath.replace(/\\/g, '/').split('/')
  if (parts.slice(0, -1).some(isIgnoredSegment)) return false

  const lowerName = file.name.toLowerCase()
  if (SUPPORTED_FILENAMES.has(lowerName)) return true
  const dotIdx = lowerName.lastIndexOf('.')
  return dotIdx !== -1 && SUPPORTED_EXTENSIONS.has(lowerName.slice(dotIdx))
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

  const handleFiles = async (fileList: FileList | null, isFolder: boolean) => {
    if (!fileList || fileList.length === 0) return

    const allFiles = Array.from(fileList)
    const filtered = isFolder ? allFiles.filter(isScannableFile) : allFiles

    if (filtered.length === 0) {
      onValidationError?.(
        'No supported source files (.py, .js, .jsx, .ts, .tsx, requirements.txt, package.json) were found in the selected folder.'
      )
      return
    }

    const firstRel = (filtered[0] as File & { webkitRelativePath?: string }).webkitRelativePath
    const folderName = isFolder && firstRel ? firstRel.split('/')[0] : null
    setSelectedLabel(folderName ? `${folderName} (${filtered.length} files)` : `${filtered.length} item(s)`)
    setSelectedNames(filtered.map((f) => ((f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name)))

    await onUpload(filtered)
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
        accept=".py,.js,.jsx,.ts,.tsx,.zip,.json,.txt,.toml"
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
            ? progressText || 'Running static AST, Bandit & dependency analysis...'
            : 'Click to Choose Any Folder from Your Device'}
        </p>
        <p className="text-xs text-slate-400 mt-1.5">
          Scans all supported source files in the selected folder (no file-count cap; auto-skips node_modules, .git &amp; venv).
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

        {selectedLabel && (
          <div className="mt-5 pt-4 border-t border-slate-800/80">
            <p className="text-xs font-medium text-cyan-300 mb-2 inline-flex items-center gap-1.5">
              <UploadCloud className="w-3.5 h-3.5" />
              Selected: {selectedLabel}
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
