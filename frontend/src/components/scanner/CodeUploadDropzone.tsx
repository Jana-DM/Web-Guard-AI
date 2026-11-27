import React, { useRef, useState } from 'react'
import { FileArchive, FileCode2, FolderOpen, UploadCloud } from 'lucide-react'

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
    const eligibleFiles: File[] = []

    for (const file of allFiles) {
      const relPath = getRelPath(file)
      const parts = relPath.split('/')
      if (isFolder && parts.slice(0, -1).some(isIgnoredSystemSegment)) {
        continue
      }
      eligibleFiles.push(file)
    }

    if (eligibleFiles.length === 0) {
      onValidationError?.('No files found in the selected folder. Please choose a valid website project.')
      return
    }

    const firstRel = getRelPath(eligibleFiles[0])
    const folderName = isFolder && firstRel.includes('/') ? firstRel.split('/')[0] : null
    setSelectedLabel(folderName ? `${folderName} (${eligibleFiles.length} files)` : `${eligibleFiles.length} item(s)`)
    setSelectedNames(eligibleFiles.map(getRelPath))

    await onUpload(eligibleFiles)
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
          Automatically discovers all files, validates web technologies (React, Vite, Next.js, Node, Python, PHP), detects sensitive keys in .env, and audits full project security.
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
              Selected Project: {selectedLabel}
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
