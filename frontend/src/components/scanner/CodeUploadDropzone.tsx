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

/**
 * Recursively read all files from a dropped directory entry (supporting Chrome, Edge, Firefox).
 */
async function readFileSystemEntry(entry: any, basePath = ''): Promise<File[]> {
  if (entry.isFile) {
    return new Promise((resolve) => {
      entry.file((file: File) => {
        const fullRel = basePath ? `${basePath}/${file.name}` : file.name
        try {
          Object.defineProperty(file, 'webkitRelativePath', {
            value: fullRel,
            writable: true,
          })
        } catch {
          // fallback if property define fails
        }
        resolve([file])
      }, () => resolve([]))
    })
  } else if (entry.isDirectory) {
    const dirReader = entry.createReader()
    const collected: any[] = []

    const readBatch = async (): Promise<any[]> => {
      const batch: any[] = await new Promise((resolve) => {
        dirReader.readEntries(resolve, () => resolve([]))
      })
      if (batch.length > 0) {
        collected.push(...batch)
        return readBatch()
      }
      return collected
    }

    const allEntries = await readBatch()
    const nextPath = basePath ? `${basePath}/${entry.name}` : entry.name
    const results = await Promise.all(
      allEntries.map((subEntry) => readFileSystemEntry(subEntry, nextPath))
    )
    return results.flat()
  }
  return []
}

export const CodeUploadDropzone: React.FC<{
  onUpload: (files: File[]) => Promise<void>
  onValidationError?: (message: string) => void
  loading: boolean
  progressText?: string | null
}> = ({ onUpload, onValidationError, loading, progressText }) => {
  const folderInputRef = useRef<HTMLInputElement | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [selectedLabel, setSelectedLabel] = useState<string | null>(null)
  const [selectedNames, setSelectedNames] = useState<string[]>([])
  const [excludedCount, setExcludedCount] = useState<number>(0)

  const processFiles = async (allFiles: File[], isFolder: boolean) => {
    if (allFiles.length === 0) return

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
        `Dropped folder contains ${allFiles.length} files, but none are web development source or configuration files (HTML, CSS, JS, TS, Python, PHP, .env, etc.). Non-code files (${excluded}) were skipped.`
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

  // Handle Drag & Drop of Folders or Files
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (!loading) setIsDragging(true)
  }

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
    if (loading) return

    const items = e.dataTransfer.items
    if (items && items.length > 0) {
      const extractedFiles: File[] = []
      let containsDirectory = false

      for (let i = 0; i < items.length; i++) {
        const item = items[i]
        const entry = (item as any).webkitGetAsEntry?.()
        if (entry) {
          if (entry.isDirectory) {
            containsDirectory = true
          }
          const files = await readFileSystemEntry(entry)
          extractedFiles.push(...files)
        }
      }

      if (extractedFiles.length > 0) {
        await processFiles(extractedFiles, containsDirectory)
        return
      }
    }

    // Fallback to standard files list
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await processFiles(Array.from(e.dataTransfer.files), false)
    }
  }

  return (
    <div className="space-y-4">
      {/* Hidden Native Folder Picker */}
      <input
        ref={folderInputRef}
        type="file"
        multiple
        className="hidden"
        {...({ webkitdirectory: '', directory: '' } as React.InputHTMLAttributes<HTMLInputElement>)}
        onChange={(e) => {
          if (e.target.files) void processFiles(Array.from(e.target.files), true)
          e.target.value = ''
        }}
      />

      {/* Hidden Native File / ZIP Picker */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept=".html,.htm,.css,.scss,.sass,.less,.py,.js,.jsx,.mjs,.cjs,.ts,.tsx,.php,.vue,.svelte,.sql,.zip,.json,.txt,.toml,.env,.env.*,.gitignore"
        className="hidden"
        onChange={(e) => {
          if (e.target.files) void processFiles(Array.from(e.target.files), false)
          e.target.value = ''
        }}
      />

      {/* Drag & Drop Zone */}
      <div
        onDragOver={handleDragOver}
        onDragEnter={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => !loading && folderInputRef.current?.click()}
        className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
          isDragging
            ? 'border-cyan-400 bg-cyan-950/40 scale-[1.01] shadow-2xl shadow-cyan-500/20 ring-4 ring-cyan-500/30'
            : 'border-slate-700 hover:border-cyan-500/70 bg-[#060a13]/70'
        }`}
      >
        <div className={`transition-transform duration-200 ${isDragging ? 'scale-110' : ''}`}>
          <FolderOpen className={`w-12 h-12 mx-auto mb-3 ${isDragging ? 'text-cyan-300 animate-bounce' : 'text-cyan-400'}`} />
        </div>

        <p className="text-base font-semibold text-slate-100">
          {isDragging
            ? 'Release to Drop Folder or Files Here!'
            : loading
            ? progressText || 'Validating project technologies & scanning for security vulnerabilities...'
            : 'Drag & Drop Folder Here, or Click to Browse'}
        </p>

        <p className="text-xs text-slate-400 mt-1.5 max-w-xl mx-auto leading-relaxed">
          Drag and drop any website project folder directly from your computer (e.g. Elite Drone). All subfolders, code, and .env files will be scanned automatically.
        </p>

        <div className="mt-5 flex flex-wrap items-center justify-center gap-3">
          <button
            type="button"
            disabled={loading}
            onClick={(e) => {
              e.stopPropagation()
              folderInputRef.current?.click()
            }}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold disabled:opacity-50 transition-colors shadow-md"
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
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-sm font-medium disabled:opacity-50 transition-colors"
          >
            <FileArchive className="w-4 h-4 text-cyan-400" />
            Select Files or ZIP
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
