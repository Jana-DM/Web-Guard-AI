import React, { useRef, useState } from 'react'
import { FileCode2, UploadCloud } from 'lucide-react'

export const CodeUploadDropzone: React.FC<{
  onUpload: (files: FileList) => Promise<void>
  loading: boolean
}> = ({ onUpload, loading }) => {
  const fileInputRef = useRef<HTMLInputElement | null>(null)
  const [selectedNames, setSelectedNames] = useState<string[]>([])

  const handleFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return
    setSelectedNames(Array.from(files).map((f) => f.name))
    await onUpload(files)
  }

  return (
    <div
      onClick={() => fileInputRef.current?.click()}
      className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-xl p-8 text-center cursor-pointer transition-colors bg-[#060a13]/60"
    >
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept=".py,.js,.jsx,.ts,.tsx,.zip,.json,.txt,.toml"
        className="hidden"
        onChange={(e) => handleFiles(e.target.files)}
      />
      <UploadCloud className="w-10 h-10 text-cyan-400 mx-auto mb-3" />
      <p className="text-sm font-medium text-slate-200">
        {loading ? 'Running static AST, Bandit & dependency analysis...' : 'Click to upload Python / JS / TS files or a ZIP archive'}
      </p>
      <p className="text-xs text-slate-400 mt-1">
        Uploaded source code is analyzed statically and never executed.
      </p>
      {selectedNames.length > 0 && (
        <div className="mt-4 flex flex-wrap justify-center gap-2">
          {selectedNames.slice(0, 6).map((name) => (
            <span key={name} className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 text-xs text-slate-300">
              <FileCode2 className="w-3.5 h-3.5 text-cyan-400" />
              {name}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
