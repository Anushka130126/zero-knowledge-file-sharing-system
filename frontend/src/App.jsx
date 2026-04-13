import { useEffect, useRef, useState } from 'react'
import { encryptFile, decryptFile } from './utils/cryptoUtils'
import { embedDataInImage, extractDataFromImage } from './utils/stegoUtils'

const API_BASE_URL = 'http://localhost:8000'
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024 // 10MB

function App() {
  const [fileId, setFileId] = useState(/** @type {string | null} */ (null))

  // Sender view state
  const [secretFile, setSecretFile] = useState(/** @type {File | null} */ (null))
  const [carrierImage, setCarrierImage] = useState(/** @type {File | null} */ (null))
  const [senderStatus, setSenderStatus] = useState('')
  const [senderError, setSenderError] = useState('')
  const [shareUrl, setShareUrl] = useState(/** @type {string | null} */ (null))
  const [isSenderSubmitting, setIsSenderSubmitting] = useState(false)

  // Receiver view state
  const [keyImage, setKeyImage] = useState(/** @type {File | null} */ (null))
  const [receiverStatus, setReceiverStatus] = useState('')
  const [receiverError, setReceiverError] = useState('')
  const [isReceiverProcessing, setIsReceiverProcessing] = useState(false)

  const secretInputRef = useRef(/** @type {HTMLInputElement | null} */ (null))
  const carrierInputRef = useRef(/** @type {HTMLInputElement | null} */ (null))
  const keyImageInputRef = useRef(/** @type {HTMLInputElement | null} */ (null))

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const id = params.get('file_id')
    if (id) {
      setFileId(id)
    }
  }, [])

  const handleSecretFileSelected = (file) => {
    if (!file) return
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setSenderError('Secret file too large. Maximum allowed size is 10MB.')
      setSecretFile(null)
      return
    }
    setSenderError('')
    setSecretFile(file)
  }

  const handleCarrierImageSelected = (file) => {
    if (!file) return
    if (file.type !== 'image/png') {
      setSenderError('Carrier image must be a PNG file.')
      setCarrierImage(null)
      return
    }
    setSenderError('')
    setCarrierImage(file)
  }

  const handleKeyImageSelected = (file) => {
    if (!file) return
    if (!file.type.startsWith('image/')) {
      setReceiverError('Key image must be an image file.')
      setKeyImage(null)
      return
    }
    setReceiverError('')
    setKeyImage(file)
  }

  const handleSenderSubmit = async () => {
    if (!secretFile || !carrierImage) {
      setSenderError('Select a secret file (≤10MB) and a PNG carrier image.')
      return
    }

    setSenderError('')
    setSenderStatus('Encrypting file locally with AES-GCM 256...')
    setShareUrl(null)
    setIsSenderSubmitting(true)

    try {
      const { ciphertextBlob, exportedKey, iv } = await encryptFile(secretFile)

      setSenderStatus('Embedding key and IV into carrier image (LSB steganography)...')
      const payload = JSON.stringify({ key: exportedKey, iv })
      const stegoFile = await embedDataInImage(carrierImage, payload)

      // Trigger local download of the stego image
      const stegoUrl = URL.createObjectURL(stegoFile)
      try {
        const link = document.createElement('a')
        link.href = stegoUrl
        link.download = stegoFile.name || 'stego_image.png'
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
      } finally {
        URL.revokeObjectURL(stegoUrl)
      }

      setSenderStatus('Uploading encrypted blob to zero-knowledge backend...')

      const formData = new FormData()
      const uploadName = `${secretFile.name}.enc`
      formData.append('file', ciphertextBlob, uploadName)

      let response
      try {
        response = await fetch(`${API_BASE_URL}/api/upload`, {
          method: 'POST',
          body: formData,
        })
      } catch (networkError) {
        throw new Error(
          networkError instanceof Error
            ? `Network error while uploading encrypted blob: ${networkError.message}`
            : 'Network error while uploading encrypted blob.',
        )
      }

      if (!response.ok) {
        let message = 'Upload failed.'
        try {
          const data = await response.json()
          if (data && data.detail) {
            message = data.detail
          }
        } catch {
          // ignore JSON parse errors
        }
        throw new Error(message)
      }

      let data
      try {
        data = await response.json()
      } catch {
        throw new Error('Unexpected server response while uploading encrypted blob.')
      }

      if (!data || typeof data.file_id !== 'string') {
        throw new Error('Upload completed but file_id was not returned by the server.')
      }

      const newFileId = data.file_id
      const linkUrl = `${window.location.origin}/?file_id=${encodeURIComponent(newFileId)}`
      setShareUrl(linkUrl)

      setSenderStatus('Stego image downloaded. Share the link below with the receiver.')
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Unexpected error during sender flow.'
      setSenderError(message)
      setSenderStatus('')
    } finally {
      setIsSenderSubmitting(false)
    }
  }

  const handleReceiverSubmit = async () => {
    if (!fileId) {
      setReceiverError('Missing file identifier in URL. This secure link may be invalid.')
      return
    }
    if (!keyImage) {
      setReceiverError('Upload the key image (stego image) to proceed.')
      return
    }

    setReceiverError('')
    setReceiverStatus('Extracting key material from key image...')
    setIsReceiverProcessing(true)

    /** @type {{ key: string, iv: string } | null} */
    let extracted = null

    try {
      extracted = await extractDataFromImage(keyImage)
    } catch (extractionError) {
      // Extraction failed: trigger intruder lockout signal to backend
      try {
        await fetch(`${API_BASE_URL}/api/fail/${encodeURIComponent(fileId)}`, {
          method: 'POST',
        })
      } catch {
        // Silent failure as per requirement; do not override user-facing message
      }

      setReceiverError('Invalid Image Key. Intruder lockout active.')
      setReceiverStatus('')
      setIsReceiverProcessing(false)
      return
    }

    try {
      const { key, iv } = extracted

      setReceiverStatus('Fetching encrypted blob from zero-knowledge backend...')

      let response
      try {
        response = await fetch(
          `${API_BASE_URL}/api/download/${encodeURIComponent(fileId)}`,
        )
      } catch (networkError) {
        throw new Error(
          networkError instanceof Error
            ? `Network error while downloading encrypted blob: ${networkError.message}`
            : 'Network error while downloading encrypted blob.',
        )
      }

      if (!response.ok) {
        let message =
          'Unable to retrieve encrypted file. It may have already been burned or the link is invalid.'
        try {
          const data = await response.json()
          if (data && data.detail) {
            message = data.detail
          }
        } catch {
          // ignore JSON parse errors
        }
        throw new Error(message)
      }

      const encryptedBlob = await response.blob()

      setReceiverStatus('Decrypting file locally in your browser...')
      const decryptedBlob = await decryptFile(encryptedBlob, key, iv)

      const downloadUrl = URL.createObjectURL(decryptedBlob)
      try {
        const link = document.createElement('a')
        link.href = downloadUrl
        link.download = 'decrypted_file'
        document.body.appendChild(link)
        link.click()
        document.body.removeChild(link)
      } finally {
        URL.revokeObjectURL(downloadUrl)
      }

      setReceiverStatus(
        'File decrypted. The server has permanently burned the encrypted copy.',
      )
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'Unexpected error during receiver flow.'
      setReceiverError(message)
      setReceiverStatus('')
    } finally {
      setIsReceiverProcessing(false)
    }
  }

  const isReceiverView = Boolean(fileId)

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto flex min-h-screen max-w-4xl flex-col px-4 py-8">
        <header className="mb-8 border-b border-slate-800 pb-4">
          <div className="flex items-baseline justify-between gap-4">
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">
                Zero-Trust Secure File Sharing
              </h1>
              <p className="mt-2 text-sm text-slate-400">
                End-to-end encrypted file transfer with steganographic key delivery. The
                backend never sees your keys or plaintext.
              </p>
            </div>
            <span className="rounded-full border border-emerald-500/40 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
              {isReceiverView ? 'Receiver Mode' : 'Sender Mode'}
            </span>
          </div>
        </header>

        <main className="flex-1 space-y-6">
          {!isReceiverView && (
            <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm">
              <h2 className="text-lg font-medium text-slate-100">Sender Flow</h2>
              <p className="mt-1 text-sm text-slate-400">
                Encrypt your file locally, hide the key in a carrier image, and upload the
                ciphertext to the zero-knowledge backend.
              </p>

              <div className="mt-6 grid gap-6 md:grid-cols-2">
                <div>
                  <p className="text-sm font-medium text-slate-200">Secret File</p>
                  <p className="mt-1 text-xs text-slate-500">
                    Any file type, up to 10MB. Encrypted entirely in your browser.
                  </p>

                  <div
                    className="mt-3 flex cursor-pointer flex-col items-center justify-center rounded-md border-2 border-dashed border-slate-700 bg-slate-900/60 px-4 py-8 text-center hover:border-indigo-500 hover:bg-slate-900"
                    onClick={() => {
                      if (secretInputRef.current) secretInputRef.current.click()
                    }}
                    onDragOver={(event) => {
                      event.preventDefault()
                      event.stopPropagation()
                    }}
                    onDrop={(event) => {
                      event.preventDefault()
                      const file = event.dataTransfer.files?.[0]
                      if (file) {
                        handleSecretFileSelected(file)
                      }
                    }}
                  >
                    <span className="text-xs font-medium uppercase tracking-wide text-slate-400">
                      Drop file here or click to browse
                    </span>
                    {secretFile && (
                      <p className="mt-2 truncate text-xs text-emerald-300">
                        Selected: {secretFile.name} ({secretFile.size} bytes)
                      </p>
                    )}
                    {!secretFile && (
                      <p className="mt-2 text-xs text-slate-500">
                        We enforce a strict 10MB limit for security and stability.
                      </p>
                    )}
                  </div>

                  <input
                    ref={secretInputRef}
                    type="file"
                    className="hidden"
                    onChange={(event) => {
                      const file = event.target.files?.[0]
                      if (file) {
                        handleSecretFileSelected(file)
                      }
                    }}
                  />
                </div>

                <div>
                  <p className="text-sm font-medium text-slate-200">Carrier Image (PNG)</p>
                  <p className="mt-1 text-xs text-slate-500">
                    Lossless PNG only. The encryption key and IV are hidden in its pixels.
                  </p>

                  <div
                    className="mt-3 flex cursor-pointer flex-col items-center justify-center rounded-md border-2 border-dashed border-slate-700 bg-slate-900/60 px-4 py-8 text-center hover:border-emerald-500 hover:bg-slate-900"
                    onClick={() => {
                      if (carrierInputRef.current) carrierInputRef.current.click()
                    }}
                    onDragOver={(event) => {
                      event.preventDefault()
                      event.stopPropagation()
                    }}
                    onDrop={(event) => {
                      event.preventDefault()
                      const file = event.dataTransfer.files?.[0]
                      if (file) {
                        handleCarrierImageSelected(file)
                      }
                    }}
                  >
                    <span className="text-xs font-medium uppercase tracking-wide text-slate-400">
                      Drop PNG here or click to browse
                    </span>
                    {carrierImage && (
                      <p className="mt-2 truncate text-xs text-emerald-300">
                        Selected: {carrierImage.name} ({carrierImage.size} bytes)
                      </p>
                    )}
                    {!carrierImage && (
                      <p className="mt-2 text-xs text-slate-500">
                        We never upload this image; it stays on your device.
                      </p>
                    )}
                  </div>

                  <input
                    ref={carrierInputRef}
                    type="file"
                    accept="image/png"
                    className="hidden"
                    onChange={(event) => {
                      const file = event.target.files?.[0]
                      if (file) {
                        handleCarrierImageSelected(file)
                      }
                    }}
                  />
                </div>
              </div>

              <div className="mt-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <button
                  type="button"
                  onClick={handleSenderSubmit}
                  disabled={isSenderSubmitting || !secretFile || !carrierImage}
                  className="inline-flex items-center justify-center rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:bg-slate-700"
                >
                  {isSenderSubmitting ? 'Securing & Uploading…' : 'Lock & Upload Secret'}
                </button>

                {shareUrl && (
                  <div className="mt-2 w-full rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-100 md:mt-0 md:w-auto">
                    <p className="font-semibold text-emerald-300">Shareable Link</p>
                    <p className="mt-1 break-all font-mono text-[11px]">{shareUrl}</p>
                  </div>
                )}
              </div>
            </section>
          )}

          {isReceiverView && (
            <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 shadow-sm">
              <h2 className="text-lg font-medium text-slate-100">Receiver Flow</h2>
              <p className="mt-1 text-sm text-slate-400">
                Upload the key image you received out-of-band. The app will locally extract
                the AES key and IV, fetch the encrypted blob, and decrypt it in your
                browser.
              </p>

              <div className="mt-6">
                <p className="text-xs font-mono text-slate-500">
                  File ID:&nbsp;
                  <span className="text-slate-300">{fileId}</span>
                </p>

                <div
                  className="mt-4 flex cursor-pointer flex-col items-center justify-center rounded-md border-2 border-dashed border-slate-700 bg-slate-900/60 px-4 py-10 text-center hover:border-emerald-500 hover:bg-slate-900"
                  onClick={() => {
                    if (keyImageInputRef.current) keyImageInputRef.current.click()
                  }}
                  onDragOver={(event) => {
                    event.preventDefault()
                    event.stopPropagation()
                  }}
                  onDrop={(event) => {
                    event.preventDefault()
                    const file = event.dataTransfer.files?.[0]
                    if (file) {
                      handleKeyImageSelected(file)
                    }
                  }}
                >
                  <span className="text-xs font-medium uppercase tracking-wide text-slate-400">
                    Drop key image here or click to browse
                  </span>
                  {keyImage && (
                    <p className="mt-2 truncate text-xs text-emerald-300">
                      Selected: {keyImage.name} ({keyImage.size} bytes)
                    </p>
                  )}
                  {!keyImage && (
                    <p className="mt-2 text-xs text-slate-500">
                      This image never leaves your device. Only the ciphertext is fetched
                      from the backend.
                    </p>
                  )}
                </div>

                <input
                  ref={keyImageInputRef}
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={(event) => {
                    const file = event.target.files?.[0]
                    if (file) {
                      handleKeyImageSelected(file)
                    }
                  }}
                />

                <button
                  type="button"
                  onClick={handleReceiverSubmit}
                  disabled={isReceiverProcessing || !keyImage}
                  className="mt-6 inline-flex items-center justify-center rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:bg-slate-700"
                >
                  {isReceiverProcessing ? 'Validating & Decrypting…' : 'Unlock & Download'}
                </button>
              </div>
            </section>
          )}

          {!isReceiverView && (senderStatus || senderError) && (
            <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 text-sm">
              {senderStatus && (
                <p className="text-slate-200">
                  <span className="font-semibold text-indigo-400">Status:</span>{' '}
                  {senderStatus}
                </p>
              )}
              {senderError && (
                <p className="mt-1 text-rose-400">
                  <span className="font-semibold">Error:</span> {senderError}
                </p>
              )}
            </section>
          )}

          {isReceiverView && (receiverStatus || receiverError) && (
            <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 text-sm">
              {receiverStatus && (
                <p className="text-slate-200">
                  <span className="font-semibold text-emerald-400">Status:</span>{' '}
                  {receiverStatus}
                </p>
              )}
              {receiverError && (
                <p className="mt-1 text-rose-400">
                  <span className="font-semibold">Error:</span> {receiverError}
                </p>
              )}
            </section>
          )}
        </main>

        <footer className="mt-8 border-t border-slate-800 pt-4 text-xs text-slate-500">
          All cryptographic and steganographic operations run entirely in your browser.
          The FastAPI backend only stores and serves opaque ciphertext blobs.
        </footer>
      </div>
    </div>
  )
}

export default App

