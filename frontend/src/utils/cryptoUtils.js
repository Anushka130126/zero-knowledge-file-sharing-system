// @ts-check

/**
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i])
  }
  const base64 = window.btoa(binary)
  bytes.fill(0)
  return base64
}

/**
 * @param {string} base64
 * @returns {Uint8Array}
 */
function base64ToUint8Array(base64) {
  const binary = window.atob(base64)
  const len = binary.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/**
 * @returns {Promise<CryptoKey>}
 */
export async function generateAesGcmKey() {
  const crypto = window.crypto
  const key = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt'],
  )
  return key
}

/**
 * @typedef {Object} EncryptFileResult
 * @property {Blob} ciphertextBlob
 * @property {string} exportedKey
 * @property {string} iv
 */

/**
 * @param {File} file
 * @returns {Promise<EncryptFileResult>}
 */
export async function encryptFile(file) {
  const crypto = window.crypto
  const key = await generateAesGcmKey()

  const ivBytes = new Uint8Array(12)
  crypto.getRandomValues(ivBytes)

  const plaintextBuffer = await file.arrayBuffer()

  let ciphertextBuffer
  try {
    ciphertextBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes,
      },
      key,
      plaintextBuffer,
    )
  } finally {
    const plainBytes = new Uint8Array(plaintextBuffer)
    plainBytes.fill(0)
  }

  const ciphertextBlob = new Blob([ciphertextBuffer], {
    type: 'application/octet-stream',
  })

  const rawKey = await crypto.subtle.exportKey('raw', key)
  const exportedKey = arrayBufferToBase64(rawKey)
  const iv = arrayBufferToBase64(ivBytes.buffer)

  ivBytes.fill(0)

  return {
    ciphertextBlob,
    exportedKey,
    iv,
  }
}

/**
 * @param {Blob | ArrayBuffer} ciphertextInput
 * @param {string} base64Key
 * @param {string} base64Iv
 * @returns {Promise<Blob>}
 */
export async function decryptFile(ciphertextInput, base64Key, base64Iv) {
  const crypto = window.crypto

  const ciphertextBuffer =
    ciphertextInput instanceof Blob
      ? await ciphertextInput.arrayBuffer()
      : ciphertextInput

  const keyBytes = base64ToUint8Array(base64Key)
  const ivBytes = base64ToUint8Array(base64Iv)

  /** @type {CryptoKey | null} */
  let key = null
  try {
    key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      {
        name: 'AES-GCM',
      },
      false,
      ['decrypt'],
    )
  } finally {
    keyBytes.fill(0)
  }

  if (!key) {
    throw new Error('Failed to import decryption key')
  }

  let plaintextBuffer
  try {
    plaintextBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes,
      },
      key,
      ciphertextBuffer,
    )
  } finally {
    ivBytes.fill(0)
    // @ts-expect-error allow explicit nulling for GC
    key = null
  }

  const plaintextBlob = new Blob([plaintextBuffer], {
    type:
      ciphertextInput instanceof Blob
        ? ciphertextInput.type
        : 'application/octet-stream',
  })

  const plainBytes = new Uint8Array(plaintextBuffer)
  plainBytes.fill(0)

  return plaintextBlob
}

