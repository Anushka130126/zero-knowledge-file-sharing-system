// @ts-check

/**
 * @param {File} imageFile
 * @returns {Promise<HTMLImageElement>}
 */
async function loadImageFromFile(imageFile) {
  const url = URL.createObjectURL(imageFile)

  return new Promise((resolve, reject) => {
    const img = new Image()
    img.onload = () => {
      URL.revokeObjectURL(url)
      resolve(img)
    }
    img.onerror = (event) => {
      URL.revokeObjectURL(url)
      reject(
        new Error(
          `Failed to load image for steganography${
            event instanceof ErrorEvent && event.message
              ? `: ${event.message}`
              : ''
          }`,
        ),
      )
    }
    img.src = url
  })
}

/**
 * @param {string} payloadString
 * @returns {number[]}
 */
function stringToBitsWithDelimiter(payloadString) {
  const encoder = new TextEncoder()
  const payloadBytes = encoder.encode(payloadString)

  /** @type {number[]} */
  const bits = []

  for (let i = 0; i < payloadBytes.length; i += 1) {
    const byte = payloadBytes[i]
    for (let bitIndex = 7; bitIndex >= 0; bitIndex -= 1) {
      const bit = (byte >> bitIndex) & 1
      bits.push(bit)
    }
  }

  for (let i = 0; i < 16; i += 1) {
    bits.push(0)
  }

  payloadBytes.fill(0)

  return bits
}

/**
 * @param {number[]} bits
 * @returns {Uint8Array}
 */
function bitsToBytes(bits) {
  const byteLength = Math.floor(bits.length / 8)
  const bytes = new Uint8Array(byteLength)

  for (let i = 0; i < byteLength; i += 1) {
    let byte = 0
    for (let bitIndex = 0; bitIndex < 8; bitIndex += 1) {
      const bit = bits[i * 8 + bitIndex]
      byte = (byte << 1) | (bit & 1)
    }
    bytes[i] = byte
  }

  return bytes
}

/**
 * @param {HTMLCanvasElement} canvas
 * @returns {Promise<Blob>}
 */
function canvasToPngBlob(canvas) {
  return new Promise((resolve, reject) => {
    canvas.toBlob(
      (blob) => {
        if (!blob) {
          reject(new Error('Failed to create PNG blob from canvas'))
          return
        }
        resolve(blob)
      },
      'image/png',
      1,
    )
  })
}

/**
 * @param {File} imageFile
 * @param {string} payloadString
 * @returns {Promise<File>}
 */
export async function embedDataInImage(imageFile, payloadString) {
  const img = await loadImageFromFile(imageFile)

  const canvas = document.createElement('canvas')
  canvas.width = img.naturalWidth || img.width
  canvas.height = img.naturalHeight || img.height

  const ctx = canvas.getContext('2d')
  if (!ctx) {
    throw new Error('Canvas2DContextUnavailable')
  }

  ctx.drawImage(img, 0, 0)

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
  const data = imageData.data

  const bits = stringToBitsWithDelimiter(payloadString)
  const capacityBits = (data.length / 4) * 3

  if (bits.length > capacityBits) {
    for (let i = 0; i < bits.length; i += 1) {
      bits[i] = 0
    }
    throw new Error('STEGO_PAYLOAD_TOO_LARGE')
  }

  let bitIndex = 0
  for (let i = 0; i < data.length && bitIndex < bits.length; i += 4) {
    for (let channel = 0; channel < 3 && bitIndex < bits.length; channel += 1) {
      const offset = i + channel
      const bit = bits[bitIndex]
      data[offset] = (data[offset] & ~1) | (bit & 1)
      bitIndex += 1
    }
  }

  for (let i = 0; i < bits.length; i += 1) {
    bits[i] = 0
  }

  ctx.putImageData(imageData, 0, 0)

  const pngBlob = await canvasToPngBlob(canvas)

  const baseName = imageFile.name.replace(/\.[^.]+$/, '')
  const stegoName = `${baseName || 'stego'}-embedded.png`

  const stegoFile = new File([pngBlob], stegoName, {
    type: 'image/png',
    lastModified: Date.now(),
  })

  return stegoFile
}

/**
 * @typedef {{ key: string, iv: string }} ExtractedKeyIv
 */

/**
 * @param {File} imageFile
 * @returns {Promise<ExtractedKeyIv>}
 */
export async function extractDataFromImage(imageFile) {
  const img = await loadImageFromFile(imageFile)

  const canvas = document.createElement('canvas')
  canvas.width = img.naturalWidth || img.width
  canvas.height = img.naturalHeight || img.height

  const ctx = canvas.getContext('2d')
  if (!ctx) {
    throw new Error('Canvas2DContextUnavailable')
  }

  ctx.drawImage(img, 0, 0)

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
  const data = imageData.data

  /** @type {number[]} */
  const bits = []
  let consecutiveZeroBits = 0
  let delimiterFound = false

  outer: for (let i = 0; i < data.length; i += 4) {
    for (let channel = 0; channel < 3; channel += 1) {
      const offset = i + channel
      const bit = data[offset] & 1
      bits.push(bit)

      if (bit === 0) {
        consecutiveZeroBits += 1
        if (consecutiveZeroBits === 16) {
          bits.length -= 16
          delimiterFound = true
          break outer
        }
      } else {
        consecutiveZeroBits = 0
      }
    }
  }

  if (!delimiterFound) {
    for (let i = 0; i < bits.length; i += 1) {
      bits[i] = 0
    }
    throw new Error('STEGO_DELIMITER_NOT_FOUND')
  }

  const payloadBytes = bitsToBytes(bits)

  for (let i = 0; i < bits.length; i += 1) {
    bits[i] = 0
  }

  let payloadString = ''
  try {
    const decoder = new TextDecoder()
    payloadString = decoder.decode(payloadBytes)
  } catch {
    payloadBytes.fill(0)
    throw new Error('STEGO_JSON_PARSE_FAILED')
  }

  payloadBytes.fill(0)

  let parsed
  try {
    parsed = JSON.parse(payloadString)
  } catch {
    throw new Error('STEGO_JSON_PARSE_FAILED')
  } finally {
    payloadString = ''
  }

  if (
    !parsed ||
    typeof parsed.key !== 'string' ||
    typeof parsed.iv !== 'string'
  ) {
    throw new Error('STEGO_JSON_PARSE_FAILED')
  }

  return {
    key: parsed.key,
    iv: parsed.iv,
  }
}

