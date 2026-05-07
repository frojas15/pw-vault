import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ChangeEvent, KeyboardEvent } from 'react'
import './App.css'

type VaultItem = {
  id: string
  title: string
  username: string
  password: string
  website: string
  notes: string
  tags: string[]
  updatedAt: string
}

type VaultPayload = {
  items: VaultItem[]
}

type BeforeInstallPromptEvent = Event & {
  prompt: () => Promise<void>
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed'; platform: string }>
}

type EncryptedBlob = {
  salt?: string
  iv: string
  data: string
  version: number
}

type WebAuthnVaultCredential = {
  credentialId: string
  prfSalt: string
  wrappedMasterPassword: EncryptedBlob
  timestamp: number
  version: number
}

type PrfResults = AuthenticationExtensionsClientOutputs & {
  prf?: {
    enabled?: boolean
    results?: {
      first?: ArrayBuffer
    }
  }
}

type SortOrder = 'alpha' | 'recent'

type SyncConfig = {
  workerUrl: string
  token: string
  username: string
}

const STORAGE_KEY = 'password_vault_blob_v1'
const WEBAUTHN_KEY = 'password_vault_webauthn'
const SYNC_KEY = 'password_vault_sync_v1'
const PASSWORD_GROUPS = [
  'ABCDEFGHJKLMNPQRSTUVWXYZ',
  'abcdefghijkmnpqrstuvwxyz',
  '23456789',
  '!@#$%&*?',
]

// Evaluated once at module load — safe to keep outside the component
const isPhone = window.matchMedia('(pointer: coarse)').matches

function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  const chunkSize = 0x8000

  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.slice(index, index + chunkSize))
  }

  return btoa(binary)
}

function base64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0))
}

function bytesToBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer
}

async function deriveKey(masterPassword: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(masterPassword),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  )

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: 250000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function deriveBiometricWrappingKey(secret: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey('raw', bytesToBuffer(secret), { name: 'HKDF' }, false, ['deriveKey'])

  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      salt: encoder.encode('password-vault-biometric-v1'),
      info: encoder.encode('master-password-wrap'),
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function encryptVault(masterPassword: string, payload: VaultPayload): Promise<string> {
  const encoder = new TextEncoder()
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveKey(masterPassword, salt)
  const plaintext = encoder.encode(JSON.stringify(payload))
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext)

  return JSON.stringify({
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(encrypted)),
    version: 1,
  })
}

async function decryptVault(masterPassword: string, vaultBlob: string): Promise<VaultPayload> {
  const parsed = JSON.parse(vaultBlob) as EncryptedBlob
  if (!parsed.salt) {
    throw new Error('Missing vault salt.')
  }
  const salt = base64ToBytes(parsed.salt)
  const iv = base64ToBytes(parsed.iv)
  const data = base64ToBytes(parsed.data)
  const key = await deriveKey(masterPassword, salt)
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    data as BufferSource,
  )
  const decoder = new TextDecoder()
  return JSON.parse(decoder.decode(decrypted))
}

async function wrapMasterPassword(secret: Uint8Array, masterPassword: string): Promise<EncryptedBlob> {
  const encoder = new TextEncoder()
  const key = await deriveBiometricWrappingKey(secret)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(masterPassword))

  return {
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(encrypted)),
    version: 1,
  }
}

async function unwrapMasterPassword(secret: Uint8Array, wrapped: EncryptedBlob): Promise<string> {
  const key = await deriveBiometricWrappingKey(secret)
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytesToBuffer(base64ToBytes(wrapped.iv)) },
    key,
    bytesToBuffer(base64ToBytes(wrapped.data)),
  )

  return new TextDecoder().decode(decrypted)
}

function randomIndex(maxExclusive: number): number {
  const limit = Math.floor(256 / maxExclusive) * maxExclusive
  const byte = new Uint8Array(1)

  do {
    crypto.getRandomValues(byte)
  } while (byte[0] >= limit)

  return byte[0] % maxExclusive
}

function shuffleSecure(values: string[]): string[] {
  const shuffled = [...values]

  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const swapIndex = randomIndex(index + 1)
    ;[shuffled[index], shuffled[swapIndex]] = [shuffled[swapIndex], shuffled[index]]
  }

  return shuffled
}

function generatePassword(length: number): string {
  const safeLength = Math.max(length, PASSWORD_GROUPS.length)
  const chars = PASSWORD_GROUPS.join('')
  const required = PASSWORD_GROUPS.map((group) => group[randomIndex(group.length)])
  const remaining = Array.from({ length: safeLength - required.length }, () => chars[randomIndex(chars.length)])

  return shuffleSecure([...required, ...remaining]).join('')
}

function normalizeHeader(value: string): string {
  return value.toLowerCase().replace(/\s+/g, '').trim()
}

function toText(value: unknown): string {
  if (value === null || value === undefined) {
    return ''
  }
  if (value instanceof Date) {
    return value.toISOString().slice(0, 10)
  }
  return String(value).trim()
}

function getPasswordStrength(value: string): { label: string; score: number } {
  if (!value) {
    return { label: 'Empty', score: 0 }
  }

  let score = 0
  if (value.length >= 10) score += 1
  if (/[A-Z]/.test(value) && /[a-z]/.test(value)) score += 1
  if (/\d/.test(value)) score += 1
  if (/[^A-Za-z0-9]/.test(value)) score += 1

  const labels = ['Weak', 'Fair', 'Good', 'Strong']
  return { label: labels[Math.max(0, score - 1)], score }
}

function getPasswordAge(updatedAt: string): number {
  return Math.floor((Date.now() - new Date(updatedAt).getTime()) / (1000 * 60 * 60 * 24))
}

function getFaviconUrl(website: string): string {
  try {
    const url = new URL(website.startsWith('http') ? website : `https://${website}`)
    return `https://www.google.com/s2/favicons?sz=32&domain=${url.hostname}`
  } catch {
    return ''
  }
}

async function lazyLoadXLSX() {
  const { read, utils } = await import('xlsx')
  return { read, utils }
}

function getStoredWebAuthnCredential(): WebAuthnVaultCredential | null {
  const stored = localStorage.getItem(WEBAUTHN_KEY)
  if (!stored) {
    return null
  }

  try {
    const parsed = JSON.parse(stored) as Partial<WebAuthnVaultCredential>
    if (!parsed.credentialId || !parsed.prfSalt || !parsed.wrappedMasterPassword) {
      return null
    }
    return parsed as WebAuthnVaultCredential
  } catch {
    return null
  }
}

async function getWebAuthnPrfSecret(credentialId: Uint8Array, prfSalt: Uint8Array): Promise<Uint8Array | null> {
  const assertion = await navigator.credentials.get?.({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ id: bytesToBuffer(credentialId), type: 'public-key' }],
      timeout: 60000,
      userVerification: 'required',
      extensions: {
        prf: {
          eval: {
            first: bytesToBuffer(prfSalt),
          },
        },
      },
    } as PublicKeyCredentialRequestOptions,
  })

  const results = assertion ? ((assertion as PublicKeyCredential).getClientExtensionResults() as PrfResults) : null
  const prfSecret = results?.prf?.results?.first
  return prfSecret ? new Uint8Array(prfSecret) : null
}

async function registerWebAuthn(displayName: string, masterPassword: string): Promise<boolean> {
  try {
    if (!window.PublicKeyCredential) {
      return false
    }

    const prfSalt = crypto.getRandomValues(new Uint8Array(32))
    const credential = await navigator.credentials.create?.({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: 'Password Vault' },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: displayName,
          displayName,
        },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
        timeout: 60000,
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          residentKey: 'required',
          userVerification: 'required',
          requireResidentKey: true,
        },
        extensions: {
          prf: {
            eval: {
              first: bytesToBuffer(prfSalt),
            },
          },
        },
      } as PublicKeyCredentialCreationOptions,
    })

    if (!credential) {
      return false
    }

    const credentialId = new Uint8Array((credential as PublicKeyCredential).rawId)
    const secret = await getWebAuthnPrfSecret(credentialId, prfSalt)
    if (!secret) {
      return false
    }

    const wrappedMasterPassword = await wrapMasterPassword(secret, masterPassword)
    localStorage.setItem(
      WEBAUTHN_KEY,
      JSON.stringify({
        credentialId: bytesToBase64(credentialId),
        prfSalt: bytesToBase64(prfSalt),
        wrappedMasterPassword,
        timestamp: Date.now(),
        version: 2,
      } satisfies WebAuthnVaultCredential),
    )
    return true
  } catch {
    return false
  }
}

async function unlockMasterPasswordWithWebAuthn(): Promise<string | null> {
  try {
    if (!window.PublicKeyCredential) {
      return null
    }

    const stored = getStoredWebAuthnCredential()
    if (!stored) {
      return null
    }

    const secret = await getWebAuthnPrfSecret(base64ToBytes(stored.credentialId), base64ToBytes(stored.prfSalt))
    if (!secret) {
      return null
    }

    return await unwrapMasterPassword(secret, stored.wrappedMasterPassword)
  } catch {
    return null
  }
}

function isWebAuthnAvailable(): boolean {
  return !!window.PublicKeyCredential && !!getStoredWebAuthnCredential()
}

const emptyForm = {
  title: '',
  username: '',
  password: '',
  website: '',
  notes: '',
  tags: [] as string[],
}

const tagOptions = ['Bills', 'Banking', 'Work', 'Personal', 'Social', 'Shopping']

function App() {
  const [masterPassword, setMasterPassword] = useState('')
  const [setupPassword, setSetupPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [unlockError, setUnlockError] = useState('')
  const [isLocked, setIsLocked] = useState(true)
  const [items, setItems] = useState<VaultItem[]>([])
  const [query, setQuery] = useState('')
  const [form, setForm] = useState(emptyForm)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [lockMinutes, setLockMinutes] = useState(isPhone ? 3 : 15)
  const [toast, setToast] = useState('')
  const [importStatus, setImportStatus] = useState('')
  const [showFormPassword, setShowFormPassword] = useState(false)
  const [visiblePasswords, setVisiblePasswords] = useState<Record<string, boolean>>({})
  const [installPrompt, setInstallPrompt] = useState<BeforeInstallPromptEvent | null>(null)
  const [webauthnAvailable, setWebauthnAvailable] = useState(isWebAuthnAvailable)
  const [selectedTags, setSelectedTags] = useState<string[]>([])
  const [sortOrder, setSortOrder] = useState<SortOrder>('alpha')
  const [customTagInput, setCustomTagInput] = useState('')
  const [syncConfig, setSyncConfig] = useState<SyncConfig | null>(() => {
    try {
      const stored = localStorage.getItem(SYNC_KEY)
      return stored ? (JSON.parse(stored) as SyncConfig) : null
    } catch { return null }
  })
  const [syncStatus, setSyncStatus] = useState<'idle' | 'syncing' | 'synced' | 'error'>('idle')
  const [syncOpen, setSyncOpen] = useState(false)
  const [syncFormUsername, setSyncFormUsername] = useState('')
  const [syncFormPassword, setSyncFormPassword] = useState('')
  const [syncFormUrl, setSyncFormUrl] = useState('')
  const [syncError, setSyncError] = useState('')
  const [syncIsRegistering, setSyncIsRegistering] = useState(true)
  const syncConfigRef = useRef<SyncConfig | null>(null)
  syncConfigRef.current = syncConfig
  const fileInputRef = useRef<HTMLInputElement>(null)
  const backupFileRef = useRef<HTMLInputElement>(null)
  const [hasVault, setHasVault] = useState(() => Boolean(localStorage.getItem(STORAGE_KEY)))

  // Refs so lockNow can read current form state without being in its dep array
  const formRef = useRef(emptyForm)
  const editingIdRef = useRef<string | null>(null)
  formRef.current = form
  editingIdRef.current = editingId

  const lockNow = useCallback(() => {
    setIsLocked(true)
    setMasterPassword('')
    setItems([])
    setForm(emptyForm)
    setEditingId(null)
    setQuery('')
    setVisiblePasswords({})
    setSelectedTags([])
    setShowFormPassword(false)
    setImportStatus('')
    setSyncStatus('idle')
  }, [])

  const applySyncConfig = (config: SyncConfig) => {
    localStorage.setItem(SYNC_KEY, JSON.stringify(config))
    setSyncConfig(config)
  }

  const removeSyncConfig = useCallback(() => {
    localStorage.removeItem(SYNC_KEY)
    setSyncConfig(null)
    setSyncStatus('idle')
  }, [])

  const syncPush = useCallback(async (config: SyncConfig) => {
    const blob = localStorage.getItem(STORAGE_KEY)
    if (!blob) return
    setSyncStatus('syncing')
    try {
      const res = await fetch(`${config.workerUrl}/api/vault`, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${config.token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ blob }),
      })
      setSyncStatus(res.ok ? 'synced' : 'error')
    } catch {
      setSyncStatus('error')
    }
  }, [])

  const syncPushRef = useRef(syncPush)
  syncPushRef.current = syncPush

  const syncMergeAndApply = useCallback(async (
    config: SyncConfig,
    password: string,
    localItems: VaultItem[],
  ): Promise<VaultItem[]> => {
    setSyncStatus('syncing')
    try {
      const res = await fetch(`${config.workerUrl}/api/vault`, {
        headers: { Authorization: `Bearer ${config.token}` },
      })
      if (!res.ok) {
        setSyncStatus('error')
        return localItems
      }
      const { blob: serverBlob } = (await res.json()) as { blob: string | null }
      if (!serverBlob) {
        await syncPush(config)
        return localItems
      }
      const serverPayload = await decryptVault(password, serverBlob)
      const serverItems = (serverPayload.items ?? []).map((i) => ({ ...i, tags: i.tags ?? [] }))
      const byId = new Map(localItems.map((i) => [i.id, i]))
      let changed = false
      for (const si of serverItems) {
        const local = byId.get(si.id)
        if (!local || new Date(si.updatedAt) > new Date(local.updatedAt)) {
          byId.set(si.id, si)
          changed = true
        }
      }
      const merged = Array.from(byId.values())
      if (changed) {
        const mergedBlob = await encryptVault(password, { items: merged })
        localStorage.setItem(STORAGE_KEY, mergedBlob)
        await syncPush(config)
      }
      setSyncStatus('synced')
      return merged
    } catch {
      setSyncStatus('error')
      return localItems
    }
  }, [syncPush])

  const handleSyncSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSyncError('')
    const url = syncFormUrl.trim().replace(/\/$/, '')
    try {
      const endpoint = syncIsRegistering ? '/api/register' : '/api/login'
      const res = await fetch(`${url}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: syncFormUsername, password: syncFormPassword }),
      })
      const data = (await res.json()) as { token?: string; error?: string }
      if (!res.ok) { setSyncError(data.error ?? 'Connection failed'); return }
      const newConfig: SyncConfig = { workerUrl: url, token: data.token!, username: syncFormUsername }
      applySyncConfig(newConfig)
      setSyncOpen(false)
      setSyncFormPassword('')
      if (!isLocked && masterPassword) {
        const merged = await syncMergeAndApply(newConfig, masterPassword, items)
        setItems(merged)
      }
      setToast(`Sync ${syncIsRegistering ? 'enabled' : 'connected'}`)
    } catch {
      setSyncError('Could not reach the Worker URL. Double-check it and try again.')
    }
  }

  // Used by the Lock Now button — warns if user has unsaved form data
  const requestLock = useCallback(() => {
    const hasUnsaved =
      editingIdRef.current !== null ||
      Boolean(formRef.current.title || formRef.current.username || formRef.current.password)
    if (hasUnsaved && !window.confirm('You have unsaved changes. Lock anyway?')) return
    lockNow()
  }, [lockNow])

  useEffect(() => {
    if (!toast) {
      return
    }
    const timeout = window.setTimeout(() => setToast(''), 1500)
    return () => window.clearTimeout(timeout)
  }, [toast])

  useEffect(() => {
    const onBeforeInstallPrompt = (event: Event) => {
      event.preventDefault()
      setInstallPrompt(event as BeforeInstallPromptEvent)
    }

    window.addEventListener('beforeinstallprompt', onBeforeInstallPrompt)
    return () => window.removeEventListener('beforeinstallprompt', onBeforeInstallPrompt)
  }, [])

  useEffect(() => {
    if (isLocked) {
      return
    }

    const timeoutMs = lockMinutes * 60 * 1000
    let timeout = window.setTimeout(lockNow, timeoutMs)

    const resetLockTimer = () => {
      clearTimeout(timeout)
      timeout = window.setTimeout(lockNow, timeoutMs)
    }

    const events = ['mousemove', 'keydown', 'mousedown', 'touchstart', 'scroll']
    events.forEach((eventName) => window.addEventListener(eventName, resetLockTimer, { passive: true }))

    return () => {
      clearTimeout(timeout)
      events.forEach((eventName) => window.removeEventListener(eventName, resetLockTimer))
    }
  }, [isLocked, lockMinutes, lockNow])

  const allTags = useMemo(() => {
    const tags = new Set<string>()
    items.forEach((item) => item.tags.forEach((tag) => tags.add(tag)))
    return Array.from(tags).sort()
  }, [items])

  const filteredItems = useMemo(() => {
    const q = query.toLowerCase().trim()
    const sorted = [...items].sort((a, b) =>
      sortOrder === 'alpha'
        ? a.title.localeCompare(b.title)
        : new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime(),
    )

    return sorted.filter((item) => {
      const matchesQuery =
        !q ||
        [item.title, item.username, item.website, item.notes].some((field) => field.toLowerCase().includes(q))

      const matchesTags = selectedTags.length === 0 || selectedTags.some((tag) => item.tags.includes(tag))

      return matchesQuery && matchesTags
    })
  }, [items, query, selectedTags, sortOrder])

  const passwordStrength = useMemo(() => getPasswordStrength(form.password), [form.password])

  const persistItems = useCallback(
    async (nextItems: VaultItem[]) => {
      const blob = await encryptVault(masterPassword, { items: nextItems })
      localStorage.setItem(STORAGE_KEY, blob)
      setItems(nextItems)
      const config = syncConfigRef.current
      if (config) syncPushRef.current(config)
    },
    [masterPassword],
  )

  const createVault = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (setupPassword.length < 10) {
      setUnlockError('Use at least 10 characters for your master password.')
      return
    }
    if (setupPassword !== confirmPassword) {
      setUnlockError('Passwords do not match.')
      return
    }

    const blob = await encryptVault(setupPassword, { items: [] })
    localStorage.setItem(STORAGE_KEY, blob)
    setHasVault(true)
    setMasterPassword(setupPassword)
    setSetupPassword('')
    setConfirmPassword('')
    setItems([])
    setIsLocked(false)
    setUnlockError('')
  }

  const unlockVault = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    try {
      const blob = localStorage.getItem(STORAGE_KEY)
      if (!blob) { setUnlockError('Could not unlock vault.'); return }
      const payload = await decryptVault(masterPassword, blob)
      const localItems = (payload.items ?? []).map((item) => ({ ...item, tags: item.tags ?? [] }))
      setItems(localItems)
      setIsLocked(false)
      setUnlockError('')
      const config = syncConfigRef.current
      if (config) {
        syncMergeAndApply(config, masterPassword, localItems).then((merged) => {
          if (merged !== localItems) setItems(merged)
        })
      }
    } catch {
      setUnlockError('Could not unlock vault.')
    }
  }

  const unlockWithBiometric = async () => {
    try {
      const unlockedMasterPassword = await unlockMasterPasswordWithWebAuthn()
      if (!unlockedMasterPassword) {
        setUnlockError('Biometric authentication failed.')
        return
      }

      const blob = localStorage.getItem(STORAGE_KEY)
      if (!blob) {
        setUnlockError('Could not unlock vault.')
        return
      }
      const payload = await decryptVault(unlockedMasterPassword, blob)
      const localItems = (payload.items ?? []).map((item) => ({ ...item, tags: item.tags ?? [] }))
      setMasterPassword(unlockedMasterPassword)
      setItems(localItems)
      setIsLocked(false)
      setUnlockError('')
      setToast('Unlocked with biometric')
      const config = syncConfigRef.current
      if (config) {
        syncMergeAndApply(config, unlockedMasterPassword, localItems).then((merged) => {
          if (merged !== localItems) setItems(merged)
        })
      }
    } catch {
      setUnlockError('Biometric authentication failed.')
    }
  }

  const saveEntry = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!form.title || !form.username || !form.password) {
      return
    }

    if (!editingId) {
      const duplicate = items.find(
        (item) =>
          item.title.toLowerCase() === form.title.toLowerCase() &&
          item.username.toLowerCase() === form.username.toLowerCase(),
      )
      if (duplicate && !window.confirm(`"${form.title}" with this username already exists. Add anyway?`)) return
    }

    const now = new Date().toISOString()
    const isEditing = Boolean(editingId)
    const nextItems = editingId
      ? items.map((item) => (item.id === editingId ? { ...item, ...form, updatedAt: now } : item))
      : [{ id: crypto.randomUUID(), ...form, updatedAt: now }, ...items]

    await persistItems(nextItems)
    setForm(emptyForm)
    setEditingId(null)
    setToast(isEditing ? 'Entry updated' : 'Entry saved')
  }

  const editEntry = (item: VaultItem) => {
    setEditingId(item.id)
    setForm({
      title: item.title,
      username: item.username,
      password: item.password,
      website: item.website,
      notes: item.notes,
      tags: [...item.tags],
    })
  }

  const deleteEntry = async (id: string, title: string) => {
    if (!window.confirm(`Delete "${title}"? This cannot be undone.`)) return
    const nextItems = items.filter((item) => item.id !== id)
    await persistItems(nextItems)
    setToast('Entry deleted')
  }

  const copyText = async (value: string, label = 'Copied') => {
    try {
      await navigator.clipboard.writeText(value)
      setToast(`${label} — clears in 30s`)
      setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30_000)
    } catch {
      window.alert('Clipboard access failed. Use a secure HTTPS context.')
    }
  }

  const togglePasswordVisibility = (id: string) => {
    setVisiblePasswords((current) => ({ ...current, [id]: !current[id] }))
  }

  const toggleTag = (tag: string) => {
    setSelectedTags((current) => (current.includes(tag) ? current.filter((t) => t !== tag) : [...current, tag]))
  }

  const toggleFormTag = (tag: string) => {
    setForm((current) => ({
      ...current,
      tags: current.tags.includes(tag) ? current.tags.filter((t) => t !== tag) : [...current.tags, tag],
    }))
  }

  const addCustomTag = () => {
    const trimmed = customTagInput.trim()
    if (trimmed && !form.tags.includes(trimmed)) {
      setForm((current) => ({ ...current, tags: [...current.tags, trimmed] }))
    }
    setCustomTagInput('')
  }

  const handleCustomTagKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      addCustomTag()
    }
  }

  const parseExcelRows = (rows: Record<string, unknown>[]): VaultItem[] => {
    const now = new Date().toISOString()

    return rows
      .map((row) => {
        const normalized = new Map<string, string>()
        for (const [key, value] of Object.entries(row)) {
          normalized.set(normalizeHeader(key), toText(value))
        }

        const company = normalized.get('company') ?? normalized.get('title') ?? ''
        const account = normalized.get('account') ?? ''
        const service = normalized.get('service') ?? normalized.get('website') ?? normalized.get('site') ?? ''
        const username = normalized.get('username') ?? normalized.get('user') ?? normalized.get('login') ?? normalized.get('email') ?? ''
        const password = normalized.get('password') ?? normalized.get('passcode') ?? normalized.get('pwd') ?? ''
        const due = normalized.get('due') ?? ''
        const recurring = normalized.get('recurring') ?? ''
        const payment = normalized.get('payment') ?? ''
        const balance = normalized.get('balance') ?? ''
        const notes = normalized.get('notes') ?? ''

        const title = company || service || account || 'Imported Entry'
        const website = service

        const noteParts = [
          notes && `Notes: ${notes}`,
          account && `Account: ${account}`,
          due && `Due: ${due}`,
          recurring && `Recurring: ${recurring}`,
          payment && `Payment: ${payment}`,
          balance && `Balance: ${balance}`,
        ].filter(Boolean)

        return {
          id: crypto.randomUUID(),
          title,
          username,
          password,
          website,
          notes: noteParts.join(' | '),
          tags: [],
          updatedAt: now,
        }
      })
      .filter((item) => Boolean(item.password && (item.username || item.title)))
  }

  const handleExcelImport = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }

    try {
      const { read, utils } = await lazyLoadXLSX()
      const buffer = await file.arrayBuffer()
      const workbook = read(buffer)
      const importedAllSheets: VaultItem[] = []

      const detectHeaderRow = (grid: unknown[][]): number => {
        for (let rowIndex = 0; rowIndex < Math.min(grid.length, 20); rowIndex += 1) {
          const cells = (grid[rowIndex] ?? []).map((cell) => normalizeHeader(toText(cell)))
          const hasPassword = cells.includes('password') || cells.includes('passcode') || cells.includes('pwd')
          const hasIdentity =
            cells.includes('username') ||
            cells.includes('user') ||
            cells.includes('login') ||
            cells.includes('email') ||
            cells.includes('company') ||
            cells.includes('account') ||
            cells.includes('service')

          if (hasPassword && hasIdentity) {
            return rowIndex
          }
        }
        return -1
      }

      for (const sheetName of workbook.SheetNames) {
        const sheet = workbook.Sheets[sheetName]
        const grid = utils.sheet_to_json<unknown[]>(sheet, { header: 1, defval: '' }) as unknown[][]
        const headerRowIndex = detectHeaderRow(grid)
        if (headerRowIndex < 0) {
          continue
        }

        const headers = (grid[headerRowIndex] ?? []).map((cell) => toText(cell))
        const rowObjects = grid
          .slice(headerRowIndex + 1)
          .filter((row) => row.some((cell) => toText(cell) !== ''))
          .map((row) => {
            const rowObject: Record<string, unknown> = {}
            headers.forEach((header, index) => {
              if (header) {
                rowObject[header] = row[index] ?? ''
              }
            })
            return rowObject
          })

        importedAllSheets.push(...parseExcelRows(rowObjects))
      }

      if (importedAllSheets.length === 0) {
        setImportStatus('No rows with password data were found. Check that a sheet has Password and Username columns.')
        return
      }

      const existingByKey = new Map(
        items.map((item) => [
          `${item.title.toLowerCase()}|${item.username.toLowerCase()}|${item.website.toLowerCase()}`,
          item,
        ]),
      )

      for (const importedItem of importedAllSheets) {
        const key = `${importedItem.title.toLowerCase()}|${importedItem.username.toLowerCase()}|${importedItem.website.toLowerCase()}`
        existingByKey.set(key, importedItem)
      }

      const merged = Array.from(existingByKey.values())
      await persistItems(merged)
      setImportStatus(`Imported ${importedAllSheets.length} entries from ${file.name}.`)
      setToast('Import complete')
    } catch {
      setImportStatus('Import failed: unsupported or corrupted file.')
    } finally {
      event.target.value = ''
    }
  }

  const exportVault = async () => {
    const now = new Date().toISOString().slice(0, 10)
    const vaultBlob = localStorage.getItem(STORAGE_KEY)
    if (!vaultBlob) {
      setImportStatus('No vault data found to export.')
      return
    }

    const backup = {
      encrypted: true,
      vaultBlob,
      exportedAt: now,
      version: 2,
    }
    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `vault-encrypted-backup-${now}.json`
    a.click()
    URL.revokeObjectURL(url)
    setToast('Encrypted backup downloaded')
  }

  const handleVaultImport = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }

    try {
      const text = await file.text()
      const data = JSON.parse(text) as { encrypted?: boolean; vaultBlob?: string }

      if (!data.encrypted || !data.vaultBlob) {
        setImportStatus('Invalid backup file. Only encrypted backups exported from this vault are supported.')
        return
      }

      const restoredItems = (await decryptVault(masterPassword, data.vaultBlob)).items

      if (!Array.isArray(restoredItems)) {
        setImportStatus('Invalid backup file format.')
        return
      }

      const normalized = restoredItems.map((item) => ({ ...item, tags: item.tags ?? [] }))
      const existingByKey = new Map(
        items.map((item) => [
          `${item.title.toLowerCase()}|${item.username.toLowerCase()}|${item.website.toLowerCase()}`,
          item,
        ]),
      )

      for (const importedItem of normalized) {
        const key = `${importedItem.title.toLowerCase()}|${importedItem.username.toLowerCase()}|${importedItem.website.toLowerCase()}`
        existingByKey.set(key, importedItem)
      }

      const merged = Array.from(existingByKey.values())
      await persistItems(merged)
      setImportStatus(`Restored ${normalized.length} entries.`)
      setToast('Restore complete')
    } catch {
      setImportStatus('Restore failed: invalid, corrupted, or wrong-password backup file.')
    } finally {
      event.target.value = ''
    }
  }

  const registerBiometric = async () => {
    try {
      const success = await registerWebAuthn('Password Vault User', masterPassword)
      if (success) {
        setWebauthnAvailable(true)
        setToast('Biometric registered')
      } else {
        setToast('Biometric unlock requires a browser and device that support passkey PRF.')
      }
    } catch {
      setToast('Biometric registration failed.')
    }
  }

  const openExcelImportPicker = () => {
    fileInputRef.current?.click()
  }

  const openVaultImportPicker = () => {
    backupFileRef.current?.click()
  }

  const installApp = async () => {
    if (!installPrompt) {
      return
    }
    await installPrompt.prompt()
    await installPrompt.userChoice
    setInstallPrompt(null)
  }

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <h1>Password Vault</h1>
          <p>Encrypted local vault for your phone and desktop browser.</p>
        </div>
        {!isLocked && installPrompt && (
          <button type="button" className="install" onClick={installApp}>
            Install App
          </button>
        )}
      </header>

      {toast && <p className="toast">{toast}</p>}

      {isLocked ? (
        <section className="card">
          {!hasVault ? (
            <form onSubmit={createVault} className="stack">
              <h2>Create your vault</h2>
              <label>
                Master password
                <input
                  type="password"
                  value={setupPassword}
                  onChange={(event) => setSetupPassword(event.target.value)}
                  autoComplete="new-password"
                  required
                />
              </label>
              <label>
                Confirm password
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  autoComplete="new-password"
                  required
                />
              </label>
              <button type="submit">Create Vault</button>
            </form>
          ) : (
            <form onSubmit={unlockVault} className="stack">
              <h2>Unlock vault</h2>
              <label>
                Master password
                <input
                  type="password"
                  value={masterPassword}
                  onChange={(event) => setMasterPassword(event.target.value)}
                  autoComplete="current-password"
                  required
                />
              </label>
              <button type="submit">Unlock</button>
              {webauthnAvailable && (
                <button type="button" className="secondary" onClick={unlockWithBiometric}>
                  Unlock with Biometric
                </button>
              )}
            </form>
          )}
          {unlockError && <p className="error">{unlockError}</p>}
        </section>
      ) : (
        <>
          <section className="card controls">
            <label>
              Search
              <div className="search-wrap">
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Find by title, username, website"
                />
                {query && (
                  <button
                    type="button"
                    className="clear-search"
                    onClick={() => setQuery('')}
                    aria-label="Clear search"
                  >
                    ×
                  </button>
                )}
              </div>
            </label>
            <label>
              Auto-lock
              <select value={lockMinutes} onChange={(event) => setLockMinutes(Number(event.target.value))}>
                <option value={1}>1 minute</option>
                <option value={3}>3 minutes</option>
                <option value={5}>5 minutes</option>
                <option value={15}>15 minutes</option>
                <option value={30}>30 minutes</option>
              </select>
            </label>
            <label>
              Sort
              <select value={sortOrder} onChange={(event) => setSortOrder(event.target.value as SortOrder)}>
                <option value="alpha">A–Z</option>
                <option value="recent">Recently updated</option>
              </select>
            </label>
            <div className="controls-actions">
              <button type="button" className="secondary" onClick={openExcelImportPicker}>
                Import Excel
              </button>
              <button type="button" className="secondary" onClick={exportVault}>
                Export
              </button>
              <button type="button" className="secondary" onClick={openVaultImportPicker}>
                Restore
              </button>
              <button type="button" onClick={requestLock} className="secondary">
                Lock now
              </button>
            </div>
            <div className="sync-bar">
              {syncConfig ? (
                <div className="sync-info">
                  <span className={`sync-dot sync-dot--${syncStatus}`} />
                  <span className="sync-user">{syncConfig.username}</span>
                  <button type="button" className="secondary small" onClick={() => syncPushRef.current(syncConfig)}>
                    Sync now
                  </button>
                  <button type="button" className="secondary small danger-text" onClick={removeSyncConfig}>
                    Disconnect
                  </button>
                </div>
              ) : (
                <button type="button" className="secondary" onClick={() => setSyncOpen((v) => !v)}>
                  Enable Cloud Sync
                </button>
              )}
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".xlsx,.xls,.csv"
              onChange={handleExcelImport}
              className="hidden"
            />
            <input ref={backupFileRef} type="file" accept=".json" onChange={handleVaultImport} className="hidden" />
          </section>

          <p className="entry-count">
            {filteredItems.length !== items.length
              ? `${filteredItems.length} of ${items.length} entries`
              : `${items.length} ${items.length === 1 ? 'entry' : 'entries'}`}
          </p>

          {importStatus && <p className="import-status">{importStatus}</p>}

          {!webauthnAvailable && (
            <section className="card biometric-prompt">
              <p>Speed up future logins with biometric unlock (Face ID / fingerprint / Windows Hello).</p>
              <button type="button" className="secondary" onClick={registerBiometric}>
                Set up Biometric Unlock
              </button>
            </section>
          )}

          {allTags.length > 0 && (
            <section className="card tags-filter">
              <p>Filter by tags:</p>
              <div className="tag-buttons">
                {allTags.map((tag) => (
                  <button
                    key={tag}
                    type="button"
                    className={`tag-button ${selectedTags.includes(tag) ? 'active' : ''}`}
                    onClick={() => toggleTag(tag)}
                  >
                    {tag}
                  </button>
                ))}
              </div>
            </section>
          )}

          <section className="card">
            <form onSubmit={saveEntry} className="stack">
              <h2>{editingId ? 'Edit Entry' : 'Add Entry'}</h2>
              <label>
                Title
                <input
                  value={form.title}
                  onChange={(event) => setForm({ ...form, title: event.target.value })}
                  placeholder="Example: Gmail"
                  required
                />
              </label>
              <label>
                Username
                <input
                  value={form.username}
                  onChange={(event) => setForm({ ...form, username: event.target.value })}
                  autoComplete="username"
                  required
                />
              </label>
              <label>
                Password
                <div className="inline">
                  <input
                    type={showFormPassword ? 'text' : 'password'}
                    value={form.password}
                    onChange={(event) => setForm({ ...form, password: event.target.value })}
                    autoComplete="new-password"
                    required
                  />
                  <button type="button" className="secondary" onClick={() => setShowFormPassword((v) => !v)}>
                    {showFormPassword ? 'Hide' : 'Show'}
                  </button>
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => setForm({ ...form, password: generatePassword(20) })}
                  >
                    Generate
                  </button>
                </div>
              </label>
              <div className="strength">
                <div className={`strength-bar score-${passwordStrength.score}`} />
                <p>Password strength: {passwordStrength.label}</p>
              </div>
              <label>
                Website
                <input
                  value={form.website}
                  onChange={(event) => setForm({ ...form, website: event.target.value })}
                  placeholder="https://"
                />
              </label>
              <label>
                Notes
                <textarea
                  value={form.notes}
                  onChange={(event) => setForm({ ...form, notes: event.target.value })}
                  rows={3}
                />
              </label>
              <div>
                <p className="tag-label-heading">Tags</p>
                <div className="tag-buttons">
                  {tagOptions.map((tag) => (
                    <button
                      key={tag}
                      type="button"
                      className={`tag-button ${form.tags.includes(tag) ? 'active' : ''}`}
                      onClick={() => toggleFormTag(tag)}
                    >
                      {tag}
                    </button>
                  ))}
                </div>
                <div className="custom-tag-input">
                  <input
                    value={customTagInput}
                    onChange={(e) => setCustomTagInput(e.target.value)}
                    onKeyDown={handleCustomTagKeyDown}
                    placeholder="Custom tag…"
                  />
                  <button
                    type="button"
                    className="secondary"
                    onClick={addCustomTag}
                    disabled={!customTagInput.trim()}
                  >
                    Add
                  </button>
                </div>
                {form.tags.filter((t) => !tagOptions.includes(t)).length > 0 && (
                  <div className="tag-buttons" style={{ marginTop: '0.4rem' }}>
                    {form.tags
                      .filter((t) => !tagOptions.includes(t))
                      .map((tag) => (
                        <button
                          key={tag}
                          type="button"
                          className="tag-button active"
                          onClick={() => toggleFormTag(tag)}
                        >
                          {tag} ×
                        </button>
                      ))}
                  </div>
                )}
              </div>
              <div className="inline">
                <button type="submit">{editingId ? 'Update' : 'Save'}</button>
                {editingId && (
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => {
                      setEditingId(null)
                      setForm(emptyForm)
                    }}
                  >
                    Cancel
                  </button>
                )}
              </div>
            </form>
          </section>

          {syncOpen && (
            <section className="card">
              <form onSubmit={handleSyncSubmit} className="stack">
                <h2>Cloud Sync Setup</h2>
                <p className="sync-note">Your vault is encrypted before it ever leaves your device.</p>
                <div className="inline">
                  <button type="button" className={syncIsRegistering ? '' : 'secondary'} onClick={() => setSyncIsRegistering(true)}>
                    New account
                  </button>
                  <button type="button" className={!syncIsRegistering ? '' : 'secondary'} onClick={() => setSyncIsRegistering(false)}>
                    Existing account
                  </button>
                </div>
                <label>
                  Worker URL
                  <input value={syncFormUrl} onChange={(e) => setSyncFormUrl(e.target.value)} placeholder="https://your-worker.workers.dev" required />
                </label>
                <label>
                  Username
                  <input value={syncFormUsername} onChange={(e) => setSyncFormUsername(e.target.value)} autoComplete="username" required />
                </label>
                <label>
                  Sync password
                  <input type="password" value={syncFormPassword} onChange={(e) => setSyncFormPassword(e.target.value)} autoComplete="new-password" required />
                </label>
                {syncError && <p className="error">{syncError}</p>}
                <div className="inline">
                  <button type="submit">{syncIsRegistering ? 'Create & connect' : 'Connect'}</button>
                  <button type="button" className="secondary" onClick={() => { setSyncOpen(false); setSyncError('') }}>
                    Cancel
                  </button>
                </div>
              </form>
            </section>
          )}

          <section className="entries">
            {filteredItems.length === 0 ? (
              <p className="empty">No entries yet.</p>
            ) : (
              filteredItems.map((item) => {
                const age = getPasswordAge(item.updatedAt)
                const faviconUrl = item.website ? getFaviconUrl(item.website) : ''
                return (
                  <article key={item.id} className="card item">
                    <div>
                      <div className="item-title">
                        {faviconUrl && (
                          <img
                            src={faviconUrl}
                            alt=""
                            width={16}
                            height={16}
                            className="favicon"
                            onError={(e) => {
                              e.currentTarget.style.display = 'none'
                            }}
                          />
                        )}
                        <h3>{item.title}</h3>
                      </div>
                      <p>{item.username}</p>
                      {item.website && (
                        <a href={item.website.startsWith('http') ? item.website : `https://${item.website}`} target="_blank" rel="noreferrer">
                          {item.website}
                        </a>
                      )}
                      <p className="masked">{visiblePasswords[item.id] ? item.password : '••••••••••••'}</p>
                      {age > 180 && (
                        <p className="age-warning">Password not changed in {age} days</p>
                      )}
                      {item.notes && <p className="item-notes">{item.notes}</p>}
                      {item.tags.length > 0 && (
                        <div className="item-tags">
                          {item.tags.map((tag) => (
                            <span key={tag} className="tag-label">
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                      <p className="updated">Updated {new Date(item.updatedAt).toLocaleString()}</p>
                    </div>
                    <div className="inline">
                      <button type="button" className="secondary" onClick={() => copyText(item.username, 'Username copied')}>
                        Copy Username
                      </button>
                      <button type="button" className="secondary" onClick={() => copyText(item.password, 'Password copied')}>
                        Copy Password
                      </button>
                      <button type="button" className="secondary" onClick={() => togglePasswordVisibility(item.id)}>
                        {visiblePasswords[item.id] ? 'Hide' : 'Show'}
                      </button>
                    </div>
                    <div className="inline">
                      <button type="button" className="secondary" onClick={() => editEntry(item)}>
                        Edit
                      </button>
                      <button type="button" className="danger" onClick={() => deleteEntry(item.id, item.title)}>
                        Delete
                      </button>
                    </div>
                  </article>
                )
              })
            )}
          </section>
        </>
      )}
    </div>
  )
}

export default App
