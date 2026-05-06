import { useEffect, useMemo, useRef, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'
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

const STORAGE_KEY = 'password_vault_blob_v1'
const WEBAUTHN_KEY = 'password_vault_webauthn'

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
}

function base64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0))
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
  const parsed = JSON.parse(vaultBlob) as { salt: string; iv: string; data: string }
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

function generatePassword(length: number): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%&*?'
  const bytes = crypto.getRandomValues(new Uint8Array(length))
  return Array.from(bytes, (byte) => chars[byte % chars.length]).join('')
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

async function lazyLoadXLSX() {
  const { read, utils } = await import('xlsx')
  return { read, utils }
}

async function registerWebAuthn(displayName: string): Promise<boolean> {
  try {
    if (!window.PublicKeyCredential) {
      return false
    }

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
          residentKey: 'preferred',
          userVerification: 'preferred',
        },
      } as PublicKeyCredentialCreationOptions,
    })

    if (!credential) {
      return false
    }

    localStorage.setItem(WEBAUTHN_KEY, JSON.stringify({ registered: true, timestamp: Date.now() }))
    return true
  } catch {
    return false
  }
}

async function authenticateWebAuthn(): Promise<boolean> {
  try {
    if (!window.PublicKeyCredential) {
      return false
    }

    const assertion = await navigator.credentials.get?.({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        timeout: 60000,
        userVerification: 'preferred',
      } as PublicKeyCredentialRequestOptions,
    })

    return !!assertion
  } catch {
    return false
  }
}

function isWebAuthnAvailable(): boolean {
  return !!window.PublicKeyCredential && !!localStorage.getItem(WEBAUTHN_KEY)
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
  const [lockMinutes, setLockMinutes] = useState(5)
  const [toast, setToast] = useState('')
  const [importStatus, setImportStatus] = useState('')
  const [showFormPassword, setShowFormPassword] = useState(false)
  const [visiblePasswords, setVisiblePasswords] = useState<Record<string, boolean>>({})
  const [installPrompt, setInstallPrompt] = useState<BeforeInstallPromptEvent | null>(null)
  const [webauthnAvailable, setWebauthnAvailable] = useState(false)
  const [selectedTags, setSelectedTags] = useState<string[]>([])
  const fileInputRef = useRef<HTMLInputElement>(null)
  const backupFileRef = useRef<HTMLInputElement>(null)
  const [hasVault, setHasVault] = useState(() => Boolean(localStorage.getItem(STORAGE_KEY)))

  useEffect(() => {
    setWebauthnAvailable(isWebAuthnAvailable())
  }, [])

  useEffect(() => {
    if (!isLocked || !masterPassword) {
      return
    }

    setMasterPassword('')
  }, [isLocked, masterPassword])

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
    let timeout = window.setTimeout(() => setIsLocked(true), timeoutMs)

    const resetLockTimer = () => {
      clearTimeout(timeout)
      timeout = window.setTimeout(() => setIsLocked(true), timeoutMs)
    }

    const events = ['mousemove', 'keydown', 'mousedown', 'touchstart', 'scroll']
    events.forEach((eventName) => window.addEventListener(eventName, resetLockTimer, { passive: true }))

    return () => {
      clearTimeout(timeout)
      events.forEach((eventName) => window.removeEventListener(eventName, resetLockTimer))
    }
  }, [isLocked, lockMinutes])

  const allTags = useMemo(() => {
    const tags = new Set<string>()
    items.forEach((item) => item.tags.forEach((tag) => tags.add(tag)))
    return Array.from(tags).sort()
  }, [items])

  const filteredItems = useMemo(() => {
    const q = query.toLowerCase().trim()
    const sorted = [...items].sort((a, b) => a.title.localeCompare(b.title))

    return sorted.filter((item) => {
      const matchesQuery =
        !q ||
        [item.title, item.username, item.website, item.notes].some((field) => field.toLowerCase().includes(q))

      const matchesTags = selectedTags.length === 0 || selectedTags.some((tag) => item.tags.includes(tag))

      return matchesQuery && matchesTags
    })
  }, [items, query, selectedTags])

  const passwordStrength = useMemo(() => getPasswordStrength(form.password), [form.password])

  const persistItems = async (nextItems: VaultItem[]) => {
    const blob = await encryptVault(masterPassword, { items: nextItems })
    localStorage.setItem(STORAGE_KEY, blob)
    setItems(nextItems)
  }

  const createVault = async (event: FormEvent) => {
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
    setItems([])
    setIsLocked(false)
    setUnlockError('')
  }

  const unlockVault = async (event: FormEvent) => {
    event.preventDefault()
    try {
      const blob = localStorage.getItem(STORAGE_KEY)
      if (!blob) {
        setUnlockError('No vault found.')
        return
      }
      const payload = await decryptVault(masterPassword, blob)
      setItems((payload.items ?? []).map((item) => ({ ...item, tags: item.tags ?? [] })))
      setIsLocked(false)
      setUnlockError('')
    } catch {
      setUnlockError('Incorrect master password.')
    }
  }

  const unlockWithBiometric = async () => {
    try {
      const success = await authenticateWebAuthn()
      if (!success) {
        setUnlockError('Biometric authentication failed.')
        return
      }

      const blob = localStorage.getItem(STORAGE_KEY)
      if (!blob) {
        setUnlockError('No vault found.')
        return
      }
      setItems((await decryptVault(masterPassword, blob)).items ?? [])
      setIsLocked(false)
      setUnlockError('')
      setToast('Unlocked with biometric')
    } catch {
      setUnlockError('Biometric authentication failed.')
    }
  }

  const lockNow = () => {
    setIsLocked(true)
    setItems([])
    setForm(emptyForm)
    setEditingId(null)
    setQuery('')
    setVisiblePasswords({})
    setSelectedTags([])
  }

  const saveEntry = async (event: FormEvent) => {
    event.preventDefault()
    if (!form.title || !form.username || !form.password) {
      return
    }

    const now = new Date().toISOString()
    const nextItems = editingId
      ? items.map((item) => (item.id === editingId ? { ...item, ...form, updatedAt: now } : item))
      : [{ id: crypto.randomUUID(), ...form, updatedAt: now }, ...items]

    await persistItems(nextItems)
    setForm(emptyForm)
    setEditingId(null)
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

  const deleteEntry = async (id: string) => {
    const nextItems = items.filter((item) => item.id !== id)
    await persistItems(nextItems)
  }

  const copyText = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      setToast('Copied')
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

  const parseExcelRows = (rows: Record<string, unknown>[]): VaultItem[] => {
    const now = new Date().toISOString()

    return rows
      .map((row) => {
        const normalized = new Map<string, string>()
        for (const [key, value] of Object.entries(row)) {
          normalized.set(normalizeHeader(key), toText(value))
        }

        const company = normalized.get('company') ?? ''
        const account = normalized.get('account') ?? ''
        const service = normalized.get('service') ?? ''
        const username = normalized.get('username') ?? ''
        const password = normalized.get('password') ?? ''
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
      const firstSheetName = workbook.SheetNames[0]
      if (!firstSheetName) {
        setImportStatus('Import failed: no sheet found.')
        return
      }

      const sheet = workbook.Sheets[firstSheetName]
      const rows = utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: '' })
      const imported = parseExcelRows(rows)

      if (imported.length === 0) {
        setImportStatus('No rows with password data were found.')
        return
      }

      const existingByKey = new Map(
        items.map((item) => [
          `${item.title.toLowerCase()}|${item.username.toLowerCase()}|${item.website.toLowerCase()}`,
          item,
        ]),
      )

      for (const importedItem of imported) {
        const key = `${importedItem.title.toLowerCase()}|${importedItem.username.toLowerCase()}|${importedItem.website.toLowerCase()}`
        existingByKey.set(key, importedItem)
      }

      const merged = Array.from(existingByKey.values())
      await persistItems(merged)
      setImportStatus(`Imported ${imported.length} entries from ${file.name}.`)
      setToast('Import complete')
    } catch {
      setImportStatus('Import failed: unsupported or corrupted file.')
    } finally {
      event.target.value = ''
    }
  }

  const exportVault = async () => {
    const now = new Date().toISOString().slice(0, 10)
    const blob = new Blob([JSON.stringify({ items, exportedAt: now }, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `vault-backup-${now}.json`
    a.click()
    URL.revokeObjectURL(url)
    setToast('Backup downloaded')
  }

  const handleVaultImport = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }

    try {
      const text = await file.text()
      const data = JSON.parse(text) as { items: VaultItem[] }

      if (!Array.isArray(data.items)) {
        setImportStatus('Invalid backup file format.')
        return
      }

      const normalized = data.items.map((item) => ({ ...item, tags: item.tags ?? [] }))
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
      setImportStatus('Restore failed: invalid or corrupted backup file.')
    } finally {
      event.target.value = ''
    }
  }

  const registerBiometric = async () => {
    try {
      const success = await registerWebAuthn('Password Vault User')
      if (success) {
        setWebauthnAvailable(true)
        setToast('Biometric registered')
      } else {
        setUnlockError('Biometric registration not available on this device.')
      }
    } catch {
      setUnlockError('Biometric registration failed.')
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
                  required
                />
              </label>
              <label>
                Confirm password
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
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
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Find by title, username, website"
              />
            </label>
            <label>
              Auto-lock
              <select value={lockMinutes} onChange={(event) => setLockMinutes(Number(event.target.value))}>
                <option value={1}>1 minute</option>
                <option value={5}>5 minutes</option>
                <option value={15}>15 minutes</option>
              </select>
            </label>
            <button type="button" className="secondary" onClick={openExcelImportPicker}>
              Import Excel
            </button>
            <button type="button" className="secondary" onClick={exportVault}>
              Export
            </button>
            <button type="button" className="secondary" onClick={openVaultImportPicker}>
              Restore
            </button>
            <button type="button" onClick={lockNow} className="secondary">
              Lock now
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".xlsx,.xls,.csv"
              onChange={handleExcelImport}
              className="hidden"
            />
            <input ref={backupFileRef} type="file" accept=".json" onChange={handleVaultImport} className="hidden" />
          </section>

          {importStatus && <p className="import-status">{importStatus}</p>}

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
              <label>
                Tags
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
              </label>
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

          <section className="entries">
            {filteredItems.length === 0 ? (
              <p className="empty">No entries yet.</p>
            ) : (
              filteredItems.map((item) => (
                <article key={item.id} className="card item">
                  <div>
                    <h3>{item.title}</h3>
                    <p>{item.username}</p>
                    {item.website && (
                      <a href={item.website.startsWith('http') ? item.website : `https://${item.website}`} target="_blank" rel="noreferrer">
                        {item.website}
                      </a>
                    )}
                    <p className="masked">{visiblePasswords[item.id] ? item.password : '••••••••••••'}</p>
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
                    <button type="button" className="secondary" onClick={() => copyText(item.username)}>
                      Copy Username
                    </button>
                    <button type="button" className="secondary" onClick={() => copyText(item.password)}>
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
                    <button type="button" className="danger" onClick={() => deleteEntry(item.id)}>
                      Delete
                    </button>
                  </div>
                </article>
              ))
            )}
          </section>

          {!webauthnAvailable && (
            <section className="card">
              <p>
                <button type="button" className="secondary" onClick={registerBiometric}>
                  Register Biometric for Faster Unlock
                </button>
              </p>
            </section>
          )}
        </>
      )}
    </div>
  )
}

export default App
