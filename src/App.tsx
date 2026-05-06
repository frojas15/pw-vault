import { useEffect, useMemo, useRef, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'
import * as XLSX from 'xlsx'
import './App.css'

type VaultItem = {
  id: string
  title: string
  username: string
  password: string
  website: string
  notes: string
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

const emptyForm = {
  title: '',
  username: '',
  password: '',
  website: '',
  notes: '',
}

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
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [hasVault, setHasVault] = useState(() => Boolean(localStorage.getItem(STORAGE_KEY)))

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

  const filteredItems = useMemo(() => {
    const q = query.toLowerCase().trim()
    const sorted = [...items].sort((a, b) => a.title.localeCompare(b.title))

    if (!q) {
      return sorted
    }

    return sorted.filter((item) => {
      return [item.title, item.username, item.website, item.notes].some((field) =>
        field.toLowerCase().includes(q),
      )
    })
  }, [items, query])

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
      setItems(payload.items ?? [])
      setIsLocked(false)
      setUnlockError('')
    } catch {
      setUnlockError('Incorrect master password.')
    }
  }

  const lockNow = () => {
    setIsLocked(true)
    setItems([])
    setForm(emptyForm)
    setEditingId(null)
    setQuery('')
    setVisiblePasswords({})
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
          updatedAt: now,
        }
      })
      .filter((item) => Boolean(item.password && (item.username || item.title)))
  }

  const handleImport = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) {
      return
    }

    try {
      const buffer = await file.arrayBuffer()
      const workbook = XLSX.read(buffer)
      const firstSheetName = workbook.SheetNames[0]
      if (!firstSheetName) {
        setImportStatus('Import failed: no sheet found.')
        return
      }

      const sheet = workbook.Sheets[firstSheetName]
      const rows = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: '' })
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

  const openImportPicker = () => {
    fileInputRef.current?.click()
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
            <button type="button" className="secondary" onClick={openImportPicker}>
              Import Excel
            </button>
            <button type="button" onClick={lockNow} className="secondary">
              Lock now
            </button>
            <input
              ref={fileInputRef}
              type="file"
              accept=".xlsx,.xls,.csv"
              onChange={handleImport}
              className="hidden"
            />
          </section>

          {importStatus && <p className="import-status">{importStatus}</p>}

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
                      {visiblePasswords[item.id] ? 'Hide Password' : 'Show Password'}
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
        </>
      )}
    </div>
  )
}

export default App
