import fs from 'fs'
import path from 'path'
import { spawn } from 'child_process'
import dotenv from 'dotenv'

dotenv.config()
const localEnvPath = path.resolve(process.cwd(), '.env.local')
if (fs.existsSync(localEnvPath)) {
  dotenv.config({ path: localEnvPath, override: true })
}

const hasDatabaseUrl = Boolean(process.env.DATABASE_URL?.trim())
const script = hasDatabaseUrl ? 'dev:full' : 'dev:client'

if (!hasDatabaseUrl) {
  console.log(
    '[dev] DATABASE_URL absent: lancement du client uniquement (vite).',
  )
  console.log(
    '[dev] Ajoutez DATABASE_URL dans .env ou .env.local pour lancer aussi le serveur.',
  )
}

const child = spawn(`npm run ${script}`, {
  stdio: 'inherit',
  shell: true,
  env: process.env,
})

child.on('exit', (code) => {
  process.exit(code ?? 0)
})
