import { createClient } from '@supabase/supabase-js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_DEFAULT_KEY

if (!supabaseUrl) {
  throw new Error('VITE_SUPABASE_URL manquant pour Supabase Auth')
}

if (!supabaseAnonKey) {
  throw new Error('VITE_SUPABASE_PUBLISHABLE_DEFAULT_KEY manquant pour Supabase Auth')
}

// Client unique pour toutes les interactions Auth côté front.
export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
})

export type SupabaseClient = typeof supabase
