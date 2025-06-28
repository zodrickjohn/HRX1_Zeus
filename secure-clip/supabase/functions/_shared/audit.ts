
import { SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2'

interface AuditLogData {
  user_id: string
  device_id: string
  action: string
  target_domain?: string
  target_application?: string
  content_hash: string
  status: string
  metadata?: any
}

export async function createAuditLog(supabase: SupabaseClient, logData: AuditLogData) {
  try {
    // Get the previous log hash for chaining
    const { data: previousLog } = await supabase
      .from('audit_logs')
      .select('hmac_signature')
      .order('created_at', { ascending: false })
      .limit(1)
      .single()

    const previousLogHash = previousLog?.hmac_signature || 'genesis'

    // Create HMAC signature for tamper-proofing
    const logString = JSON.stringify({
      ...logData,
      previous_log_hash: previousLogHash,
      timestamp: new Date().toISOString()
    })

    const hmacSignature = await generateHMAC(logString)

    // Insert the audit log
    const { error } = await supabase
      .from('audit_logs')
      .insert({
        ...logData,
        hmac_signature: hmacSignature,
        previous_log_hash: previousLogHash
      })

    if (error) {
      console.error('Failed to create audit log:', error)
    }
  } catch (error) {
    console.error('Error creating audit log:', error)
  }
}

async function generateHMAC(data: string): Promise<string> {
  const secret = Deno.env.get('AUDIT_LOG_SECRET') || 'default-secret-key'
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data))
  const hashArray = Array.from(new Uint8Array(signature))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}
