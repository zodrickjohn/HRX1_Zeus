
import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { corsHeaders } from '../_shared/cors.ts'
import { createAuditLog } from '../_shared/audit.ts'

const supabaseUrl = Deno.env.get('SUPABASE_URL')!
const supabaseAnonKey = Deno.env.get('SUPABASE_ANON_KEY')!

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return new Response(JSON.stringify({ error: 'No authorization header' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    const supabase = createClient(supabaseUrl, supabaseAnonKey, {
      auth: { persistSession: false }
    })

    const token = authHeader.replace('Bearer ', '')
    const { data: { user }, error: authError } = await supabase.auth.getUser(token)

    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Invalid token' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    const url = new URL(req.url)
    const method = req.method

    if (method === 'POST' && url.pathname.endsWith('/validate')) {
      const { domain, application, device_id, content_hash } = await req.json()

      // Get user's organization
      const { data: userData } = await supabase
        .from('users')
        .select('organization_id')
        .eq('id', user.id)
        .single()

      if (!userData?.organization_id) {
        return new Response(JSON.stringify({ allowed: false, reason: 'No organization found' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        })
      }

      let allowed = true
      let reason = 'Default allow'

      // Check domain rules if domain is provided
      if (domain) {
        const { data: domainRules } = await supabase
          .from('domain_rules')
          .select('*')
          .eq('organization_id', userData.organization_id)
          .eq('is_active', true)

        if (domainRules) {
          const blacklistRule = domainRules.find(rule => 
            rule.rule_type === 'blacklist' && 
            (rule.domain === domain || domain.includes(rule.domain))
          )

          const whitelistRule = domainRules.find(rule => 
            rule.rule_type === 'whitelist' && 
            (rule.domain === domain || domain.includes(rule.domain))
          )

          if (blacklistRule) {
            allowed = false
            reason = 'Domain blacklisted'
          } else if (domainRules.some(rule => rule.rule_type === 'whitelist') && !whitelistRule) {
            allowed = false
            reason = 'Domain not whitelisted'
          }
        }
      }

      // Check application rules if application is provided
      if (application && allowed) {
        const { data: appRules } = await supabase
          .from('application_rules')
          .select('*')
          .eq('organization_id', userData.organization_id)
          .eq('is_active', true)

        if (appRules) {
          const blacklistRule = appRules.find(rule => 
            rule.rule_type === 'blacklist' && 
            application.toLowerCase().includes(rule.application_name.toLowerCase())
          )

          const whitelistRule = appRules.find(rule => 
            rule.rule_type === 'whitelist' && 
            application.toLowerCase().includes(rule.application_name.toLowerCase())
          )

          if (blacklistRule) {
            allowed = false
            reason = 'Application blacklisted'
          } else if (appRules.some(rule => rule.rule_type === 'whitelist') && !whitelistRule) {
            allowed = false
            reason = 'Application not whitelisted'
          }
        }
      }

      // Create audit log
      await createAuditLog(supabase, {
        user_id: user.id,
        device_id,
        action: allowed ? 'allow' : 'block',
        target_domain: domain,
        target_application: application,
        content_hash,
        status: allowed ? 'success' : 'blocked',
        metadata: { reason }
      })

      return new Response(JSON.stringify({ allowed, reason }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    if (method === 'GET' && url.pathname.endsWith('/rules')) {
      // Get domain and application rules for organization
      const { data: userData } = await supabase
        .from('users')
        .select('organization_id')
        .eq('id', user.id)
        .single()

      if (!userData?.organization_id) {
        return new Response(JSON.stringify({ domain_rules: [], application_rules: [] }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        })
      }

      const { data: domainRules } = await supabase
        .from('domain_rules')
        .select('*')
        .eq('organization_id', userData.organization_id)
        .eq('is_active', true)

      const { data: applicationRules } = await supabase
        .from('application_rules')
        .select('*')
        .eq('organization_id', userData.organization_id)
        .eq('is_active', true)

      return new Response(JSON.stringify({
        domain_rules: domainRules || [],
        application_rules: applicationRules || []
      }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      })
    }

    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    })

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    })
  }
})
