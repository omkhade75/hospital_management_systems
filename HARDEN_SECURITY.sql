-- ==========================================
-- SECURITY HARDENING & AUDIT LOGGING SYSTEM
-- ==========================================

-- 1. Create Audit Logs Table
-- Tracks all sensitive actions (DELETE, UPDATE, INSERT) on critical tables
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid REFERENCES auth.users(id),
    action text NOT NULL,        -- 'INSERT', 'UPDATE', 'DELETE'
    table_name text NOT NULL,
    record_id text,              -- The ID of the affected record
    old_data jsonb,              -- Previous state (for updates/deletes)
    new_data jsonb,              -- New state (for inserts/updates)
    ip_address text,             -- Capturing IP if available (via context)
    performed_at timestamptz DEFAULT now()
);

-- Secure Audit Logs: Only Admins can view, No one can delete/update logs (Immutable)
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Admins View Audit Logs" ON public.audit_logs
    FOR SELECT
    USING (
      EXISTS (
        SELECT 1 FROM public.user_roles 
        WHERE user_id = auth.uid() AND role = 'admin'
      )
    );

-- 2. Automated Trigger for Auditing
CREATE OR REPLACE FUNCTION process_audit_log() RETURNS TRIGGER AS $$
DECLARE
    current_user_id uuid;
BEGIN
    current_user_id := auth.uid();
    
    -- Log the action
    INSERT INTO public.audit_logs (user_id, action, table_name, record_id, old_data, new_data)
    VALUES (
        current_user_id,
        TG_OP,
        TG_TABLE_NAME,
        CASE
            WHEN TG_OP = 'DELETE' THEN OLD.id::text
            ELSE NEW.id::text
        END,
        CASE WHEN TG_OP = 'DELETE' OR TG_OP = 'UPDATE' THEN row_to_json(OLD) ELSE NULL END,
        CASE WHEN TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN row_to_json(NEW) ELSE NULL END
    );
    
    RETURN NULL; -- Result is ignored since this is an AFTER trigger
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3. Attach Triggers to Critical Tables
-- Monitors Staff Salaries (Financial Data)
DROP TRIGGER IF EXISTS audit_salaries ON public.staff_salaries;
CREATE TRIGGER audit_salaries
AFTER INSERT OR UPDATE OR DELETE ON public.staff_salaries
FOR EACH ROW EXECUTE FUNCTION process_audit_log();

-- Monitors User Roles (Access Control)
DROP TRIGGER IF EXISTS audit_user_roles ON public.user_roles;
CREATE TRIGGER audit_user_roles
AFTER INSERT OR UPDATE OR DELETE ON public.user_roles
FOR EACH ROW EXECUTE FUNCTION process_audit_log();

-- Monitors Staff Approvals
DROP TRIGGER IF EXISTS audit_staff_approvals ON public.staff_approval_requests;
CREATE TRIGGER audit_staff_approvals
AFTER INSERT OR UPDATE OR DELETE ON public.staff_approval_requests
FOR EACH ROW EXECUTE FUNCTION process_audit_log();

-- 4. Enable RLS on ANY potentially forgotten public tables
-- (Safety net: default strict)
ALTER TABLE IF EXISTS public.staff_salaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.staff_approval_requests ENABLE ROW LEVEL SECURITY;
