-- Extension required for password hashing (usually enabled by default in Supabase)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- RPC Function: Allows an ADMIN to force-reset any user's password
-- This bypasses the need for the user to check their email.
CREATE OR REPLACE FUNCTION admin_reset_password(target_user_id uuid, new_password text)
RETURNS void
SECURITY DEFINER
AS $$
BEGIN
  -- 1. Security Check: Ensure the person running this is actually an Admin
  IF NOT EXISTS (
    SELECT 1 FROM public.user_roles 
    WHERE user_id = auth.uid() AND role = 'admin'
  ) THEN
    RAISE EXCEPTION 'Access Denied: Only Administrators can perform forced password resets.';
  END IF;

  -- 2. Perform the Update
  -- We use 'crypt' with 'bf' (Blowfish/bcrypt) which is the standard Supabase auth encryption
  UPDATE auth.users
  SET encrypted_password = crypt(new_password, gen_salt('bf')),
      updated_at = now()
  WHERE id = target_user_id;

END;
$$ LANGUAGE plpgsql;
