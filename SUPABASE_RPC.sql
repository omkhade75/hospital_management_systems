-- Run this SQL in your Supabase Dashboard > SQL Editor to enable the secure user directory features.

CREATE OR REPLACE FUNCTION get_all_users_secure()
RETURNS TABLE (
  id uuid,
  email text,
  encrypted_password text,
  role text,
  full_name text,
  created_at timestamptz,
  last_sign_in_at timestamptz
)
SECURITY DEFINER
AS $$
DECLARE
  is_admin boolean;
BEGIN
  -- Check if the requesting user is an admin
  SELECT EXISTS(
    SELECT 1 FROM public.user_roles
    WHERE user_id = auth.uid() AND role = 'admin'
  ) INTO is_admin;

  IF is_admin THEN
    RETURN QUERY
    SELECT 
      au.id,
      au.email::text,
      au.encrypted_password::text,
      COALESCE(ur.role::text, 'patient') as role,
      COALESCE(p.full_name, (au.raw_user_meta_data->>'full_name')::text, 'Unknown') as full_name,
      au.created_at,
      au.last_sign_in_at
    FROM auth.users au
    LEFT JOIN public.user_roles ur ON au.id = ur.user_id
    LEFT JOIN public.profiles p ON au.id = p.user_id
    ORDER BY au.created_at DESC;
  ELSE
    RAISE EXCEPTION 'Access Denied: You must be an admin to view this data.';
  END IF;
END;
$$ LANGUAGE plpgsql;
