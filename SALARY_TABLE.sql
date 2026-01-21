-- Create a table to store staff salaries
CREATE TABLE IF NOT EXISTS public.staff_salaries (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid REFERENCES auth.users(id) NOT NULL UNIQUE,
    salary numeric DEFAULT 0,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.staff_salaries ENABLE ROW LEVEL SECURITY;

-- Create policy for Admin access (Full Access)
CREATE POLICY "Admins can manage salaries" ON public.staff_salaries
    FOR ALL
    USING (
      EXISTS (
        SELECT 1 FROM public.user_roles 
        WHERE user_id = auth.uid() AND role = 'admin'
      )
    );

-- Create policy for Staff to view their own salary (Read Only)
CREATE POLICY "Staff can view own salary" ON public.staff_salaries
    FOR SELECT
    USING (auth.uid() = user_id);
