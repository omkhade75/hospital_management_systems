-- 1. Helper Functions for Security
-- Checks if the current user has any staff role
CREATE OR REPLACE FUNCTION public.is_staff()
RETURNS boolean AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.user_roles 
    WHERE user_id = auth.uid() 
    AND role IN ('admin', 'doctor', 'nurse', 'receptionist', 'cashier')
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Checks if the current user is an admin
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.user_roles 
    WHERE user_id = auth.uid() 
    AND role = 'admin'
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 2. Enable RLS on valid tables
ALTER TABLE public.patients ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.doctors ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.appointments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.patient_appointments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.departments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.staff_approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- 3. Define Policies

-- --- PATIENTS TABLE ---
-- Staff can view/edit all patients
CREATE POLICY "Staff Full Access Patients" ON public.patients
FOR ALL USING (public.is_staff());

-- Patients can view ONLY their own record (linked via email matching auth email for simplicity, or patient_accounts)
-- Optimized for email match as primary link
CREATE POLICY "Patients View Own Record" ON public.patients
FOR SELECT USING (
  email = auth.jwt() ->> 'email'
);


-- --- DOCTORS TABLE ---
-- Everyone (including public) can view doctors (for landing page)
CREATE POLICY "Public View Doctors" ON public.doctors
FOR SELECT USING (true);

-- Only Admin can manage doctors
CREATE POLICY "Admin Manage Doctors" ON public.doctors
FOR ALL USING (public.is_admin());


-- --- APPOINTMENTS TABLE ---
-- Staff can view/manage all appointments
CREATE POLICY "Staff Full Access Appointments" ON public.appointments
FOR ALL USING (public.is_staff());

-- Patients can view their own appointments
-- Assuming appointments links to patients table via patient_id
CREATE POLICY "Patients View Own Appointments" ON public.appointments
FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM public.patients p
    WHERE p.id = appointments.patient_id
    AND p.email = auth.jwt() ->> 'email'
  )
);


-- --- PATIENT APPOINTMENTS (Web Portal Requests) ---
-- Users can Create their own requests
CREATE POLICY "Users Create Appointment Requests" ON public.patient_appointments
FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Users can View their own requests
CREATE POLICY "Users View Own Appointment Requests" ON public.patient_appointments
FOR SELECT USING (auth.uid() = user_id);

-- Staff can View/Manage all requests
CREATE POLICY "Staff Manage Appointment Requests" ON public.patient_appointments
FOR ALL USING (public.is_staff());


-- --- DEPARTMENTS TABLE ---
-- Public Read
CREATE POLICY "Public View Departments" ON public.departments
FOR SELECT USING (true);

-- Admin Write
CREATE POLICY "Admin Manage Departments" ON public.departments
FOR ALL USING (public.is_admin());


-- --- USER ROLES ---
-- Users read their own role
CREATE POLICY "Users Read Own Role" ON public.user_roles
FOR SELECT USING (auth.uid() = user_id);

-- Admins manage all roles
CREATE POLICY "Admins Manage Roles" ON public.user_roles
FOR ALL USING (public.is_admin());


-- --- PROFILES ---
-- Public Read Profiles (needed for names in UI)
CREATE POLICY "Public Read Profiles" ON public.profiles
FOR SELECT USING (true);

-- Users update own profile
CREATE POLICY "Users Update Own Profile" ON public.profiles
FOR UPDATE USING (auth.uid() = user_id);


-- --- STAFF APPROVAL REQUESTS ---
-- Users can create a request
CREATE POLICY "Users Create Staff Request" ON public.staff_approval_requests
FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Users can view their own request
CREATE POLICY "Users View Own Staff Request" ON public.staff_approval_requests
FOR SELECT USING (auth.uid() = user_id);

-- Admins can view/manage all
CREATE POLICY "Admins Manage Staff Requests" ON public.staff_approval_requests
FOR ALL USING (public.is_admin());
