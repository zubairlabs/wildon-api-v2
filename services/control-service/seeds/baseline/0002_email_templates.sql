INSERT INTO control_app.email_templates (
  template_name,
  subject_template,
  html_template,
  placeholders,
  updated_by
)
VALUES
  (
    'email-otp',
    'Your verification code',
    '<h2>Email verification</h2><p>Your one-time verification code is <strong>{{otp_code}}</strong>.</p><p>This code expires in 10 minutes.</p>',
    ARRAY['otp_code']::TEXT[],
    'seed'
  ),
  (
    'welcome',
    'Welcome to Wildon',
    '<h2>Welcome to Wildon</h2><p>Your email <strong>{{email}}</strong> has been verified successfully.</p><p>You can now sign in and start using your account.</p>',
    ARRAY['email']::TEXT[],
    'seed'
  ),
  (
    'password-reset-request',
    'Password reset code',
    '<h2>Password reset request</h2><p>Use this one-time password reset code: <strong>{{otp_code}}</strong>.</p><p>If you did not request this, you can ignore this email.</p>',
    ARRAY['otp_code']::TEXT[],
    'seed'
  ),
  (
    'password-changed-success',
    'Your password has been changed',
    '<h2>Password changed</h2><p>Your password for <strong>{{email}}</strong> was changed successfully.</p><p>Changed at: {{changed_at}}</p><p>If this was not you, contact support immediately.</p>',
    ARRAY['email', 'changed_at']::TEXT[],
    'seed'
  )
ON CONFLICT (template_name)
DO UPDATE SET
  subject_template = EXCLUDED.subject_template,
  html_template = EXCLUDED.html_template,
  placeholders = EXCLUDED.placeholders,
  updated_by = EXCLUDED.updated_by,
  updated_at = NOW();
