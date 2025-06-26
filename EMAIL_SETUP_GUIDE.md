# 📧 Email Configuration Guide for QR Attendance System

## 🚨 **IMPORTANT: Email is NOT configured yet!**

Your QR Attendance System is **LIVE** at https://qra.onrender.com but email functionality is disabled.

**Current Status:**

- ✅ **Login Working**: Admin code `23456` works
- ✅ **Teacher Creation**: Teachers can be created but credentials won't be emailed
- ❌ **Email Disabled**: Environment variables not set

---

## 📋 **Step-by-Step Email Configuration**

### **Step 1: Get Gmail App Password**

1. **Go to Google Account Settings**

   - Visit: https://myaccount.google.com/
   - Sign in with your Gmail account

2. **Enable 2-Factor Authentication**

   - Go to "Security" → "2-Step Verification"
   - Follow setup process if not already enabled

3. **Generate App Password**
   - Go to "Security" → "App passwords"
   - Select "Mail" as the app
   - Copy the **16-character password** (e.g., `abcd efgh ijkl mnop`)

### **Step 2: Configure Environment Variables in Render**

1. **Go to Render Dashboard**

   - Visit: https://dashboard.render.com/
   - Click on your **"qra"** service

2. **Go to Environment Tab**

   - Click **"Environment"** in the left sidebar
   - Click **"Add Environment Variable"**

3. **Add These Variables:**

```bash
# Email Configuration
MAIL_USERNAME=your-gmail-address@gmail.com
MAIL_PASSWORD=your-16-char-app-password
MAIL_DEFAULT_SENDER=your-gmail-address@gmail.com

# Security (Optional but recommended)
SECRET_KEY=your-random-32-plus-character-secret-key
```

### **Step 3: Example Configuration**

```bash
MAIL_USERNAME=school.admin@gmail.com
MAIL_PASSWORD=abcd efgh ijkl mnop
MAIL_DEFAULT_SENDER=school.admin@gmail.com
SECRET_KEY=super-secret-random-key-change-this-in-production-32-chars
```

### **Step 4: Redeploy**

1. **Trigger Redeploy**

   - In Render dashboard, click **"Manual Deploy"**
   - OR make a small change to any file and push to GitHub

2. **Verify Email Works**
   - Create a test teacher account
   - Check if credentials are sent via email

---

## 🎯 **Quick Email Test**

### **Test Email Configuration:**

1. **Login as Admin**: Use code `23456`
2. **Create Teacher**: Add a teacher with your email
3. **Check Email**: You should receive login credentials

### **If Email Still Doesn't Work:**

1. **Check Gmail Settings**

   - Ensure 2FA is enabled
   - Verify app password is correct
   - Check "Less secure app access" is OFF (use app password instead)

2. **Check Render Logs**

   - Go to Render dashboard → "Logs"
   - Look for email-related error messages

3. **Common Issues:**
   - Wrong app password format (should be 16 chars without spaces)
   - Gmail account doesn't have 2FA enabled
   - Wrong email address in MAIL_USERNAME

---

## 🔧 **Alternative Email Providers**

### **If Gmail doesn't work, try:**

**Outlook/Hotmail:**

```bash
MAIL_SERVER=smtp-mail.outlook.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@outlook.com
MAIL_PASSWORD=your-outlook-password
```

**Yahoo Mail:**

```bash
MAIL_SERVER=smtp.mail.yahoo.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@yahoo.com
MAIL_PASSWORD=your-yahoo-app-password
```

---

## ✅ **System Status After Email Setup**

Once email is configured, your system will have:

- ✅ **Admin Dashboard**: Working
- ✅ **Teacher Management**: Create/delete teachers
- ✅ **Course Management**: Create courses with QR codes
- ✅ **Student Registration**: Mobile-friendly QR scanning
- ✅ **Attendance Tracking**: Location-based verification
- ✅ **Email Notifications**: Teacher credentials sent automatically
- ✅ **Export Features**: PDF/Excel attendance reports

---

## 🚀 **Current Working Features (Without Email)**

Even without email, you can still use:

1. **Manual Teacher Setup**: Create teachers and manually share credentials
2. **Course Creation**: Generate QR codes for student registration
3. **Attendance Sessions**: Create mobile-friendly attendance QR codes
4. **Analytics**: View attendance statistics and reports
5. **Mobile Access**: Students can register and mark attendance via QR codes

---

## 📞 **Need Help?**

If you have issues with email configuration:

1. **Check Render Logs**: Look for specific error messages
2. **Verify Gmail Settings**: Ensure 2FA and app password are correct
3. **Test Different Email**: Try with a different Gmail account
4. **Manual Workaround**: Create teachers and share credentials manually

**Remember**: The system is fully functional except for automatic email sending!
