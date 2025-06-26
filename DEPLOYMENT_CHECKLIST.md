# 🚀 QR Attendance System - Render Deployment Checklist

## ✅ **PRE-DEPLOYMENT CHECKLIST**

### **1. GitHub Repository Setup**

- [ ] Repository created: `Roland2232/QRA`
- [ ] All files uploaded to GitHub
- [ ] Repository is **PUBLIC** (required for Render free tier)

### **2. Required Files in Repository**

- [ ] `render_app.py` - Main application file
- [ ] `render_config.py` - Configuration file
- [ ] `render_requirements.txt` - Dependencies
- [ ] `models.py` - Database models
- [ ] `templates/` folder - HTML templates
- [ ] `static/` folder - CSS, JS, images

### **3. Gmail App Password Setup**

- [ ] 2-Factor Authentication enabled on Gmail
- [ ] App Password generated (16 characters)
- [ ] App Password saved securely

---

## 🔧 **RENDER DEPLOYMENT STEPS**

### **Step 1: Create Render Account**

1. Go to [render.com](https://render.com)
2. Sign up with GitHub account
3. Verify email address

### **Step 2: Create PostgreSQL Database**

1. **Dashboard** → **New +** → **PostgreSQL**
2. **Settings**:
   - **Name**: `qr-attendance-db`
   - **Database**: `qra_attendance`
   - **User**: `qr_user`
   - **Region**: Choose closest to you
   - **Plan**: **Free** (1GB storage)
3. **Click "Create Database"**
4. **Wait 2-3 minutes** for database to be ready
5. **Copy "External Database URL"** - save this!

### **Step 3: Create Web Service**

1. **Dashboard** → **New +** → **Web Service**
2. **Connect Repository**: `Roland2232/QRA`
3. **Settings**:
   - **Name**: `qr-attendance-system`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r render_requirements.txt`
   - **Start Command**: `gunicorn render_app:app`
   - **Plan**: **Free**

### **Step 4: Configure Environment Variables**

In your Web Service → **Environment**, add:

| Variable              | Value                   | Example                               |
| --------------------- | ----------------------- | ------------------------------------- |
| `SECRET_KEY`          | Random 32+ chars        | `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6`    |
| `DATABASE_URL`        | From PostgreSQL service | `postgresql://user:pass@host:port/db` |
| `MAIL_USERNAME`       | Your Gmail              | `your-email@gmail.com`                |
| `MAIL_PASSWORD`       | Gmail App Password      | `abcd efgh ijkl mnop`                 |
| `MAIL_DEFAULT_SENDER` | Same as username        | `your-email@gmail.com`                |
| `ADMIN_SECRET_CODE`   | Admin code              | `23456`                               |

### **Step 5: Deploy**

1. **Click "Create Web Service"**
2. **Monitor build logs** (5-10 minutes)
3. **Wait for "Deploy succeeded"**
4. **Note your app URL**: `https://your-app.onrender.com`

---

## 🧪 **POST-DEPLOYMENT TESTING**

### **Immediate Tests**

- [ ] App loads without errors
- [ ] Health check works: `https://your-app.onrender.com/health`
- [ ] Login page displays correctly

### **Admin Functionality**

- [ ] Admin login works (secret code: 23456)
- [ ] Admin dashboard loads
- [ ] Can create teacher accounts
- [ ] Email sending works (check teacher creation)

### **Teacher Functionality**

- [ ] Teacher can login with generated credentials
- [ ] Teacher must change password on first login
- [ ] Can create courses
- [ ] QR codes generate correctly

### **Mobile Testing**

- [ ] QR codes scan properly on mobile
- [ ] Registration QR works
- [ ] Attendance QR works
- [ ] Geolocation features work (HTTPS required)

---

## 🎯 **SUCCESS CRITERIA**

Your deployment is successful when:

✅ **App loads instantly** (after initial wake-up)  
✅ **Admin can login** and create teachers  
✅ **Teachers receive email** with credentials  
✅ **QR codes work** on mobile devices  
✅ **Attendance tracking** functions properly  
✅ **Geolocation** works on HTTPS  
✅ **Database** stores data correctly

---

**🎉 Ready to deploy? Follow this checklist step by step for a successful deployment!**
