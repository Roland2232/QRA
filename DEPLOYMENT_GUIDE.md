# 🚀 QR Attendance System - Production Deployment Guide

## 📋 Prerequisites

Before deploying, ensure you have:

- Python 3.8+ installed
- MySQL server running (localhost:3307)
- Database 'Qra' created with user 'remi' (password: '1234')
- Gmail SMTP credentials configured
- Network access for mobile devices

## 🛠️ Step 1: Install Production Dependencies

```bash
# Install Waitress WSGI server
pip install waitress==3.0.0

# Or install all updated requirements
pip install -r requirements.txt
```

## 🔧 Step 2: Production Configuration

### Environment Variables (Recommended)

Create a `.env` file in your project directory:

```env
# Database Configuration
DATABASE_URL=mysql+pymysql://remi:1234@localhost:3307/Qra

# Email Configuration (Gmail)
MAIL_USERNAME=notorios2003@gmail.com
MAIL_PASSWORD=thsl usar tiol uvxi
MAIL_DEFAULT_SENDER=notorios2003@gmail.com

# Server Configuration
PORT=5000
SECRET_KEY=your-super-secret-production-key-change-this

# Admin Configuration
ADMIN_SECRET_CODE=23456
```

### Security Considerations

- Change the `SECRET_KEY` to a random, secure value
- Consider changing the `ADMIN_SECRET_CODE` for production
- Ensure MySQL user has minimal required permissions

## 🚀 Step 3: Deploy the Application

### Option A: Direct Deployment (Recommended for testing)

```bash
# Navigate to your project directory
cd C:\Users\WILLKOMMEN HP\Desktop\QRA

# Start the production server
python serve.py
```

### Option B: Background Service (Windows)

1. **Create a batch file** `start_qr_attendance.bat`:

```batch
@echo off
cd /d "C:\Users\WILLKOMMEN HP\Desktop\QRA"
python serve.py
pause
```

2. **Run as Windows Service** (Advanced):
   - Use `nssm` (Non-Sucking Service Manager)
   - Download from: https://nssm.cc/download
   - Install as Windows service

### Option C: Using Environment Variables

```bash
# Set custom port
set PORT=8080
python serve.py

# Or with PowerShell
$env:PORT=8080
python serve.py
```

## 📱 Step 4: Mobile Access Setup

### 1. Verify Network Connectivity

- Ensure laptop and phones are on the same WiFi network
- Check Windows Firewall isn't blocking connections

### 2. Test Mobile Access

```bash
# Generate test QR code
python -c "
import qrcode, socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('8.8.8.8', 80))
ip = s.getsockname()[0]
s.close()
qr = qrcode.QRCode()
qr.add_data(f'http://{ip}:5000/mobile-test')
qr.make()
qr.make_image().save('mobile_test.png')
print(f'Test QR: http://{ip}:5000/mobile-test')
"
```

### 3. Update Existing QR Codes

1. Login as admin (code: 23456)
2. Go to Admin Dashboard
3. Click "Regenerate QR Codes"
4. All existing QR codes will be updated with current IP

## 🔒 Step 5: Security Configuration

### Windows Firewall

If mobile devices can't connect:

1. **Windows Security** > **Firewall & network protection**
2. **Allow an app through firewall**
3. **Add Python** to allowed apps for private networks
4. Or temporarily disable for testing

### MySQL Security

Ensure your MySQL configuration is secure:

```sql
-- Create dedicated user with minimal permissions
CREATE USER 'qr_attendance'@'localhost' IDENTIFIED BY 'secure_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON Qra.* TO 'qr_attendance'@'localhost';
FLUSH PRIVILEGES;
```

## 📊 Step 6: Monitoring and Maintenance

### Logs

The production server creates logs in:

- **Console**: Real-time output
- **File**: `qr_attendance.log` (in project directory)

### Performance Monitoring

Monitor these aspects:

- **Response times** for mobile devices
- **Database connections** (MySQL)
- **Memory usage** of Python process
- **Network traffic** on port 5000

### Regular Maintenance

1. **Backup database** regularly
2. **Monitor log files** for errors
3. **Update dependencies** periodically
4. **Check QR code accessibility** from mobile devices

## 🚨 Troubleshooting

### Common Issues

**1. "Can't reach site" on mobile**

- Check WiFi network (same for laptop and phone)
- Verify Windows Firewall settings
- Test with `http://YOUR_IP:5000/mobile-test`

**2. Database connection errors**

```bash
# Check MySQL service
net start mysql
# Or check if running on port 3307
netstat -an | find "3307"
```

**3. QR codes show old IP**

- Login as admin and regenerate QR codes
- Or restart the server to auto-detect new IP

**4. Email not sending**

- Verify Gmail app password is correct
- Check internet connection
- Test SMTP settings

### Production Tips

1. **Use HTTPS in production** (consider reverse proxy with nginx)
2. **Set up automated backups** for MySQL database
3. **Monitor disk space** for logs and QR code images
4. **Consider load balancing** for high usage
5. **Set up health checks** to monitor server status

## 🎯 Quick Start Commands

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start production server
python serve.py

# 3. Test mobile access (scan generated QR)
python -c "import qrcode,socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(('8.8.8.8',80));ip=s.getsockname()[0];s.close();qr=qrcode.QRCode();qr.add_data(f'http://{ip}:5000/mobile-test');qr.make();qr.make_image().save('test.png');print(f'http://{ip}:5000/mobile-test')"

# 4. Access admin panel
# Browser: http://YOUR_IP:5000/login
# Admin code: 23456
```

## 📞 Support

If you encounter issues:

1. Check the `qr_attendance.log` file
2. Verify all prerequisites are met
3. Test network connectivity between devices
4. Ensure database is accessible

**🎉 Your QR Attendance System is now ready for production use!**
