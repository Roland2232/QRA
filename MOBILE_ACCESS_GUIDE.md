# 📱 Mobile Access Troubleshooting Guide

## 🚀 Quick Test

1. **Generate Test QR Code**:

   ```bash
   python generate_test_qr.py
   ```

2. **Scan the generated `mobile_test_qr.png` with your phone**

3. **If it works**: You'll see a success page with server info
4. **If it doesn't work**: Follow the troubleshooting steps below

## 🔧 Troubleshooting Steps

### Step 1: Verify Server is Running

- Open browser on your laptop: `http://172.24.7.191:5000`
- Should show the QR Attendance homepage

### Step 2: Check Network Connection

**Both devices must be on the same network:**

- **Laptop**: Connected to WiFi network (e.g., "YourWiFi")
- **Phone**: Connected to the SAME WiFi network

### Step 3: Check Firewall Settings

If your phone still can't access the server:

1. **Windows Firewall** might be blocking connections
2. **Temporarily disable** Windows Firewall:
   - Go to Windows Settings > Privacy & Security > Windows Security
   - Click "Firewall & network protection"
   - Turn off firewall for "Private network"
   - Test mobile access
   - **Remember to turn it back on later!**

### Step 4: Alternative IP Addresses

If the auto-detected IP doesn't work, try these commands to find other IPs:

```bash
# Get all IP addresses
ipconfig

# Look for "IPv4 Address" under your WiFi adapter
```

Common IP ranges:

- `192.168.1.x` (most home routers)
- `192.168.0.x` (some routers)
- `10.0.0.x` (some networks)
- `172.x.x.x` (current detected)

### Step 5: Manual IP Configuration

If you need to manually set the IP address:

1. Edit `app.py`
2. Change line: `app.config['SERVER_IP'] = get_local_ip()`
3. To: `app.config['SERVER_IP'] = 'YOUR_CORRECT_IP'`
4. Restart the app: `python app.py`

## 🎯 Success Indicators

### ✅ Working QR Codes Should:

- Open a webpage on your phone
- Show course registration or attendance forms
- Display properly formatted pages

### ❌ Common Error Signs:

- "Site can't be reached"
- "Connection timeout"
- "No internet connection" (but you have internet)
- QR code doesn't scan at all

## 🔄 After Fixing

1. **Regenerate all QR codes** by creating new courses/attendance sessions
2. **Old QR codes** may still point to the wrong IP
3. **Test with the mobile test QR first** before using real course QR codes

## 📞 Still Having Issues?

The most common cause is **network mismatch**:

- Laptop on WiFi
- Phone on mobile data (or different WiFi)

**Solution**: Make sure both devices are on the same WiFi network!
