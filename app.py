import os
import random
import re
import sqlite3
import google.generativeai as genai
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'cyber_shield_secret_key_2024'

# ============= GEMINI API CONFIGURATION =============
# Get FREE API key from: https://aistudio.google.com/
GEMINI_API_KEY = "AIzaSyC8F_hMD14zz9DaE7pgUDa9wDmmyF6Ku_o"  # ✅ APNA API KEY YAHAN DALO

# Configure Gemini
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-1.5-flash')  # Free model
    GEMINI_AVAILABLE = True
    print("✅ Gemini API Configured!")
else:
    GEMINI_AVAILABLE = False
    print("⚠️ Gemini API not configured. Using local detection only.")

# ============= DATABASE SETUP =============
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  name TEXT NOT NULL, 
                  email TEXT UNIQUE NOT NULL, 
                  password TEXT NOT NULL,
                  phone TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    try:
        c.execute("SELECT phone FROM users LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    conn.commit()
    conn.close()
    print("✅ Database ready!")

init_db()

# ============= GEMINI AI THREAT ANALYSIS =============
def analyze_with_gemini(text):
    """Use Gemini AI to analyze threat"""
    if not GEMINI_AVAILABLE:
        return None
    
    try:
        prompt = f"""
        You are a cybersecurity expert. Analyze this message and tell me:
        1. Is this message a scam or threat? (YES/NO)
        2. What type of scam is it? (Payment Fraud, Job Scam, Phishing, Blackmail, Investment Scam, Lottery Scam, Safe)
        3. Risk level: HIGH, MEDIUM, or LOW
        4. Explain the problem in simple words
        5. Explain why it's dangerous
        6. Give 3 actions the user should take

        Message: "{text}"

        Respond in this exact JSON format:
        {{
            "is_threat": true/false,
            "category": "type of scam",
            "risk": "HIGH/MEDIUM/LOW",
            "problem": "what is the problem",
            "danger": "why it's dangerous",
            "actions": ["action1", "action2", "action3"]
        }}
        """
        
        response = model.generate_content(prompt)
        result_text = response.text
        
        # Clean the response (remove markdown if any)
        result_text = result_text.replace('```json', '').replace('```', '').strip()
        
        import json
        result = json.loads(result_text)
        
        return {
            "risk": result.get("risk", "MEDIUM"),
            "category": result.get("category", "Unknown"),
            "problem": result.get("problem", "AI analysis completed"),
            "danger": result.get("danger", "AI detected suspicious content"),
            "steps": [
                {"text": action, "icon": "fa-solid fa-shield-alt", "color": "#3b82f6"} 
                for action in result.get("actions", [])
            ]
        }
    except Exception as e:
        print(f"Gemini API Error: {e}")
        return None

# ============= LOCAL THREAT ANALYSIS (Fallback) =============
def analyze_locally(text):
    text_lower = text.lower()
    urls = re.findall(r'(?:https?://|www\.)[^\s<>"{}|\\^`\[\]]+', text, re.IGNORECASE)
    
    # Payment Fraud
    if any(k in text_lower for k in ['payment failed', 'upi', 'transaction failed', 'refund', 'pay now', 'otp']):
        return {
            "risk": "HIGH",
            "category": "💰 Payment Fraud",
            "problem": "💰 PAYMENT FRAUD DETECTED! Fake payment/UPI request.",
            "danger": "⚠️ Your bank account or UPI credentials could be stolen.",
            "steps": [
                {"text": "❌ NEVER share OTP with anyone", "icon": "fa-solid fa-ban", "color": "#dc2626"},
                {"text": "🏦 Check your bank app directly", "icon": "fa-solid fa-building", "color": "#3b82f6"},
                {"text": "📞 Call bank customer care on official number", "icon": "fa-solid fa-phone-alt", "color": "#10b981"}
            ]
        }
    # Job Scam
    elif ('job' in text_lower or 'work from home' in text_lower) and ('fee' in text_lower or 'registration' in text_lower):
        return {
            "risk": "HIGH",
            "category": "💼 Job Scam",
            "problem": "💼 JOB SCAM DETECTED! Fake job offer demanding registration fee.",
            "danger": "⚠️ You may lose money to fraudsters.",
            "steps": [
                {"text": "🔴 Block this sender immediately", "icon": "fa-solid fa-ban", "color": "#dc2626"},
                {"text": "💵 NEVER pay any registration fee", "icon": "fa-solid fa-money-bill", "color": "#f59e0b"},
                {"text": "🏢 Verify company on official website", "icon": "fa-solid fa-building", "color": "#3b82f6"}
            ]
        }
    # Phishing
    elif any(k in text_lower for k in ['blocked', 'verify', 'click here', 'bit.ly', 'tinyurl', 'login']):
        return {
            "risk": "HIGH",
            "category": "🎣 Phishing Attack",
            "problem": "🎣 PHISHING ATTACK DETECTED! Fake verification request.",
            "danger": "⚠️ Your password or credit card can be stolen.",
            "steps": [
                {"text": "❌ DO NOT click any link", "icon": "fa-solid fa-ban", "color": "#dc2626"},
                {"text": "🗑️ Delete this message immediately", "icon": "fa-solid fa-trash-alt", "color": "#f59e0b"},
                {"text": "🔐 Enable Two-Factor Authentication", "icon": "fa-solid fa-shield-alt", "color": "#10b981"}
            ]
        }
    # Blackmail
    elif any(k in text_lower for k in ['private video', 'blackmail', 'leak', 'pay me']):
        return {
            "risk": "HIGH",
            "category": "💀 Blackmail",
            "problem": "💀 BLACKMAIL ATTEMPT DETECTED! Someone is trying to extort you.",
            "danger": "⚠️ NEVER pay. Report immediately.",
            "steps": [
                {"text": "🚫 NEVER pay. Do not engage", "icon": "fa-solid fa-gavel", "color": "#dc2626"},
                {"text": "📸 Preserve evidence: screenshots", "icon": "fa-solid fa-camera", "color": "#f59e0b"},
                {"text": "📞 Contact Cyber Crime Helpline 1930", "icon": "fa-solid fa-phone-alt", "color": "#3b82f6"}
            ]
        }
    # Investment Scam
    elif any(k in text_lower for k in ['double your money', 'investment', 'guarantee returns', 'crypto']):
        return {
            "risk": "HIGH",
            "category": "📈 Investment Scam",
            "problem": "📈 INVESTMENT SCAM DETECTED! Fake investment with guaranteed returns.",
            "danger": "⚠️ You will lose your entire investment amount.",
            "steps": [
                {"text": "❌ NEVER invest based on SMS", "icon": "fa-solid fa-ban", "color": "#dc2626"},
                {"text": "🏢 Only invest through SEBI registered brokers", "icon": "fa-solid fa-building", "color": "#3b82f6"},
                {"text": "📞 Report to SEBI helpline 1800 22 7575", "icon": "fa-solid fa-phone-alt", "color": "#10b981"}
            ]
        }
    # Lottery Scam
    elif any(k in text_lower for k in ['lottery', 'won', 'prize', 'congratulations', 'lucky draw']):
        return {
            "risk": "HIGH",
            "category": "🎁 Lottery Scam",
            "problem": "🎁 LOTTERY SCAM DETECTED! Fake lottery/prize winning notification.",
            "danger": "⚠️ Fraudsters ask for processing fee to release fake prizes.",
            "steps": [
                {"text": "❌ NEVER pay any 'processing fee'", "icon": "fa-solid fa-ban", "color": "#dc2626"},
                {"text": "🗑️ Delete this message immediately", "icon": "fa-solid fa-trash-alt", "color": "#f59e0b"},
                {"text": "📢 Report to cyber crime", "icon": "fa-solid fa-flag", "color": "#3b82f6"}
            ]
        }
    # Suspicious URL
    elif urls:
        return {
            "risk": "MEDIUM",
            "category": "🔗 Suspicious Link",
            "problem": "🔗 EXTERNAL LINK DETECTED without context.",
            "danger": "🌐 Potential redirect to phishing or malware site.",
            "steps": [{"text": "🔍 Verify URL before clicking", "icon": "fa-solid fa-link", "color": "#f59e0b"}]
        }
    # Safe
    else:
        return {
            "risk": "LOW",
            "category": "✅ Safe",
            "problem": "✅ No threats detected.",
            "danger": "Message appears legitimate and safe.",
            "steps": [{"text": "✓ No action required", "icon": "fa-solid fa-check-circle", "color": "#10b981"}]
        }

# ============= MAIN ANALYSIS FUNCTION =============
def analyze_threat(text, msg_type='SMS', sender=''):
    # First try Gemini AI (if available)
    if GEMINI_AVAILABLE:
        gemini_result = analyze_with_gemini(text)
        if gemini_result:
            return {
                "risk": gemini_result["risk"],
                "severity": 95 if gemini_result["risk"] == "HIGH" else (60 if gemini_result["risk"] == "MEDIUM" else 10),
                "confidence": 98,
                "category": gemini_result["category"],
                "problem_description": gemini_result["problem"],
                "risk_analysis": gemini_result["danger"],
                "tactical_steps": gemini_result["steps"],
                "detected_urls": re.findall(r'(?:https?://|www\.)[^\s<>"{}|\\^`\[\]]+', text, re.IGNORECASE),
                "raw_text": text,
                "type": msg_type,
                "ai_source": "Gemini AI"
            }
    
    # Fallback to local detection
    local_result = analyze_locally(text)
    return {
        "risk": local_result["risk"],
        "severity": 94 if local_result["risk"] == "HIGH" else (55 if local_result["risk"] == "MEDIUM" else 8),
        "confidence": 95,
        "category": local_result["category"],
        "problem_description": local_result["problem"],
        "risk_analysis": local_result["danger"],
        "tactical_steps": local_result["steps"],
        "detected_urls": re.findall(r'(?:https?://|www\.)[^\s<>"{}|\\^`\[\]]+', text, re.IGNORECASE),
        "raw_text": text,
        "type": msg_type,
        "ai_source": "Local Detection"
    }

# ============= API ENDPOINTS =============
@app.route('/api/analyze', methods=['POST'])
def analyze():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    text = data.get('text', '')
    msg_type = data.get('type', 'SMS')
    sender = data.get('sender', '')
    
    if not text:
        return jsonify({"error": "No text provided"}), 400
    
    result = analyze_threat(text, msg_type, sender)
    return jsonify(result)

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "gemini_available": GEMINI_AVAILABLE,
        "timestamp": datetime.now().isoformat()
    })

# ============= WEB ROUTES =============
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', user_name=session.get('name', 'User'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        phone = request.form.get('phone', '')
        
        if not name or not email or not password:
            return "All fields are required", 400
        
        hashed_pw = generate_password_hash(password)
        
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (name, email, password, phone) VALUES (?, ?, ?, ?)",
                      (name, email, hashed_pw, phone))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Email already exists", 400
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT id, name, password, phone FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['name'] = user[1]
            session['user_phone'] = user[3] or ''
            return redirect(url_for('index'))
        else:
            return "Invalid credentials", 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    print("=" * 60)
    print("🛡️ CYBER SHIELD - WITH GEMINI AI")
    print("=" * 60)
    print(f"📍 Web Dashboard: http://127.0.0.1:5000")
    print("")
    print("🤖 AI Status:")
    print(f"   └─ Gemini AI: {'✅ ACTIVE' if GEMINI_AVAILABLE else '❌ Not configured'}")
    print("")
    print("🎯 Detection Features:")
    print("   ├─ 💰 Payment Fraud")
    print("   ├─ 💼 Job Scam")
    print("   ├─ 🎣 Phishing Attack")
    print("   ├─ 💀 Blackmail")
    print("   ├─ 📈 Investment Scam")
    print("   ├─ 🎁 Lottery Scam")
    print("   └─ 🔗 Suspicious Links")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)