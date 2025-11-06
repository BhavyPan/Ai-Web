import os
import sys
from pathlib import Path

# Vercel-specific setup
if os.environ.get('VERCEL'):
    # Add current directory to Python path
    sys.path.append(str(Path(__file__).parent))
    
    # Set Flask environment
    os.environ['FLASK_ENV'] = 'production'

from flask import Flask, request, redirect, url_for, flash, render_template_string, jsonify, session, render_template
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import os
import json
import base64
from urllib.parse import urlencode
from datetime import datetime, timedelta
import logging
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import google.generativeai as genai
import re
from html import escape
import dateutil.parser

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyBc4XCu2aOs6eKJqu1AXJ2Vwa5qK1bamB8")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-123")
OAUTH_REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "")

app.secret_key = SECRET_KEY

# OAuth Scopes
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid"
]

# AI Functions
def setup_gemini():
    """Setup Gemini AI with proper error handling"""
    try:
        if not GEMINI_API_KEY:
            logger.error("GEMINI_API_KEY not set")
            return None
        
        genai.configure(api_key=GEMINI_API_KEY)
        return genai.GenerativeModel("gemini-1.5-flash")
    except Exception as e:
        logger.error(f"Gemini setup error: {str(e)}")
        return None

def strip_html(html_content):
    """Strip HTML tags from content"""
    cleanr = re.compile('<.*?>|&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-f]{1,6});')
    cleantext = re.sub(cleanr, '', html_content)
    return cleantext

def summarize_email(subject, body, snippet):
    """Generate AI summary for email"""
    try:
        model = setup_gemini()
        if not model:
            return "AI summarization unavailable"
        
        body_text = strip_html(body)[:4000] if body else snippet[:1000]
        
        prompt = f"""
        Please provide a concise summary of this email in 2-3 bullet points:
        
        Subject: {subject}
        Content: {body_text}
        
        Focus on:
        - Main purpose of the email
        - Key action items required
        - Important details or deadlines
        
        Format as bullet points.
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Summarization error: {str(e)}")
        return "Unable to generate summary"

def generate_smart_reply(subject, body, sender):
    """Generate smart AI reply"""
    try:
        model = setup_gemini()
        if not model:
            return "AI reply generation unavailable"
        
        body_text = strip_html(body)[:3000] if body else ""
        
        prompt = f"""
        Generate a professional email reply for this message:
        
        From: {sender}
        Subject: {subject}
        Content: {body_text}
        
        Provide 3 different reply options:
        1. Professional and formal
        2. Casual and friendly  
        3. Quick acknowledgment
        
        Format each option clearly.
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Smart reply error: {str(e)}")
        return "Unable to generate smart replies"

def generate_ai_composed_email(context, recipient, purpose, tone="professional"):
    """Generate AI-composed email from scratch"""
    try:
        model = setup_gemini()
        if not model:
            return "AI composition unavailable"
        
        prompt = f"""
        Compose an email with the following details:
        
        Recipient: {recipient}
        Purpose: {purpose}
        Context: {context}
        Tone: {tone}
        
        Please generate a complete email with:
        - Appropriate subject line
        - Professional greeting
        - Clear and concise body content
        - Professional closing
        
        Make sure the email is well-structured and appropriate for the given context and tone.
        """
        
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"AI composition error: {str(e)}")
        return "Unable to generate email content"

def get_ai_labels(subject, content, sender):
    """Get AI-generated labels for email"""
    try:
        model = setup_gemini()
        if not model:
            return ["general"]
        
        content_text = strip_html(content)[:2000] if content else ""
        
        prompt = f"""
        Analyze this email and assign relevant labels from these categories:
        - work
        - personal  
        - urgent
        - follow-up
        - meeting
        - project
        - finance
        - travel
        - social
        - newsletter
        - promotion
        - notification
        
        Email:
        Subject: {subject}
        From: {sender}
        Content: {content_text}
        
        Return only the most relevant 2-3 labels as a comma-separated list.
        """
        
        response = model.generate_content(prompt)
        labels = [label.strip().lower() for label in response.text.split(',')]
        return labels[:3]
    except Exception as e:
        logger.error(f"AI labeling error: {str(e)}")
        return ["general"]

def analyze_and_label_emails(emails):
    """Analyze emails and assign smart labels"""
    try:
        model = setup_gemini()
        if not model:
            return emails
            
        for email in emails:
            ai_labels = get_ai_labels(email['subject'], email.get('body', email['snippet']), email['sender'])
            email['ai_labels'] = ai_labels
            email['summary'] = summarize_email(email['subject'], email.get('body', email['snippet']), email['snippet'])
            
        return emails
    except Exception as e:
        logger.error(f"Smart labeling error: {str(e)}")
        return emails

# Email Processing Functions
def extract_email_body(payload):
    """Extract the email body from the payload"""
    try:
        body = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                mime_type = part.get('mimeType', '')
                if mime_type == 'text/html' and 'body' in part and 'data' in part['body']:
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    break
                elif mime_type == 'text/plain' and 'body' in part and 'data' in part['body']:
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        
        if not body and 'body' in payload and 'data' in payload['body']:
            data = payload['body']['data']
            body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        
        if not body:
            return "No email content available"
        
        return body
        
    except Exception as e:
        logger.error(f"Error extracting email body: {str(e)}")
        return "Error loading email content"

def analyze_email_priority(subject, snippet, sender):
    """AI-powered email priority analysis"""
    content = (subject + ' ' + snippet).lower()
    sender_lower = sender.lower()
    
    work_keywords = ['urgent', 'asap', 'important', 'project', 'meeting', 'deadline', 'boss', 'manager', 'team', 'report', 'presentation', 'review', 'action required']
    promo_keywords = ['sale', 'discount', 'offer', 'deal', 'promo', 'buy now', 'limited time', 'coupon', 'save', 'special', 'exclusive', 'offer']
    spam_keywords = ['winner', 'prize', 'free', 'congratulations', 'lottery', 'click here', 'unsubscribe', 'selected', 'cash', 'million']
    
    work_score = sum(1 for keyword in work_keywords if keyword in content)
    promo_score = sum(1 for keyword in promo_keywords if keyword in content)
    spam_score = sum(1 for keyword in spam_keywords if keyword in content)
    
    if any(domain in sender_lower for domain in ['company.com', 'work.com', 'corporate.com', 'hr.', 'manager']):
        work_score += 2
    
    if spam_score >= 2:
        return 'spam'
    elif work_score >= 2:
        return 'work'
    elif promo_score >= 2:
        return 'promotions'
    elif work_score >= 1:
        return 'medium'
    else:
        return 'low'

# Email Sending Function
def send_email(credentials, to, subject, body, cc=None, bcc=None):
    """Send an email using Gmail API"""
    try:
        service = build('gmail', 'v1', credentials=credentials)
        
        # Create message
        message = MIMEMultipart()
        message['to'] = to
        message['subject'] = subject
        
        if cc:
            message['cc'] = cc
        if bcc:
            message['bcc'] = bcc
            
        # Add HTML body
        html_part = MIMEText(body, 'html')
        message.attach(html_part)
        
        # Encode message
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
        
        # Send message
        sent_message = service.users().messages().send(
            userId='me',
            body={'raw': raw_message}
        ).execute()
        
        logger.info(f"Email sent successfully. Message ID: {sent_message['id']}")
        return {'success': True, 'message_id': sent_message['id']}
        
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        return {'success': False, 'error': str(e)}

# Cache/Keyword Helpers (Session-based for Vercel)
def load_ai_cache():
    return session.get('ai_cache', {})

def save_ai_cache(cache_data):
    session['ai_cache'] = cache_data

def load_keywords():
    return session.get('keyword_labels', {})

def save_keywords(data):
    session['keyword_labels'] = data

# Auth Routes and Guards
@app.before_request
def require_login_guard():
    allowed_endpoints = {"home", "auth", "oauth_callback", "health", "static"}
    if request.endpoint in allowed_endpoints:
        return None
    if request.path.startswith('/static'):
        return None
    if not session.get('google_creds'):
        return redirect(url_for('home'))

@app.route("/health")
def health():
    return jsonify({"status": "healthy"})

def get_redirect_uri():
    if OAUTH_REDIRECT_URI:
        return OAUTH_REDIRECT_URI
    base = request.host_url.rstrip('/')
    return f"{base}/oauth_callback"

def get_oauth_client_config():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise RuntimeError("Missing GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET env vars")
    
    redirect_uri = get_redirect_uri()
    return {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri]
        }
    }

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/auth")
def auth():
    """Start the OAuth flow"""
    try:
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            flash("OAuth configuration missing. Please check environment variables.")
            return redirect('/')
            
        domain = request.host_url.rstrip('/')
        redirect_uri = f"{domain}/oauth_callback"
        
        logger.info(f"Starting OAuth flow with redirect_uri: {redirect_uri}")
        
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            },
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            prompt='consent',
            include_granted_scopes='true'
        )
        
        session['oauth_state'] = state
        logger.info(f"Generated auth URL with {len(SCOPES)} scopes")
        return redirect(authorization_url)
        
    except Exception as e:
        error_msg = f'OAuth setup failed: {str(e)}'
        logger.error(f"OAuth Error: {error_msg}")
        flash(error_msg)
        return redirect('/')

@app.route("/oauth_callback")
def oauth_callback():
    """OAuth callback handler"""
    try:
        stored_state = session.get('oauth_state')
        request_state = request.args.get('state')
        
        if not stored_state or not request_state or stored_state != request_state:
            session.pop('oauth_state', None)
            flash("Authentication session expired. Please try again.")
            return redirect(url_for('home'))
            
        domain = request.host_url.rstrip('/')
        redirect_uri = f"{domain}/oauth_callback"
        
        logger.info(f"Handling OAuth callback with redirect_uri: {redirect_uri}")
        
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            },
            scopes=SCOPES,
            redirect_uri=redirect_uri,
            state=stored_state
        )
        
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        logger.info(f"Token fetched successfully! Granted {len(credentials.scopes)} scopes")
        
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        session['google_creds'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'expiry': credentials.expiry.isoformat() if credentials.expiry else None
        }
        
        session['user_info'] = user_info
        session.pop('oauth_state', None)
        
        flash(f"Successfully signed in as {user_info.get('name', 'User')}!")
        return redirect(url_for('inbox'))
        
    except Exception as e:
        session.pop('oauth_state', None)
        error_msg = f'Sign in failed: {str(e)}'
        logger.error(f"OAuth Callback Error: {error_msg}")
        flash(error_msg)
        return redirect('/')

# Gmail API Setup
def get_service():
    creds = None
    creds_data = session.get('google_creds')
    if creds_data:
        try:
            creds = Credentials(
                token=creds_data['token'],
                refresh_token=creds_data['refresh_token'],
                token_uri=creds_data['token_uri'],
                client_id=creds_data['client_id'],
                client_secret=creds_data['client_secret'],
                scopes=creds_data.get('scopes', SCOPES)
            )
        except Exception as e:
            logger.error(f"Failed to load credentials from session: {e}")
            creds = None
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                session['google_creds'] = {
                    'token': creds.token,
                    'refresh_token': creds.refresh_token,
                    'token_uri': creds.token_uri,
                    'client_id': creds.client_id,
                    'client_secret': creds.client_secret,
                    'scopes': creds.scopes,
                    'expiry': creds.expiry.isoformat() if creds.expiry else None
                }
            except Exception as e:
                logger.error(f"Token refresh failed: {e}")
                raise Exception("AUTH_REQUIRED")
        else:
            raise Exception("AUTH_REQUIRED")
    
    return build("gmail", "v1", credentials=creds)

# Email Fetching Functions
def fetch_emails(label="inbox", search_query="", max_results=20):
    try:
        service = get_service()
        ai_cache = load_ai_cache()
        
        label_map = {
            "inbox": "INBOX", "sent": "SENT", "drafts": "DRAFT",
            "starred": "STARRED", "trash": "TRASH", "spam": "SPAM"
        }
        label_ids_param = [label_map.get(label)] if label in label_map and label_map.get(label) else [label]

        q_param_parts = []
        
        if search_query:
            q_param_parts.append(search_query)
            
        if label == "inbox":
            time_filter = "newer_than:1d"
            q_param_parts.append(time_filter)
            
        if q_param_parts:
            q_param = " ".join(q_param_parts)
        else:
            q_param = None

        email_list = []
        
        # Handle drafts separately
        if label == "drafts":
            results = service.users().drafts().list(userId='me').execute()
            drafts = results.get('drafts', [])
            
            for draft in drafts[:max_results]:
                try:
                    draft_data = service.users().drafts().get(
                        userId='me', 
                        id=draft['id'], 
                        format='metadata', 
                        metadataHeaders=['Subject', 'To', 'Date']
                    ).execute()
                    
                    message = draft_data['message']
                    headers = message.get('payload', {}).get('headers', [])
                    
                    subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "(No Subject)")
                    to = next((h["value"] for h in headers if h["name"].lower() == "to"), "(No Recipient)")
                    date_raw = next((h["value"] for h in headers if h["name"].lower() == "date"), "")
                    
                    try: 
                        parsed_date = email.utils.parsedate_to_datetime(date_raw)
                        date_str = parsed_date.astimezone().strftime("%b %d, %I:%M %p")
                    except: 
                        date_str = date_raw
                    
                    email_list.append({
                        "id": draft['id'],
                        "subject": subject or "(No Subject)",
                        "sender": f"To: {to}",
                        "date": date_str,
                        "date_raw": date_raw,
                        "snippet": "Draft - Click to edit",
                        "labels": ["DRAFT"],
                        "is_urgent": False,
                        "is_draft": True
                    })
                except Exception as e:
                    logger.error(f"Error fetching draft {draft['id']}: {e}")
        else:
            # Regular emails
            res = service.users().messages().list(
                userId="me", 
                labelIds=label_ids_param, 
                q=q_param, 
                maxResults=max_results
            ).execute()
            messages = res.get("messages", [])
            
            for m in messages:
                try:
                    msg_data = service.users().messages().get(
                        userId="me", 
                        id=m["id"], 
                        format="metadata", 
                        metadataHeaders=["Subject", "From", "Date"]
                    ).execute()
                    
                    headers = msg_data.get("payload", {}).get("headers", [])
                    subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "(No Subject)")
                    sender = next((h["value"] for h in headers if h["name"].lower() == "from"), "(Unknown Sender)")
                    date_raw = next((h["value"] for h in headers if h["name"].lower() == "date"), "")
                    
                    try: 
                        parsed_date = email.utils.parsedate_to_datetime(date_raw)
                        date_str = parsed_date.astimezone().strftime("%b %d, %I:%M %p")
                    except: 
                        date_str = date_raw
                    
                    is_urgent = ai_cache.get(m["id"], {}).get("is_urgent", False)
                    
                    email_list.append({
                        "id": m["id"], 
                        "subject": subject, 
                        "sender": sender, 
                        "date": date_str, 
                        "date_raw": date_raw,
                        "snippet": msg_data.get("snippet", ""), 
                        "labels": msg_data.get("labelIds", []),
                        "is_urgent": is_urgent,
                        "is_draft": False
                    })
                except Exception as e: 
                    logger.error(f"Error fetching metadata for message {m['id']}: {e}")
                    
        return email_list
    except Exception as e: 
        logger.error(f"Error listing emails: {e}")
        flash("Error fetching emails.")
        return []

def fetch_single_email(email_id):
    try:
        service = get_service()
        msg = service.users().messages().get(userId="me", id=email_id, format="full").execute()
        payload = msg.get('payload', {})
        headers = payload.get("headers", [])

        subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "(No Subject)")
        sender = next((h["value"] for h in headers if h["name"].lower() == "from"), "(Unknown Sender)")
        date_raw = next((h["value"] for h in headers if h["name"].lower() == "date"), "")
        
        try: 
            date = email.utils.parsedate_to_datetime(date_raw).astimezone().strftime("%A, %B %d, %Y at %I:%M %p")
        except: 
            date = date_raw

        body = extract_email_body(payload)
        priority = analyze_email_priority(subject, body, sender)
        
        return {
            "id": email_id, 
            "subject": subject, 
            "sender": sender, 
            "date": date, 
            "body": body, 
            "priority": priority,
            "snippet": msg.get("snippet", "")
        }
    except Exception as e:
        logger.error(f"Error fetching single email {email_id}: {e}")
        return None

# Main Routes
@app.route("/inbox")
def inbox():
    label = request.args.get("label", "inbox")
    search_query = request.args.get("search", "")
    
    try:
        emails = fetch_emails(label, search_query)
        return render_template('inbox.html', label=label, emails=emails, search_query=search_query)
    except Exception as e:
        if "AUTH_REQUIRED" in str(e):
            return redirect(url_for('home'))
        return f"Error: {e}", 500

@app.route("/email/<email_id>")
def view_email(email_id):
    try:
        email_data = fetch_single_email(email_id)
        if not email_data:
            return "Email not found.", 404
        
        return render_template('email-view.html', email=email_data)
    except Exception as e:
        if "AUTH_REQUIRED" in str(e):
            return redirect(url_for('home'))
        return f"Error: {e}", 500

@app.route("/email/<email_id>/summary")
def email_summary(email_id):
    try:
        email_data = fetch_single_email(email_id)
        if not email_data:
            return "Email not found.", 404
        
        ai_cache = load_ai_cache()
        ai_data = ai_cache.get(email_id)
        
        if not ai_data:
            ai_data = {
                "summary": summarize_email(email_data["subject"], email_data["body"], email_data["snippet"]),
                "ai_labels": get_ai_labels(email_data["subject"], email_data["body"], email_data["sender"]),
                "smart_reply": generate_smart_reply(email_data["subject"], email_data["body"], email_data["sender"])
            }
            ai_cache[email_id] = ai_data
            save_ai_cache(ai_cache)
        
        return render_template('email-summary.html', email=email_data, ai_data=ai_data)
    except Exception as e:
        if "AUTH_REQUIRED" in str(e):
            return redirect(url_for('home'))
        return f"Error: {e}", 500

@app.route("/compose")
def compose():
    return render_template('compose.html')

@app.route("/ai-compose")
def ai_compose():
    return render_template('ai-compose.html')

@app.route("/smart-labels")
def smart_labels():
    try:
        emails = fetch_emails("inbox", "", 10)
        analyzed_emails = analyze_and_label_emails(emails)
        return render_template('smart-labels.html', emails=analyzed_emails)
    except Exception as e:
        if "AUTH_REQUIRED" in str(e):
            return redirect(url_for('home'))
        return f"Error: {e}", 500

@app.route("/dashboard")
def dashboard():
    try:
        emails = fetch_emails("inbox", "", 50)
        
        stats = {
            'total_emails': len(emails),
            'work_emails': len([e for e in emails if e.get('priority') == 'work']),
            'promo_emails': len([e for e in emails if e.get('priority') == 'promotions']),
            'low_emails': len([e for e in emails if e.get('priority') == 'low']),
        }
        
        return render_template('dashboard.html', stats=stats, emails=emails)
    except Exception as e:
        if "AUTH_REQUIRED" in str(e):
            return redirect(url_for('home'))
        return f"Error: {e}", 500

# API Routes
@app.route('/api/send-email', methods=['POST'])
def api_send_email():
    """API endpoint to send email"""
    try:
        data = request.json
        to = data.get('to')
        subject = data.get('subject')
        body = data.get('body')
        cc = data.get('cc')
        bcc = data.get('bcc')
        
        if not to or not subject or not body:
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        creds_data = session.get('google_creds')
        if not creds_data:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        credentials = Credentials(
            token=creds_data['token'],
            refresh_token=creds_data['refresh_token'],
            token_uri=creds_data['token_uri'],
            client_id=creds_data['client_id'],
            client_secret=creds_data['client_secret'],
            scopes=creds_data.get('scopes', SCOPES)
        )
        
        # Convert plain text to HTML for better formatting
        html_body = f"<div style='font-family: Arial, sans-serif; line-height: 1.6;'>{body.replace(chr(10), '<br>')}</div>"
        
        result = send_email(credentials, to, subject, html_body, cc, bcc)
        
        if result['success']:
            return jsonify({'success': True, 'message_id': result['message_id']})
        else:
            return jsonify({'success': False, 'error': result['error']})
            
    except Exception as e:
        logger.error(f"Send email error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/ai-compose-email', methods=['POST'])
def api_ai_compose_email():
    """API endpoint for AI email composition"""
    try:
        data = request.json
        recipient = data.get('recipient')
        purpose = data.get('purpose')
        context = data.get('context', '')
        tone = data.get('tone', 'professional')
        
        if not recipient or not purpose:
            return jsonify({'success': False, 'error': 'Recipient and purpose are required'})
        
        email_content = generate_ai_composed_email(context, recipient, purpose, tone)
        
        return jsonify({
            'success': True, 
            'email_content': email_content
        })
        
    except Exception as e:
        logger.error(f"AI compose error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/analyze-email/<email_id>', methods=['POST'])
def api_analyze_email(email_id):
    """API endpoint for AI email analysis"""
    try:
        email_data = fetch_single_email(email_id)
        if not email_data:
            return jsonify({'success': False, 'error': 'Email not found'})
        
        ai_data = {
            "summary": summarize_email(email_data["subject"], email_data["body"], email_data["snippet"]),
            "ai_labels": get_ai_labels(email_data["subject"], email_data["body"], email_data["sender"]),
            "smart_reply": generate_smart_reply(email_data["subject"], email_data["body"], email_data["sender"])
        }
        
        # Update cache
        ai_cache = load_ai_cache()
        ai_cache[email_id] = ai_data
        save_ai_cache(ai_cache)
        
        return jsonify({
            'success': True, 
            'analysis': ai_data
        })
        
    except Exception as e:
        logger.error(f"Email analysis error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})

# Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('home'))

# Vercel requires this
@app.route('/favicon.ico')
def favicon():
    return '', 404

# Vercel requires the app to be named 'app'
# For Vercel serverless deployment
if __name__ == '__main__':
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        logger.warning("Warning: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set. OAuth will not work.")
        logger.warning("Please set these environment variables to enable Gmail integration.")
    
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting Gmail AI Assistant on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
