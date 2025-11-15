from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit
from models import db, User, Message
from ai_helper import summarize_messages, answer_question, generate_smart_replies
from config import config
import bcrypt
import os
import logging
from flask_caching import Cache
from sqlalchemy import text
import time
import threading
from queue import Queue
from datetime import datetime
import atexit

class FilteredLogger(logging.Filter):
    def filter(self, record):
        return "write() before start_response" not in record.getMessage()

werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.addFilter(FilteredLogger())

# Initialize Flask app
app = Flask(__name__)

# Configure caching
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 60
cache = Cache(app)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

# Load configuration
env = os.environ.get('FLASK_ENV', 'development')
app.config.from_object(config[env])

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app, async_mode="threading")

clients = {}

# ==================== MESSAGE BATCHING SYSTEM ====================
class MessageBatcher:
    """Batches messages for efficient database writes"""
    
    def __init__(self, batch_size=10, flush_interval=0.5):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.message_queue = Queue()
        self.running = False
        self.worker_thread = None
        self.last_flush = time.time()
        
    def start(self):
        """Start the batching worker thread"""
        if not self.running:
            self.running = True
            self.worker_thread = threading.Thread(target=self._worker, daemon=True)
            self.worker_thread.start()
            app.logger.info("Message batcher started")
    
    def stop(self):
        """Stop the batching worker thread"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=2)
            app.logger.info("Message batcher stopped")
    
    def add_message(self, content, user_id, timestamp):
        """Add a message to the batch queue"""
        self.message_queue.put({
            'content': content,
            'user_id': user_id,
            'timestamp': timestamp
        })
    
    def _worker(self):
        """Background worker that flushes batches to database"""
        batch = []
        
        while self.running:
            try:
                time_since_flush = time.time() - self.last_flush
                should_flush_time = time_since_flush >= self.flush_interval
                
                try:
                    msg_data = self.message_queue.get(timeout=0.1)
                    batch.append(msg_data)
                except:
                    msg_data = None
                
                should_flush = (
                    len(batch) >= self.batch_size or
                    (should_flush_time and len(batch) > 0)
                )
                
                if should_flush:
                    self._flush_batch(batch)
                    batch = []
                    self.last_flush = time.time()
                    
            except Exception as e:
                app.logger.error(f'Batch worker error: {e}')
                time.sleep(0.1)
    
    def _flush_batch(self, batch):
        """Flush a batch of messages to database"""
        if not batch:
            return
        
        try:
            with app.app_context():
                messages = [
                    Message(
                        content=msg['content'],
                        user_id=msg['user_id'],
                        timestamp=msg['timestamp']
                    )
                    for msg in batch
                ]
                
                db.session.bulk_save_objects(messages)
                db.session.commit()
                
                app.logger.info(f'Batch flushed: {len(batch)} messages')
                
                invalidate_message_cache()
                
        except Exception as e:
            app.logger.error(f'Batch flush error: {e}')
            with app.app_context():
                db.session.rollback()

# Initialize message batcher
message_batcher = MessageBatcher(batch_size=10, flush_interval=0.5)

# ==================== DATABASE INITIALIZATION ====================
def init_database():
    """Initialize database with error handling"""
    try:
        with app.app_context():
            db.create_all()
            User.query.update({'is_logged_in': False})
            db.session.commit()
            app.logger.info("Database initialized successfully")
            
            message_batcher.start()
            
    except Exception as e:
        app.logger.error(f"Database initialization failed: {e}")
        print(f"WARNING: Could not initialize database: {e}")

init_database()

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found_error(error):
    app.logger.warning(f'404 error: {request.url}')
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'500 error: {error}')
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def handle_exception(error):
    db.session.rollback()
    app.logger.error(f'Unhandled exception: {error}', exc_info=True)
    return render_template('500.html'), 500

# ==================== HELPER FUNCTIONS ====================
@cache.memoize(timeout=60)
def get_recent_messages(limit=50):
    """Fetch recent messages with caching"""
    try:
        messages = Message.query.order_by(Message.timestamp.desc()).limit(limit).all()
        return [msg.to_dict() for msg in reversed(messages)]
    except Exception as e:
        app.logger.error(f'Error fetching messages: {e}')
        return []

def invalidate_message_cache():
    """Invalidate message cache when new messages are added"""
    try:
        cache.delete_memoized(get_recent_messages)
        cache.delete_memoized(get_cached_summary)
        cache.delete_memoized(get_cached_answer)
    except Exception as e:
        app.logger.error(f'Error invalidating cache: {e}')

@cache.memoize(timeout=300)
def get_cached_summary(limit):
    """Get cached summary of messages (5 min cache)"""
    try:
        messages = Message.query.order_by(Message.timestamp.desc()).limit(limit).all()
        messages_data = [{"username": m.author.username, "message": m.content} for m in reversed(messages)]
        return summarize_messages(messages_data), len(messages_data)
    except Exception as e:
        app.logger.error(f'Summary error: {e}')
        return None, 0

@cache.memoize(timeout=300)
def get_cached_answer(question, limit):
    """Get cached answer for a question (5 min cache)"""
    try:
        messages = Message.query.order_by(Message.timestamp.desc()).limit(limit).all()
        messages_data = [{"username": m.author.username, "message": m.content} for m in reversed(messages)]
        return answer_question(messages_data, question)
    except Exception as e:
        app.logger.error(f'Answer error: {e}')
        return None

@cache.memoize(timeout=120)
def get_cached_smart_replies():
    """Get cached smart replies (2 min cache)"""
    try:
        messages = Message.query.order_by(Message.timestamp.desc()).limit(10).all()
        messages_data = [{"username": m.author.username, "message": m.content} for m in reversed(messages)]
        return generate_smart_replies(messages_data)
    except Exception as e:
        app.logger.error(f'Smart replies error: {e}')
        return []

# ==================== ROUTES ====================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("login.html", error="Username and password required")

        try:
            user = User.query.filter_by(username=username).first()

            if user and bcrypt.checkpw(password.encode(), user.password_hash.encode()):
                if user.is_logged_in:
                    app.logger.warning(f'Duplicate login attempt: {username}')
                    return render_template("login.html", error="User already logged in elsewhere!")
                
                user.is_logged_in = True
                db.session.commit()
                
                session["username"] = username
                session["user_id"] = user.id
                session.permanent = True
                
                app.logger.info(f'User logged in: {username}')
                return redirect(url_for("chat"))
            else:
                app.logger.warning(f'Failed login attempt: {username}')
                return render_template("login.html", error="Invalid username or password")
                
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Login error for {username}: {e}')
            return render_template("login.html", error="An error occurred. Please try again.")

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("signup.html", error="Username and password required")

        if len(username) < 3:
            return render_template("signup.html", error="Username must be at least 3 characters")

        if len(password) < 6:
            return render_template("signup.html", error="Password must be at least 6 characters")

        try:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                app.logger.warning(f'Signup attempt with existing username: {username}')
                return render_template("signup.html", error="Username already taken!")

            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            new_user = User(username=username, password_hash=hashed_pw)
            
            db.session.add(new_user)
            db.session.commit()
            
            app.logger.info(f'New user registered: {username}')
            return redirect(url_for("login"))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Signup error for {username}: {e}')
            return render_template("signup.html", error="Error creating user. Please try again.")

    return render_template("signup.html")

@app.route("/chat")
def chat():
    if "username" not in session:
        return redirect(url_for("login"))
    
    try:
        recent_messages = get_recent_messages(limit=50)
        return render_template("chat.html", 
                             username=session["username"],
                             recent_messages=recent_messages)
    except Exception as e:
        app.logger.error(f'Chat page error: {e}')
        return render_template("chat.html", 
                             username=session["username"],
                             recent_messages=[])

@app.route("/logout")
def logout():
    username = session.get("username")
    user_id = session.get("user_id")
    
    try:
        if user_id:
            user = db.session.get(User, user_id)
            if user:
                user.is_logged_in = False
                db.session.commit()
                app.logger.info(f'User logged out: {username}')
        
        session.clear()
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Logout error: {e}')
        session.clear()
    
    return redirect(url_for("login"))

@app.route("/health")
def health():
    """Health check endpoint"""
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "active_users": len(clients),
            "queued_messages": message_batcher.message_queue.qsize()
        }), 200
    except Exception as e:
        app.logger.error(f'Health check failed: {e}')
        return jsonify({
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e)
        }), 500

# ==================== AI ENDPOINTS ====================
@app.route("/api/summarize", methods=["POST"])
def api_summarize():
    """Summarize recent chat messages"""
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        limit = request.json.get("limit", 20)
        limit = min(limit, 100)
        
        summary, message_count = get_cached_summary(limit)
        
        if summary is None:
            return jsonify({"error": "Failed to generate summary"}), 500
        
        app.logger.info(f'Summary generated for: {session["username"]}')
        return jsonify({"summary": summary, "message_count": message_count})
        
    except Exception as e:
        app.logger.error(f'Summarize error: {e}')
        return jsonify({"error": "Failed to generate summary"}), 500

@app.route("/api/ask", methods=["POST"])
def api_ask():
    """Ask AI a question"""
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        question = request.json.get("question", "").strip()
        if not question:
            return jsonify({"error": "No question provided"}), 400
        
        if len(question) > 500:
            return jsonify({"error": "Question too long"}), 400
        
        limit = min(request.json.get("limit", 50), 100)
        
        answer = get_cached_answer(question, limit)
        
        if answer is None:
            return jsonify({"error": "Failed to answer question"}), 500
        
        app.logger.info(f'AI question answered for: {session["username"]}')
        return jsonify({"answer": answer, "question": question})
        
    except Exception as e:
        app.logger.error(f'Ask AI error: {e}')
        return jsonify({"error": "Failed to answer question"}), 500

@app.route("/api/smart-replies", methods=["GET"])
def api_smart_replies():
    """Get smart reply suggestions"""
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        suggestions = get_cached_smart_replies()
        return jsonify({"suggestions": suggestions})
        
    except Exception as e:
        app.logger.error(f'Smart replies error: {e}')
        return jsonify({"error": "Failed to generate suggestions"}), 500

# ==================== WEBSOCKET EVENTS ====================
@socketio.on("connect")
def handle_connect():
    username = session.get("username")
    if not username:
        return False
    
    try:
        clients[request.sid] = username
        emit('system', f'{username} joined the chat', broadcast=True)
        app.logger.info(f'User connected: {username}')
        
        recent_messages = get_recent_messages(limit=50)
        emit('message_history', recent_messages)
        
    except Exception as e:
        app.logger.error(f'Connect error: {e}')

@socketio.on("message")
def handle_message(msg):
    username = clients.get(request.sid)
    if not username:
        return
    
    # try:
    #     if msg == "/quit":
    #         emit('system', f'{username} left the chat', broadcast=True)
    #         return
        
        user = User.query.filter_by(username=username).first()
        if user:
            timestamp = datetime.utcnow()
            
            # Add to batch queue (non-blocking)
            message_batcher.add_message(msg, user.id, timestamp)
            
            # Prepare message data for immediate broadcast
            message_data = {
                'content': msg,
                'username': username,
                'timestamp': timestamp.isoformat()
            }
            
            # Broadcast immediately
            emit('chat', message_data, broadcast=True)
            
    except Exception as e:
        app.logger.error(f'Message error: {e}')
        emit('error', {'message': 'Failed to send message'})

@socketio.on("typing")
def handle_typing(data):
    """Handle typing indicator"""
    username = clients.get(request.sid)
    if not username:
        return
    
    try:
        emit('user_typing', {
            'username': username,
            'is_typing': data.get('is_typing', True)
        }, broadcast=True, include_self=False)
        
    except Exception as e:
        app.logger.error(f'Typing indicator error: {e}')

@socketio.on("disconnect")
def handle_disconnect():
    username = clients.pop(request.sid, None)
    if username:
        try:
            user = User.query.filter_by(username=username).first()
            if user:
                user.is_logged_in = False
                db.session.commit()
            
            emit('system', f'{username} disconnected', broadcast=True)
            app.logger.info(f'User disconnected: {username}')
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Disconnect error: {e}')

# ==================== CLEANUP ====================
def cleanup():
    """Cleanup on shutdown"""
    app.logger.info("Shutting down application...")
    message_batcher.stop()

atexit.register(cleanup)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(
        app, 
        host="0.0.0.0", 
        port=port,
        debug=False,
        allow_unsafe_werkzeug=True
    )
