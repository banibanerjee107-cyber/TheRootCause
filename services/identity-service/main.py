from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import os
import random
from typing import Optional, List

app = FastAPI(title="Identity Service")

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@postgres:5432/user_db")

# Simple OTP storage in-memory for validation (in a real app, use Redis/cache)
# Map: phone_number -> otp_code
OTP_STORE = {}

def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

# Pydantic models
class OAuthLoginRequest(BaseModel):
    provider: str
    token: str
    email: str
    name: str

class RequestOTPRequest(BaseModel):
    phone: str
    captchaToken: str

class VerificationRequest(BaseModel):
    userId: str
    phone: str
    otp: str
    captchaToken: str

class ScoreUpdateRequest(BaseModel):
    change: float
    reason: str
    isDownvote: bool = False

class Enable2FARequest(BaseModel):
    userId: str
    enabled: bool

# Help determine title based on score
def determine_title(score: int) -> str:
    milestones = [
        (1000000, "Mukhya Mantri"),
        (100000, "Mantri"),
        (50000, "Adhyaksha"),
        (20000, "Maha Sachiv"),
        (10000, "Sachiv"),
        (1000, "Pradhan"),
        (500, "Pravakta"),
        (100, "Pracharak"),
        (50, "Karyakarta"),
        (10, "Sewak")
    ]
    for limit, title in milestones:
        if score >= limit:
            return title
    return "Sewak"

@app.post("/login/oauth")
async def login_oauth(payload: OAuthLoginRequest):
    if payload.provider.lower() != "google":
        raise HTTPException(status_code=400, detail="Only Google authentication is supported.")

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Check if user exists
            cur.execute("SELECT * FROM users WHERE email = %s;", (payload.email,))
            user = cur.fetchone()

            if not user:
                # Create user
                user_id = "u_" + hashlib.md5(payload.email.encode()).hexdigest()[:12]
                public_username = payload.name.lower().replace(" ", "_") + "_" + user_id[-4:]
                anonymous_username = "anon_" + user_id[-8:]
                
                cur.execute(
                    """
                    INSERT INTO users (id, name, email, public_username, anonymous_username, score, title, two_fa_enabled)
                    VALUES (%s, %s, %s, %s, %s, 0, 'Sewak', FALSE)
                    RETURNING *;
                    """,
                    (user_id, payload.name, payload.email, public_username, anonymous_username)
                )
                user = cur.fetchone()
                conn.commit()

        return {
            "message": "Login successful",
            "user": user,
            "token": f"jwt_{user['id']}"
        }
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.post("/request-otp")
async def request_otp(payload: RequestOTPRequest):
    if not payload.captchaToken:
        raise HTTPException(status_code=400, detail="Captcha verification failed.")
    
    # Simple simulated OTP generation
    otp = str(random.randint(100000, 999999))
    OTP_STORE[payload.phone] = otp
    
    # In a production environment, this would call Twilio or another SMS API.
    # For verification, we expose it in response for sandbox testing ease.
    return {
        "message": "OTP generated successfully",
        "phone": payload.phone,
        "otp": otp, # Return for testing/mock purposes
        "info": "This verification process creates a SHA-256 hash of your phone number to prevent duplicate registrations. We do NOT store your phone number or the OTP code."
    }

@app.post("/verify")
async def verify(payload: VerificationRequest):
    if not payload.captchaToken:
        raise HTTPException(status_code=400, detail="Captcha verification is mandatory.")

    # Check OTP
    stored_otp = OTP_STORE.get(payload.phone)
    if not stored_otp or stored_otp != payload.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP code.")

    # Create SHA-256 hash
    phone_hash = hashlib.sha256(payload.phone.encode()).hexdigest()

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Check for duplicacy
            cur.execute("SELECT id FROM users WHERE phone_hash = %s AND id != %s;", (phone_hash, payload.userId))
            duplicate = cur.fetchone()
            if duplicate:
                raise HTTPException(status_code=400, detail="This phone number has already been used to verify another account.")

            # Update user
            cur.execute(
                "UPDATE users SET phone_hash = %s WHERE id = %s RETURNING *;",
                (phone_hash, payload.userId)
            )
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found.")
            
            conn.commit()

            # Clean OTP
            OTP_STORE.pop(payload.phone, None)

            return {
                "verified": True,
                "message": "User verified successfully.",
                "user": user
            }
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Verification failed: {e}")
    finally:
        conn.close()

@app.get("/users/{user_id}")
async def get_user(user_id: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s;", (user_id,))
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found.")
            return user
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.post("/users/2fa")
async def update_2fa(payload: Enable2FARequest):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET two_fa_enabled = %s WHERE id = %s RETURNING *;",
                (payload.enabled, payload.userId)
            )
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found.")
            conn.commit()
            return {"message": "2FA updated successfully", "user": user}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.post("/users/{user_id}/score")
async def update_score(user_id: str, payload: ScoreUpdateRequest):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s;", (user_id,))
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found.")

            old_score = user['score']
            change = payload.change

            # Scaling rejection cost: "if a person crosses 500 score their post rejection score cost will be higher, scaling by a ratio 1:10, so at 500, each reject post would -50"
            if change < 0 and "Post Rejected" in payload.reason and old_score >= 500:
                # Change is normally -5. Scaled 1:10, so at >= 500 it becomes -50.
                change = change * 10

            new_score = old_score + change
            new_title = determine_title(int(new_score))

            # Is restricted check: "If a users score falls below -500, they are restricted from voting, comments and debates"
            is_blocked = True if new_score < -500 else False

            cur.execute(
                """
                UPDATE users
                SET score = %s, title = %s, is_blocked = %s
                WHERE id = %s
                RETURNING *;
                """,
                (int(new_score), new_title, is_blocked, user_id)
            )
            updated_user = cur.fetchone()

            # Create notification for negative updates, except downvotes
            if change < 0 and not payload.isDownvote:
                cur.execute(
                    """
                    INSERT INTO user_notifications (user_id, type, message)
                    VALUES (%s, 'score_update', %s);
                    """,
                    (user_id, f"Your score was reduced by {abs(change)} because: {payload.reason}. Current score: {int(new_score)}")
                )

            # Create notification for rank up
            if new_title != user['title'] and new_score > old_score:
                cur.execute(
                    """
                    INSERT INTO user_notifications (user_id, type, message)
                    VALUES (%s, 'rank_up', %s);
                    """,
                    (user_id, f"Congratulations! You have been promoted to the rank of {new_title}!")
                )

            conn.commit()
            return {"message": "Score updated successfully", "user": updated_user}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.get("/users/{user_id}/notifications")
async def get_notifications(user_id: str):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM user_notifications WHERE user_id = %s ORDER BY created_at DESC;",
                (user_id,)
            )
            notifications = cur.fetchall()
            return notifications
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.post("/notifications/{notif_id}/read")
async def mark_notification_read(notif_id: int):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE user_notifications SET is_read = TRUE WHERE id = %s RETURNING *;",
                (notif_id,)
            )
            notif = cur.fetchone()
            if not notif:
                raise HTTPException(status_code=404, detail="Notification not found.")
            conn.commit()
            return {"message": "Notification marked as read", "notification": notif}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        conn.close()

@app.get("/health")
async def health():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT NOW();")
            db_time = cur.fetchone()['now']
        return {
            "status": "ok",
            "service": "identity-service",
            "dbTime": db_time.isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database status error: {e}")
    finally:
        if conn:
            conn.close()
import time
from flask import Flask, request, jsonify

app = Flask(__name__)
PORT = 3007

# Simulated database containing local issue posts with interaction logs
POSTS_DATABASE = [
    {
        "id": 1,
        "title": "Water pipeline burst in Sector 4",
        "category": "Infrastructure",
        "constituency": "Durgapur East",
        "state": "West Bengal",
        "upvotes": 45,
        "comments_count": 20,
        "created_at": time.time() - 1800  # Posted 30 mins ago
    },
    {
        "id": 2,
        "title": "Trash dumping near community park",
        "category": "Environmental",
        "constituency": "Durgapur East",
        "state": "West Bengal",
        "upvotes": 12,
        "comments_count": 4,
        "created_at": time.time() - 3600  # Posted 1 hour ago
    },
    {
        "id": 3,
        "title": "Stray dog safety concerns near schools",
        "category": "Other",
        "constituency": "Asansol",
        "state": "West Bengal",
        "upvotes": 85,
        "comments_count": 40,
        "created_at": time.time() - 7200  # Posted 2 hours ago
    }
]

# Helper Function: Calculates interaction rate and ranks the feed entries
def get_trending_posts(category=None, constituency=None, state=None):
    scored_posts = []
    
    for post in POSTS_DATABASE:
        # PRD Filter Sorting: Skip post if it doesn't match active filters
        if category and post['category'].lower() != category.lower():
            continue
        if constituency and post['constituency'].lower() != constituency.lower():
            continue
        if state and post['state'].lower() != state.lower():
            continue
            
        # Interaction Rate calculation: Total number of actions on the post
        interaction_rate = post['upvotes'] + post['comments_count']
        
        # Create a shallow copy of the dictionary to append runtime analytics safely
        post_entry = post.copy()
        post_entry['interaction_rate'] = interaction_rate
        scored_posts.append(post_entry)
        
    # PRD Requirement: Sort posts in decreasing order of interaction rate
    trending_sorted = sorted(scored_posts, key=lambda x: x['interaction_rate'], reverse=True)
    
    # PRD Scope Check: Limit to the top 50 trending posts max per cycle
    return trending_sorted[:50]

# --- ROUTE 1: FETCH TRENDING TIMELINE SORTED BY INTERACTION VELOCITY ---
@app.route('/api/v1/feed/trending', methods=['GET'])
def fetch_trending_feed():
    try:
        # Read optional sorting filters passed via URL parameters
        category = request.args.get('category')
        constituency = request.args.get('constituency')
        state = request.args.get('state')
        
        trending_list = get_trending_posts(category, constituency, state)
        
        return jsonify({
            "status": "SUCCESS",
            "cycle_refresh": "1 Hour",
            "count": len(trending_list),
            "feed": trending_list
        }), 200
        
    except Exception as runtime_error:
        return jsonify({"status": "ERROR", "error": str(runtime_error)}), 500

# Interactive Dashboard Panel View
@app.route('/')
def trending_dashboard():
    return '''
        <div style="font-family: sans-serif; max-width: 550px; margin: 40px auto; padding: 30px; border: 1px solid #e83e8c; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.08);">
            <h2 style="color: #e83e8c; margin-top: 0;"> Trending Feed Velocity Algorithm Panel</h2>
            <p style="color: #666;">Calculating interaction loops and post ranking decreasing orders matching Row 12 criteria.</p>
            <hr style="border: 0; border-top: 1px solid #e9ecef; margin: 20px 0;"/>
            
            <form action="/api/v1/feed/trending" method="GET" target="_blank" style="margin-bottom: 20px;">
                <button type="submit" style="width: 100%; background: #e83e8c; color: white; border: none; padding: 12px 20px; border-radius: 4px; font-weight: bold; cursor: pointer; font-size: 15px;">
                    View Raw Global Trending Feed Array
                </button>
            </form>

            <div style="background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #e83e8c;">
                <h4 style="margin: 0 0 12px 0; color: #333;"> Test Filter Combinations:</h4>
                <p style="font-size: 13px; color: #666; margin-bottom: 15px;">Open these specific URL paths in a new browser tab to test your platform's built-in target filters:</p>
                <ul style="padding-left: 20px; font-size: 14px; line-height: 1.8;">
                    <li>Filter by Category: <a href="/api/v1/feed/trending?category=Infrastructure" target="_blank" style="color: #e83e8c; font-weight: bold; text-decoration: none;">/trending?category=Infrastructure</a></li>
                    <li>Filter by Constituency: <a href="/api/v1/feed/trending?constituency=Asansol" target="_blank" style="color: #e83e8c; font-weight: bold; text-decoration: none;">/trending?constituency=Asansol</a></li>
                </ul>
            </div>
        </div>
    '''

if __name__ == '__main__':
    print(f"[TRENDING-SERVICE] Velocity algorithm running on port: {PORT}")
    app.run(port=PORT)
