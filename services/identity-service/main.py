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
p.route('/')
def local_feed_dashboard():
    return '''
        <div style="font-family: sans-serif; max-width: 550px; margin: 40px auto; padding: 30px; border: 1px solid #17a2b8; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.08);">
            <h2 style="color: #17a2b8; margin-top: 0;"> Local Feed Geofenced Gateway</h2>
            <hr style="border: 0; border-top: 1px solid #e9ecef; margin: 20px 0;"/>
            
            <div style="background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #17a2b8;">
                <h4 style="margin: 0 0 12px 0; color: #333;"> Simulate Infinite Scroll & Lazy Loading:</h4>
                <p style="font-size: 13px; color: #666; margin-bottom: 15px;">Click these steps sequentially to watch the backend deliver small data chunks just like a real phone feed:</p>
                <ul style="padding-left: 20px; font-size: 14px; line-height: 2;">
                    <li><a href="/api/v1/feed/local?constituency=Dhanbad&page=1&limit=2" target="_blank" style="color: #17a2b8; font-weight: bold; text-decoration: none;">🔄 Step 1: Load Page 1 (Gets 2 Newest Posts, has_more: True)</a></li>
                    <li><a href="/api/v1/feed/local?constituency=Dhanbad&page=2&limit=2" target="_blank" style="color: #17a2b8; font-weight: bold; text-decoration: none;">🔄 Step 2: Load Page 2 (Gets Last Remaining Post, has_more: False)</a></li>
                </ul>
            </div>
        </div>
    '''

if __name__ == '__main__':
    print(f"[LOCAL-FEED-SERVICE] Geofencing core online on port: {PORT}")
    app.run(port=PORT)import time
from flask import Flask, request, jsonify

app = Flask(__name__)
PORT = 3008

# Simulated active database populated with localized community complaints
POSTS_DATABASE = [
    {
        "id": 1001,
        "title": "Severe road waterlogging",
        "category": "Environmental",
        "street_address": "Near Gandhi Chowk, Main Bazaar",
        "constituency": "Dhanbad",
        "state": "Jharkhand",
        "created_at": time.time() - 600  # Posted 10 mins ago (Newest)
    },
    {
        "id": 1002,
        "title": "Damaged open transformer box",
        "category": "Infrastructure",
        "street_address": "Opposite City Rail Gate",
        "constituency": "Dhanbad",
        "state": "Jharkhand",
        "created_at": time.time() - 3600  # Posted 1 hour ago (Middle)
    },
    {
        "id": 1003,
        "title": "Garbage heap accumulation near hospital entrance",
        "category": "Environmental",
        "street_address": "Link Road, Block B",
        "constituency": "Dhanbad",
        "state": "Jharkhand",
        "created_at": time.time() - 7200  # Posted 2 hours ago (Oldest)
    },
    {
        "id": 1004,
        "title": "Streetlight failure in A-Zone",
        "category": "Infrastructure",
        "street_address": "A-Zone High Street",
        "constituency": "Durgapur",
        "state": "West Bengal",
        "created_at": time.time() - 1200  # Different constituency
    }
]

# --- ROUTE 1: FETCH GEOCONSTRAINED LOCAL TIMELINE (LAZY LOAD ENFORCED) ---
@app.route('/api/v1/feed/local', methods=['GET'])
def fetch_local_feed():
    try:
        # 1. Read target locality and pagination boundaries from request parameters
        constituency = request.args.get('constituency')
        
        # Pagination defaults: page 1, max 2 items per chunk to demonstrate lazy load
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 2))
        
        if not constituency:
            return jsonify({
                "status": "FAILED", 
                "error": "Missing mandatory location tracking parameter: 'constituency' is required."
            }), 400

        # 2. Filter posts strictly matching the user's Assembly Constituency
        local_records = [post for post in POSTS_DATABASE if post['constituency'].lower() == constituency.lower()]
        
        # 3. PRD Criteria: Sort records so recent submissions come on top (Decreasing Order)
        local_records_sorted = sorted(local_records, key=lambda x: x['created_at'], reverse=True)
        
        # 4. Implement Infinite Scroll / Lazy Load segment slicing math
        start_index = (page - 1) * limit
        end_index = start_index + limit
        paginated_slice = local_records_sorted[start_index:end_index]
        
        # Determine if additional database records remain downstream
        has_more_records = end_index < len(local_records_sorted)

        return jsonify({
            "status": "SUCCESS",
            "constituency_context": constituency,
            "page_index": page,
            "chunk_count": len(paginated_slice),
            "infinite_scroll": {
                "has_more": has_more_records,
                "next_page": page + 1 if has_more_records else None
            },
            "feed": paginated_slice
        }), 200
        
    except Exception as runtime_error:
        return jsonify({"status": "ERROR", "error": str(runtime_error)}), 500

# Interactive Dashboard Panel View
@ap
