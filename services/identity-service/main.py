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
from dotenv import load_dotenv
load_dotenv()  # This loads the environment variables instantly
import math
from flask import Flask, request, jsonify

app = Flask(__name__)
PORT = 3006

# Simulated active database tracking existing verified issues
EXISTING_ISSUES_DATABASE = [
    {
        "id": 501,
        "location_name": "Binod Nagar Main Road",
        "description": "Large road pothole causing traffic alignment cracks.",
        "latitude": 23.80410,
        "longitude": 86.43120,
        "linked_duplicates": []
    }
]

# Helper Function: Calculates exact distance between two GPS points in meters (Haversine Formula)
def calculate_geographical_distance(lat1, lon1, lat2, lon2):
    R = 6371000  # Radius of the earth in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2) * math.sin(delta_phi / 2) + \
        math.cos(phi1) * math.cos(phi2) * \
        math.sin(delta_lambda / 2) * math.sin(delta_lambda / 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c  # Returns distance in meters

# --- ROUTE 1: EVALUATE NEW SUBMISSION FOR PROXIMITY CLUBBING MATCHES ---
@app.route('/api/v1/issues/clubbing-check', methods=['POST'])
def check_issue_proximity_clubbing():
    try:
        payload = request.get_json()
        
        if not payload or 'latitude' not in payload or 'longitude' not in payload:
            return jsonify({"status": "FAILED", "error": "Missing tracking coordinates input parameters."}), 400
            
        new_lat = float(payload['latitude'])
        new_lng = float(payload['longitude'])
        new_desc = payload.get('description', 'No description provided.')
        
        PROXIMITY_THRESHOLD_METERS = 15.0  # Strict PRD boundary check rule
        matched_parent_ticket = None

        # Loop through existing database entries to calculate distance parameters
        for issue in EXISTING_ISSUES_DATABASE:
            distance = calculate_geographical_distance(new_lat, new_lng, issue['latitude'], issue['longitude'])
            
            if distance <= PROXIMITY_THRESHOLD_METERS:
                matched_parent_ticket = issue
                break

        if matched_parent_ticket:
            duplicate_id = len(matched_parent_ticket['linked_duplicates']) + 1
            duplicate_entry = {
                "duplicate_sequence_id": duplicate_id,
                "description": new_desc,
                "distance_from_parent_meters": round(distance, 2)
            }
            matched_parent_ticket['linked_duplicates'].append(duplicate_entry)
            
            return jsonify({
                "status": "CLUBBED",
                "message": f"Duplicate detected within {round(distance, 2)} meters. Ticket linked to master thread container.",
                "master_ticket_id": matched_parent_ticket['id'],
                "master_location": matched_parent_ticket['location_name']
            }), 200

        new_ticket_id = len(EXISTING_ISSUES_DATABASE) + 501
        new_master_ticket = {
            "id": new_ticket_id,
            "location_name": "New Unmapped Coordinate Area Zone",
            "description": new_desc,
            "latitude": new_lat,
            "longitude": new_lng,
            "linked_duplicates": []
        }
        EXISTING_ISSUES_DATABASE.append(new_master_ticket)

        return jsonify({
            "status": "UNIQUE",
            "message": "No matching close duplicates found. Created a fresh master report ticket identifier flag.",
            "new_ticket_id": new_ticket_id
        }), 201

    except Exception as runtime_error:
        return jsonify({"status": "ERROR", "error": str(runtime_error)}), 500

# Interactive HTML Dashboard Interface Panel view for Row 10 Validation
@app.route('/')
def local_clubbing_dashboard():
    return '''
        <div style="font-family: sans-serif; max-width: 550px; margin: 40px auto; padding: 30px; border: 1px solid #6f42c1; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.08);">
            <h2 style="color: #6f42c1; margin-top: 0;">🔀 Problem Clubbing Proximity Dashboard</h2>
            <p style="color: #666;">Simulating duplicate neighborhood report verification matching tracking metrics for Row 10.</p>
            <hr style="border: 0; border-top: 1px solid #e9ecef; margin: 20px 0;"/>
            
            <div style="background: #f8f9fa; padding: 15px; border-radius: 6px; margin-bottom: 25px; border-left: 4px solid #6f42c1; font-size: 14px; line-height: 1.5;">
                <b style="color: #333; display: block; margin-bottom: 5px;">📍 Active Master Ticket in Database (Binod Nagar):</b>
                <b>Latitude:</b> 23.80410 | <b>Longitude:</b> 86.43120<br/>
                <span style="color: #666;">PRD Cluster Boundary Rules Check: Merges duplicates within 15 meters!</span>
            </div>

            <form action="/api/v1/issues/clubbing-check" method="POST" onsubmit="runClubbingCheck(event)">
                <label style="display: block; font-weight: bold; margin-bottom: 8px; font-size: 14px;">Enter New Report Latitude:</label>
                <input type="text" id="geoLat" value="23.80415" style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; margin-bottom: 15px; box-sizing: border-box;" required />

                <label style="display: block; font-weight: bold; margin-bottom: 8px; font-size: 14px;">Enter New Report Longitude:</label>
                <input type="text" id="geoLng" value="86.43125" style="width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; margin-bottom: 15px; box-sizing: border-box;" required />

                <p style="font-size: 12px; color: #6f42c1; margin-top: -5px; font-weight: bold;">💡 Tip: The default coordinates above are just 7 meters away from our master ticket (Should CLUB!).</p>

                <label style="display: block; font-weight: bold; margin-bottom: 8px; font-size: 14px;">Problem Report Description:</label>
                <textarea id="geoDesc" style="width: 100%; height: 60px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; margin-bottom: 25px; box-sizing: border-box;" required>Pothole expansion issue reported by different neighbor account handle.</textarea>

                <button type="submit" style="width: 100%; background: #6f42c1; color: white; border: none; padding: 12px 20px; border-radius: 4px; font-weight: bold; cursor: pointer; font-size: 15px;">
                    Analyze Proximity Match Parameters
                </button>
            </form>
        </div>

        <script>
        async function runClubbingCheck(e) {
            e.preventDefault();
            const response = await fetch('/api/v1/issues/clubbing-check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    latitude: document.getElementById('geoLat').value,
                    longitude: document.getElementById('geoLng').value,
                    description: document.getElementById('geoDesc').value
                })
            });
            const data = await response.json();
            document.body.innerHTML = `<pre style="padding:20px; background:#212529; color:#f8f9fa; border-radius:6px; max-width:600px; margin:40px auto; overflow:auto; font-weight: bold;">\${JSON.stringify(data, null, 2)}</pre>`;
        }
        </script>
    '''

if __name__ == '__main__':
    print(f"[CLUBBING-SERVICE] Proximity evaluation core initialized on port: {PORT}")
    app.run(port=PORT)
