from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import os
import logging
import jwt
from functools import wraps
from bson.objectid import ObjectId
from os import environ
from dotenv import load_dotenv
import sys
from flask import send_from_directory
from flask import render_template, redirect, url_for, session
from collections import defaultdict
from datetime import datetime, timedelta
import pymongo

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure CORS
CORS(app,
     supports_credentials=True,
     resources={
         r"/api/*": {
             "origins": ["*"],
             "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
             "allow_headers": ["Authorization", "Content-Type"],
             "max_age": 600
         }
     })


# Configuration
app.config['SECRET_KEY'] = environ.get('SECRET_KEY', 'fallback-secret-key-change-me')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# Logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# MongoDB connection
try:
    MONGODB_URI = environ.get('MONGODB_URI', "mongodb+srv://ugs23043itmanichander:Z42NvHEwzOzkJ6Ti@ft.lltloli.mongodb.net/?retryWrites=true&w=majority&appName=FT")
    logger.info(f"Connecting to MongoDB at: {MONGODB_URI.split('@')[-1]}")

    client = MongoClient(
        MONGODB_URI,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=30000,
        socketTimeoutMS=30000
    )
    
    client.server_info()
    logger.info("✅ MongoDB connected successfully")

    db = client["fintrack"]
    users = db["users"]
    budgets = db["budgets"]
    reset_tokens = db["password_reset_tokens"]
    sessions = db["sessions"]
    transactions = db["transactions"]

    users.create_index("email", unique=True)
    users.create_index("username", unique=True)
    reset_tokens.create_index("expires_at", expireAfterSeconds=3600)
    sessions.create_index("expires_at", expireAfterSeconds=0)
    transactions.create_index("user_id")
    transactions.create_index([("user_id", 1), ("date", -1)])

except pymongo.errors.ServerSelectionTimeoutError:
    logger.error("❌ MongoDB server not available. Please start MongoDB service.")
    sys.exit(1)
except pymongo.errors.ConnectionFailure:
    logger.error("❌ Could not connect to MongoDB. Check your connection settings.")
    sys.exit(1)
except Exception as e:
    logger.error(f"❌ MongoDB connection failed: {str(e)}")
    sys.exit(1)

# Helper: Validate user input
def validate_user_data(data, is_login=False):
    required = ["username", "password"] if is_login else ["fullName", "email", "username", "password", "confirmPassword"]
    if not all(field in data for field in required):
        return False, "Missing required fields"
    if not is_login:
        if data["password"] != data["confirmPassword"]:
            return False, "Passwords don't match"
        if "@" not in data["email"]:
            return False, "Invalid email format"
        if len(data["password"]) < 8:
            return False, "Password must be at least 8 characters"
    return True, None

# Helper: Token generator
def create_tokens(user_id):
    access_token = jwt.encode({
        'user_id': str(user_id),
        'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    }, app.config['SECRET_KEY'], algorithm='HS256')

    refresh_token = jwt.encode({
        'user_id': str(user_id),
        'exp': datetime.utcnow() + app.config['JWT_REFRESH_TOKEN_EXPIRES']
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return access_token, refresh_token

# Helper: Token validator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
            logger.info(f"Received token: {token}")  # 👈 Add this here

        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user:
                return jsonify({'error': 'User not found'}), 404
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return jsonify({'error': 'Token validation failed'}), 401
        return f(current_user, *args, **kwargs)
    return decorated
# Health check
@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "database": "connected" if client else "disconnected",
        "timestamp": datetime.utcnow().isoformat()
    })

# Signup
@app.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.get_json()
        is_valid, error_msg = validate_user_data(data)
        if not is_valid:
            return jsonify({"error": error_msg}), 400

        if users.find_one({"$or": [{"email": data["email"]}, {"username": data["username"]}]}):
            return jsonify({"error": "User already exists"}), 409

        hashed_pw = generate_password_hash(data["password"])
        user_id = users.insert_one({
            "fullName": data["fullName"],
            "email": data["email"],
            "username": data["username"],
            "password": hashed_pw,
            "createdAt": datetime.utcnow(),
            "lastLogin": None,
            "avatar": f"https://ui-avatars.com/api/?name={data['fullName'].replace(' ', '+')}&background=random"
        }).inserted_id

        return jsonify({
            "message": "User created successfully",
            "userId": str(user_id)
        }), 201

    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Login
@app.route("/api/login", methods=["POST", "OPTIONS"])
def login():
    try:
        if request.method == "OPTIONS":
            return jsonify({"status": "ok"}), 200

        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 415

        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        is_valid, error_msg = validate_user_data(data, is_login=True)
        if not is_valid:
            return jsonify({"error": error_msg}), 400

        # Debug: Log the received credentials
        print("🔐 Attempting login for username:", data["username"])
        
        user = users.find_one({"username": data["username"]})
        print("👤 User found in DB:", bool(user))

        if user:
            password_matches = check_password_hash(user["password"], data["password"])
            print("🔑 Password match:", password_matches)
        else:
            password_matches = False

        if not user or not password_matches:
            return jsonify({"error": "Invalid username or password"}), 401

        users.update_one(
            {"_id": user["_id"]},
            {"$set": {"lastLogin": datetime.utcnow()}}
        )

        access_token, refresh_token = create_tokens(user["_id"])

        sessions.insert_one({
            "user_id": user["_id"],
            "refresh_token": refresh_token,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + app.config['JWT_REFRESH_TOKEN_EXPIRES'],
            "user_agent": request.headers.get('User-Agent'),
            "ip_address": request.remote_addr
        })

        return jsonify({
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": str(user["_id"]),
                "username": user["username"],
                "email": user["email"],
                "fullName": user["fullName"],
                "avatar": user.get("avatar", "")
            }
        })

    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

# Logout
@app.route("/api/logout", methods=["POST"])
@token_required
def logout(current_user):
    try:
        refresh_token = request.json.get('refresh_token')
        if refresh_token:
            sessions.delete_one({
                "user_id": current_user["_id"],
                "refresh_token": refresh_token
            })

        return jsonify({"message": "Logged out successfully"})

    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Token Refresh
@app.route("/api/refresh", methods=["POST"])
def refresh():
    try:
        refresh_token = request.json.get('refresh_token')
        if not refresh_token:
            return jsonify({'error': 'Refresh token is missing'}), 401

        session_data = sessions.find_one({"refresh_token": refresh_token})
        if not session_data:
            return jsonify({'error': 'Invalid refresh token'}), 401

        try:
            data = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            sessions.delete_one({"refresh_token": refresh_token})
            return jsonify({'error': 'Refresh token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid refresh token'}), 401

        access_token = jwt.encode({
            'user_id': data['user_id'],
            'exp': datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token
        })

    except Exception as e:
        logger.error(f"Refresh token error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Get current user info
@app.route("/api/me", methods=["GET"])
@token_required
def get_current_user(current_user):
    try:
        return jsonify({
            "user": {
                "id": str(current_user["_id"]),
                "username": current_user["username"],
                "email": current_user["email"],
                "fullName": current_user["fullName"],
                "avatar": current_user.get("avatar", ""),
                "createdAt": current_user["createdAt"].isoformat() if current_user.get("createdAt") else None,
                "lastLogin": current_user["lastLogin"].isoformat() if current_user.get("lastLogin") else None
            }
        })
    except Exception as e:
        logger.error(f"Get current user error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
# Get Transactions
@app.route("/api/transactions", methods=["GET"])
@token_required
def get_transactions(current_user):
    try:
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        transaction_type = request.args.get('type')
        category = request.args.get('category')

        query = {"user_id": current_user["_id"]}
        if transaction_type:
            query["type"] = transaction_type
        if category:
            query["category"] = category

        user_transactions = list(transactions.find(query)
            .sort("date", -1)
            .skip(offset)
            .limit(limit))

        total_count = transactions.count_documents(query)

        for t in user_transactions:
            t["_id"] = str(t["_id"])
            t["user_id"] = str(t["user_id"])  # <-- Add this
            t["date"] = t["date"].isoformat() if t.get("date") else None
            t["created_at"] = t["created_at"].isoformat() if t.get("created_at") else None



        return jsonify({
            "transactions": user_transactions,
            "total": total_count,
            "limit": limit,
            "offset": offset
        })

    except Exception as e:
        logger.error(f"Get transactions error: {str(e)}")
        return jsonify({"error": "Failed to get transactions"}), 500

# Add Transaction
@app.route("/api/transactions", methods=["POST"])
@token_required
def add_transaction(current_user):
    try:
        data = request.get_json()
        logger.info(f"Received transaction data: {data}")
        logger.info(f"Date received: {data.get('date')}")
        logger.info(f"Amount type: {type(data.get('amount'))}, Value: {data.get('amount')}")


        required_fields = ["description", "amount", "type", "category"]
        missing_fields = [field for field in required_fields if field not in data or not data[field]]

        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            logger.warning(error_msg)
            return jsonify({"error": error_msg}), 400

        try:
            amount = abs(float(data["amount"]))
            if data["type"] == "expense":
                amount = -amount

            if amount == 0:
                return jsonify({"error": "Amount cannot be zero"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Amount must be a valid number"}), 400

        if data["type"] not in ["income", "expense"]:
            return jsonify({"error": "Invalid transaction type"}), 400

        try:
            date = datetime.fromisoformat(data["date"]) if "date" in data and data["date"] else datetime.utcnow()
        except Exception as e:
            return jsonify({"error": "Invalid date format"}), 400

        transaction = {
            "user_id": current_user["_id"],
            "description": data["description"],
            "amount": amount,
            "type": data["type"],
            "category": data["category"],
            "date": date,
            "created_at": datetime.utcnow()
        }

        result = transactions.insert_one(transaction)
# Convert ObjectId and datetime fields to string formats
        new_transaction = transactions.find_one({"_id": result.inserted_id})
        new_transaction["_id"] = str(new_transaction["_id"])
        new_transaction["user_id"] = str(new_transaction["user_id"])  # <-- THIS LINE
        new_transaction["date"] = new_transaction["date"].isoformat()
        new_transaction["created_at"] = new_transaction["created_at"].isoformat()


        # ✅ Now this will serialize correctly
        return jsonify({
            "message": "Transaction added successfully",
            "transaction": new_transaction
        }), 201


    except Exception as e:
        logger.error(f"Add transaction error: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to add transaction"}), 500

# Delete Transaction
@app.route("/api/transactions/<transaction_id>", methods=["DELETE"])
@token_required
def delete_transaction(current_user, transaction_id):
    try:
        result = transactions.delete_one({
            "_id": ObjectId(transaction_id),
            "user_id": current_user["_id"]
        })

        if result.deleted_count == 0:
            return jsonify({"error": "Transaction not found"}), 404

        return jsonify({"message": "Transaction deleted successfully"})

    except Exception as e:
        logger.error(f"Delete transaction error: {str(e)}")
        return jsonify({"error": "Failed to delete transaction"}), 500

# Get Transaction Summary
@app.route("/api/transactions/summary", methods=["GET"])
@token_required
def get_transaction_summary(current_user):
    try:
        pipeline = [
            {"$match": {"user_id": current_user["_id"]}},
            {"$group": {
                "_id": "$category",
                "total": {"$sum": "$amount"},
                "count": {"$sum": 1}
            }},
            {"$sort": {"total": -1}}
        ]

        category_summary = list(transactions.aggregate(pipeline))

        income_total = next(transactions.aggregate([
            {"$match": {"user_id": current_user["_id"], "type": "income"}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]), {}).get("total", 0)

        expense_total = next(transactions.aggregate([
            {"$match": {"user_id": current_user["_id"], "type": "expense"}},
            {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
        ]), {}).get("total", 0)

        return jsonify({
            "summary": {
                "income": income_total,
                "expense": expense_total,
                "balance": income_total - expense_total,
                "by_category": category_summary
            }
        })

    except Exception as e:
        logger.error(f"Transaction summary error: {str(e)}")
        return jsonify({"error": "Failed to get transaction summary"}), 500
# Request Password Reset
@app.route('/api/request-password-reset', methods=['POST'])
def request_reset():
    try:
        email = request.json.get('email')
        user = users.find_one({"email": email})

        if user:
            token = secrets.token_urlsafe(32)
            expires_at = datetime.utcnow() + timedelta(hours=1)

            reset_tokens.insert_one({
                "token": token,
                "email": email,
                "expires_at": expires_at,
                "used": False
            })

            # In production, send this link via email
            reset_link = f"http://localhost:5000/reset-password.html?token={token}"
            logger.info(f"Password reset link: {reset_link}")

            return jsonify({"message": "Reset instructions sent"})

        return jsonify({"error": "Email not found"}), 404

    except Exception as e:
        logger.error(f"Password reset request error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


# Perform Password Reset
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    try:
        token = request.json.get('token')
        new_password = request.json.get('password')

        token_data = reset_tokens.find_one({
            "token": token,
            "used": False,
            "expires_at": {"$gt": datetime.utcnow()}
        })

        if not token_data:
            return jsonify({"error": "Invalid or expired token"}), 400

        # Update user password
        users.update_one(
            {"email": token_data["email"]},
            {"$set": {"password": generate_password_hash(new_password)}}
        )

        # Mark token as used
        reset_tokens.update_one(
            {"_id": token_data["_id"]},
            {"$set": {"used": True}}
        )

        # Invalidate all sessions for this user
        user = users.find_one({"email": token_data["email"]})
        if user:
            sessions.delete_many({"user_id": user["_id"]})

        return jsonify({"message": "Password updated successfully"})

    except Exception as e:
        logger.error(f"Password reset error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500
@app.route("/api/financial-analysis", methods=["GET"])
@token_required
def financial_analysis(current_user):
    try:
        # Get query parameters with defaults
        months = int(request.args.get('months', 6))
        category_months = int(request.args.get('category_months', 3))
        weeks = int(request.args.get('weeks', 4))
        budget_period = request.args.get('budget_period', 'current')

        # Calculate date ranges
        end_date = datetime.utcnow()
        monthly_start = end_date - timedelta(days=30*months)
        category_start = end_date - timedelta(days=30*category_months)
        weekly_start = end_date - timedelta(days=7*weeks)

        # Helper function to get monthly data
        def get_monthly_data(start_date, end_date):
            pipeline = [
                {"$match": {
                    "user_id": current_user["_id"],
                    "date": {"$gte": start_date, "$lte": end_date}
                }},
                {"$group": {
                    "_id": {
                        "year": {"$year": "$date"},
                        "month": {"$month": "$date"}
                    },
                    "income": {
                        "$sum": {"$cond": [{"$eq": ["$type", "income"]}, "$amount", 0]}
                    },
                    "expenses": {
                        "$sum": {"$cond": [{"$eq": ["$type", "expense"]}, "$amount", 0]}
                    }
                }},
                {"$sort": {"_id.year": 1, "_id.month": 1}}
            ]
            return list(transactions.aggregate(pipeline))

        # Get monthly data
        monthly_data = get_monthly_data(monthly_start, end_date)
        
        # Prepare monthly chart data
        monthly_labels = []
        monthly_income = []
        monthly_expenses = []
        
        for data in monthly_data:
            month = datetime(data["_id"]["year"], data["_id"]["month"], 1).strftime('%b %Y')
            monthly_labels.append(month)
            monthly_income.append(data["income"])
            monthly_expenses.append(abs(data["expenses"]))
        
        # Get category data
        category_data = list(transactions.aggregate([
    {"$match": {
        "user_id": current_user["_id"],
        "type": "expense",
        "date": {"$gte": category_start}
    }},
    {"$group": {
        "_id": "$category",
        "total": {"$sum": "$amount"}
    }},
    {"$project": {
        "_id": 1,
        "total": 1,
        "absTotal": {"$abs": "$total"}
    }},
    {"$sort": {"absTotal": -1}},  # Sort by absolute value of expenses
    {"$limit": 5}
]))

        
        category_labels = [d["_id"] for d in category_data]
        category_values = [abs(d["total"]) for d in category_data]
        
        # Get weekly cash flow data
        weekly_data = list(transactions.aggregate([
            {"$match": {
                "user_id": current_user["_id"],
                "date": {"$gte": weekly_start}
            }},
            {"$group": {
                "_id": {
                    "year": {"$year": "$date"},
                    "week": {"$week": "$date"}
                },
                "income": {
                    "$sum": {"$cond": [{"$eq": ["$type", "income"]}, "$amount", 0]}
                },
                "expenses": {
                    "$sum": {"$cond": [{"$eq": ["$type", "expense"]}, "$amount", 0]}
                }
            }},
            {"$sort": {"_id.year": 1, "_id.week": 1}},
            {"$limit": weeks}
        ]))
        
        weekly_labels = []
        weekly_income = []
        weekly_expenses = []
        
        for data in weekly_data:
            week_label = f"Week {data['_id']['week']}"
            weekly_labels.append(week_label)
            weekly_income.append(data["income"])
            weekly_expenses.append(abs(data["expenses"]))
        
        # Get budget data (simplified - in a real app this would come from a budgets collection)
        user_budgets = list(budgets.find({"user_id": current_user["_id"]}))
        budget_dict = {b["category"]: b["limit"] for b in user_budgets}

        budget_labels = list(budget_dict.keys())
        budgeted = list(budget_dict.values())

        actual_pipeline = [
    {"$match": {
        "user_id": current_user["_id"],
        "type": "expense",
        "category": {"$in": budget_labels},
        "date": {"$gte": datetime(end_date.year, end_date.month, 1)}
    }},
    {"$group": {
        "_id": "$category",
        "total": {"$sum": "$amount"}
    }}
]

        actual_data = {item["_id"]: abs(item["total"]) for item in transactions.aggregate(actual_pipeline)}
        actual_expenses = [actual_data.get(label, 0) for label in budget_labels]

        
        # Calculate metrics
        total_income = sum(monthly_income)
        total_expenses = sum(monthly_expenses)
        net_savings = total_income - total_expenses
        savings_rate = (net_savings / total_income * 100) if total_income > 0 else 0
        
        # Find largest expense
        largest_expense = max(category_data, key=lambda x: abs(x["total"]), default={"_id": "None", "total": 0})
        
        # Calculate trends (simplified - would compare to previous period in real app)
        income_trend = {
            "direction": "positive" if total_income > 0 else "negative",
            "text": f"${abs(total_income)} this period"
        }
        
        expense_trend = {
            "direction": "negative" if total_expenses > 0 else "positive",
            "text": f"${abs(total_expenses)} this period"
        }
        
        savings_trend = {
            "direction": "positive" if net_savings > 0 else "negative",
            "text": f"${abs(net_savings)} this period"
        }
        
        rate_trend = {
            "direction": "positive" if savings_rate > 0 else "negative",
            "text": f"{abs(savings_rate):.1f}% this period"
        }
        
        # Generate insights (simplified)
        insights = []
        if savings_rate < 10:
            insights.append({
                "type": "warning",
                "text": f"Your savings rate is low ({savings_rate:.1f}%). Consider reducing expenses."
            })
        else:
            insights.append({
                "type": "positive",
                "text": f"Great job! Your savings rate is {savings_rate:.1f}%."
            })
            
        if len(category_data) > 0:
            largest_category = category_data[0]
            insights.append({
                "type": "info",
                "text": f"Your largest expense category is {largest_category['_id']} (${abs(largest_category['total']):.2f})."
            })
        
        # Prepare category breakdown
        category_breakdown = []
        colors = ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#ef4444']
        for i, category in enumerate(category_data):
            category_breakdown.append({
                "name": category["_id"],
                "amount": abs(category["total"]),
                "color": colors[i % len(colors)]
            })
        
        # Prepare monthly comparison
        monthly_comparison = []
        if len(monthly_data) >= 1:
            current_month = monthly_data[-1]
            monthly_comparison.append({
                "period": "Current Month",
                "amount": current_month["income"] - abs(current_month["expenses"]),
                "change": {
                    "direction": "positive" if (current_month["income"] - abs(current_month["expenses"])) > 0 else "negative",
                    "value": 10  # Simplified - would calculate actual change in real app
                }
            })
        
        if len(monthly_data) >= 2:
            last_month = monthly_data[-2]
            monthly_comparison.append({
                "period": "Last Month",
                "amount": last_month["income"] - abs(last_month["expenses"]),
                "change": {
                    "direction": "positive" if (last_month["income"] - abs(last_month["expenses"])) > 0 else "negative",
                    "value": -5  # Simplified
                }
            })
        
        if len(monthly_data) >= 3:
            avg_3month = sum(m["income"] - abs(m["expenses"]) for m in monthly_data[-3:]) / 3
            monthly_comparison.append({
                "period": "3-Month Avg",
                "amount": avg_3month,
                "change": {
                    "direction": "positive" if avg_3month > 0 else "negative",
                    "value": 2  # Simplified
                }
            })
        
        # Return all data in the expected format
        return jsonify({
            "metrics": {
                "totalIncome": total_income,
                "totalExpenses": total_expenses,
                "netSavings": net_savings,
                "savingsRate": round(savings_rate, 1),
                "largestExpense": {
                    "amount": abs(largest_expense["total"]),
                    "category": largest_expense["_id"]
                },
                "incomeTrend": income_trend,
                "expenseTrend": expense_trend,
                "savingsTrend": savings_trend,
                "rateTrend": rate_trend
            },
            "charts": {
                "monthly": {
                    "labels": monthly_labels,
                    "income": monthly_income,
                    "expenses": monthly_expenses
                },
                "category": {
                    "labels": category_labels,
                    "values": category_values
                },
                "cashflow": {
                    "labels": weekly_labels,
                    "income": weekly_income,
                    "expenses": weekly_expenses
                },
                "budget": {
                    "labels": budget_labels,
                    "budgeted": budgeted,
                    "actual": actual_expenses
                }
            },
            "insights": insights,
            "categoryBreakdown": category_breakdown,
            "monthlyComparison": monthly_comparison
        })
        
    except Exception as e:
        logger.error(f"Financial analysis error: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to generate financial analysis"}), 500
@app.route("/api/dashboard", methods=["GET"])
@token_required
def get_dashboard_data(current_user):
    try:
        # Get transaction summary
        summary = get_transaction_summary_helper(current_user)
        
        # Get recent transactions
        recent_transactions = list(transactions.find(
            {"user_id": current_user["_id"]}
        ).sort("date", -1).limit(5))
        
        # Convert ObjectId and datetime fields
        for t in recent_transactions:
            t["_id"] = str(t["_id"])
            t["user_id"] = str(t["user_id"])
            t["date"] = t["date"].isoformat() if t.get("date") else None
            t["created_at"] = t["created_at"].isoformat() if t.get("created_at") else None
        
        return jsonify({
            "summary": summary,
            "recent_transactions": recent_transactions
        })
        
    except Exception as e:
        logger.error(f"Dashboard data error: {str(e)}")
        return jsonify({"error": "Failed to get dashboard data"}), 500

def get_transaction_summary_helper(current_user):
    income_total = next(transactions.aggregate([
        {"$match": {"user_id": current_user["_id"], "type": "income"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]), {}).get("total", 0)

    expense_total = next(transactions.aggregate([
        {"$match": {"user_id": current_user["_id"], "type": "expense"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]), {}).get("total", 0)

    category_summary = list(transactions.aggregate([
        {"$match": {"user_id": current_user["_id"]}},
        {"$group": {
            "_id": "$category",
            "total": {"$sum": "$amount"},
            "count": {"$sum": 1}
        }},
        {"$sort": {"total": -1}}
    ]))

    return {
        "income": income_total,
        "expense": expense_total,
        "balance": income_total + expense_total,  # ✅ this is now correct
        "by_category": category_summary
    }
@app.route("/api/budget", methods=["POST", "PUT"])
@token_required
def set_budget(current_user):
    data = request.get_json()
    category = data.get("category")
    limit = float(data.get("limit"))

    if not category or limit < 0:
        return jsonify({"error": "Invalid input"}), 400

    budgets.update_one(
        {"user_id": current_user["_id"], "category": category},
        {"$set": {"limit": limit}},
        upsert=True
    )
    return jsonify({"message": "Budget updated"}), 200
@app.route("/api/budget", methods=["GET"])
@token_required
def get_budgets(current_user):
    user_budgets = list(budgets.find({"user_id": current_user["_id"]}))
    for budget in user_budgets:
        budget["_id"] = str(budget["_id"])
    return jsonify(user_budgets), 200
# Get daily transaction summary
@app.route("/api/transactions/daily-summary", methods=["GET"])
@token_required
def get_daily_summary(current_user):
    try:
        start_date = request.args.get('start')
        end_date = request.args.get('end')
        
        if not start_date or not end_date:
            return jsonify({"error": "Both start and end dates are required"}), 400
            
        try:
            start_date = datetime.fromisoformat(start_date)
            end_date = datetime.fromisoformat(end_date)
        except ValueError:
            return jsonify({"error": "Invalid date format. Use ISO format (YYYY-MM-DD)"}), 400
        
        # Group transactions by day
        pipeline = [
            {
                "$match": {
                    "user_id": current_user["_id"],
                    "date": {"$gte": start_date, "$lte": end_date}
                }
            },
            {
                "$group": {
                    "_id": {
                        "date": {
                            "$dateToString": {
                                "format": "%Y-%m-%d",
                                "date": "$date"
                            }
                        }
                     },

                    "income": {
                        "$sum": {"$cond": [{"$eq": ["$type", "income"]}, "$amount", 0]}
                    },
                    "expense": {
                        "$sum": {"$cond": [{"$eq": ["$type", "expense"]}, "$amount", 0]}
                    }
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "date": "$_id.date",
                    "income": 1,
                    "expense": 1
                }

            },
            {"$sort": {"date": 1}}
        ]
        
        daily_summary = list(transactions.aggregate(pipeline))
        
        return jsonify({
            "daily_summary": daily_summary
        })
        
    except Exception as e:
        logger.error(f"Daily summary error: {str(e)}")
        return jsonify({"error": "Failed to get daily summary"}), 500

# Get transactions for a specific date
@app.route("/api/transactions", methods=["GET"])
@token_required
def get_transactions_by_date(current_user):
    try:
        date = request.args.get('date')
        if date:
            try:
                date_obj = datetime.fromisoformat(date)
                next_day = date_obj + timedelta(days=1)
                
                query = {
                    "user_id": current_user["_id"],
                    "date": {
                        "$gte": date_obj,
                        "$lt": next_day
                    }
                }
            except ValueError:
                return jsonify({"error": "Invalid date format. Use ISO format (YYYY-MM-DD)"}), 400
        else:
            query = {"user_id": current_user["_id"]}
        
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        transaction_type = request.args.get('type')
        category = request.args.get('category')

        if transaction_type:
            query["type"] = transaction_type
        if category:
            query["category"] = category

        user_transactions = list(transactions.find(query)
            .sort("date", -1)
            .skip(offset)
            .limit(limit))

        total_count = transactions.count_documents(query)

        for t in user_transactions:
            t["_id"] = str(t["_id"])
            t["user_id"] = str(t["user_id"])
            t["date"] = t["date"].isoformat() if t.get("date") else None
            t["created_at"] = t["created_at"].isoformat() if t.get("created_at") else None

        return jsonify({
            "transactions": user_transactions,
            "total": total_count,
            "limit": limit,
            "offset": offset
        })

    except Exception as e:
        logger.error(f"Get transactions error: {str(e)}")
        return jsonify({"error": "Failed to get transactions"}), 500


@app.route('/analysis')
def analysis():
    return send_from_directory('.', 'analysis.html')
@app.route('/profile.html')
def profile_page():
    return render_template('profile.html')

@app.route('/<path:filename>')
def serve_file(filename):
    return send_from_directory('.', filename)
# Run the app
if __name__ == "__main__":
    debug_mode = environ.get('DEBUG', 'False') == 'True'
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
