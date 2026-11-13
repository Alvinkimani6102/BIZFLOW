
from flask import Flask, render_template, request, redirect, url_for, session, flash
from bson.objectid import ObjectId
from pymongo import MongoClient
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timezone, timedelta

import json
import math
import secrets
from pymongo.errors import PyMongoError, DuplicateKeyError
from flask import jsonify
import re

# Load variables from .env
load_dotenv()

# =========================
# BIZFLOW SUPER ADMIN
# =========================

SUPER_ADMIN_EMAIL = "kimanialvin2003@gmail.com"


def is_super_admin():
    """Check whether the logged-in account is the authorized administrator."""
    if "user_id" not in session:
        return False

    user = users_collection.find_one({
        "_id": ObjectId(session["user_id"]),
        "email": SUPER_ADMIN_EMAIL
    })

    return user is not None


app = Flask(__name__)

# Flask secret key
SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing from .env")

app.config["SECRET_KEY"] = SECRET_KEY

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000
)

# BIZFLOW database
db = client["BIZFLOW"]

sales_drafts_collection = db["sales_drafts"]

# =========================
# BIZFLOW ORDERS MANAGEMENT
# =========================

orders_collection = db["orders"]

# Users collection
users_collection = db["users"]

# =========================
# BUSINESS WORKER ACCESS
# =========================

business_memberships = db["business_memberships"]


def get_business_access(business_id):
    """
    Return the business and the current user's role.
    Owners have full access; assigned workers have restricted access.
    """
    if "user_id" not in session:
        return None, None

    if not ObjectId.is_valid(business_id):
        return None, None

    # Check whether the logged-in user owns this business.
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if business:
        return business, "owner"

    # Otherwise, check for an explicit worker assignment.
    membership = business_memberships.find_one({
        "business_id": business_id,
        "user_id": session["user_id"],
        "status": "active"
    })

    if not membership:
        return None, None

    # Confirm the assigned business still exists.
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id)
    })

    if not business:
        return None, None

    return business, membership.get("role", "worker")


def is_business_owner(business_id):
    """Return True only when the logged-in user owns the business."""
    business, role = get_business_access(business_id)
    return business is not None and role == "owner"


# Businesses collection
businesses_collection = db["businesses"]

# =========================
# BIZFLOW SYSTEM MAINTENANCE
# =========================

system_settings = db["system_settings"]

# Account password recovery requests
password_reset_requests = db["password_reset_requests"]


def maintenance_mode_enabled():
    setting = system_settings.find_one({
        "_id": "maintenance_mode"
    })

    return bool(setting and setting.get("enabled", False))

# =========================
# MAINTENANCE MODE PROTECTION
# =========================


@app.before_request
def enforce_maintenance_mode():
    if not maintenance_mode_enabled():
        return None

    # Always allow the Super Admin through.
    if is_super_admin():
        return None

    # Allow static files (CSS, images, JavaScript).
    if request.endpoint == "static":
        return None

    # Allow the login route so the Super Admin can log in.
    if request.endpoint == "login":
        return None

    # Log out other users and display the maintenance page.
    session.clear()
    return render_template("maintenance.html"), 503


# =========================
# BUSINESS WORKER ACCESS
# =========================

business_memberships = db["business_memberships"]


@app.route(
    "/business/<business_id>/workers",
    methods=["GET", "POST"]
)
def manage_workers(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(business_id):
        return "Invalid business.", 400

    # Only the business owner can manage workers.
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    error = None
    success = None

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not name or not email or not password:
            error = "Please fill in all required fields."

        elif password != confirm_password:
            error = "The passwords do not match."

        elif len(password) < 8:
            error = "The password must be at least 8 characters."

        elif users_collection.find_one({"email": email}):
            error = "An account with this email already exists."

        else:
            worker = {
                "name": name,
                "email": email,
                "password_hash": generate_password_hash(password),
                "role": "worker",
                "created_at": datetime.now(timezone.utc)
            }

            try:
                result = users_collection.insert_one(worker)

                business_memberships.insert_one({
                    "business_id": str(business["_id"]),
                    "owner_id": session["user_id"],
                    "user_id": str(result.inserted_id),
                    "role": "worker",
                    "status": "active",
                    "created_at": datetime.now(timezone.utc)
                })

                return redirect(url_for(
                    "manage_workers",
                    business_id=business_id
                ))

            except DuplicateKeyError:
                # Handle a duplicate email if another request
                # created the account at the same time.
                error = "An account with this email already exists."

    memberships = list(
        business_memberships.find({
            "business_id": str(business["_id"]),
            "owner_id": session["user_id"],
            "status": "active"
        })
    )

    workers = []

    for membership in memberships:
        worker = users_collection.find_one({
            "_id": ObjectId(membership["user_id"]),
            "role": "worker"
        })

        if worker:
            workers.append({
                "name": worker.get("name", ""),
                "email": worker.get("email", ""),
                "membership_id": str(membership["_id"])
            })

    return render_template(
        "manage_workers.html",
        business=business,
        workers=workers,
        error=error,
        success=success
    )


# =========================
# HOME PAGE
# =========================

@app.route("/")
def home():
    return render_template("home.html")


# =========================
# ABOUT BIZFLOW
# =========================

@app.route("/about")
def about():
    return render_template("about.html")

# =========================
# XML SITEMAP
# =========================


@app.route("/sitemap.xml")
def sitemap():

    home_url = url_for("home", _external=True)
    about_url = url_for("about", _external=True)

    sitemap_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">

    <url>
        <loc>{home_url}</loc>
        <changefreq>weekly</changefreq>
        <priority>1.0</priority>
    </url>

    <url>
        <loc>{about_url}</loc>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>

</urlset>
"""

    return app.response_class(
        sitemap_xml,
        mimetype="application/xml"
    )

    # =========================
# ROBOTS.TXT
# =========================


@app.route("/robots.txt")
def robots():
    robots_txt = """User-agent: Google-InspectionTool
Allow: /

User-agent: *
Allow: /

Sitemap: https://bizflow-if4z.onrender.com/sitemap.xml
"""
    return app.response_class(
        robots_txt,
        mimetype="text/plain"
    )


# =========================
# SIGNUP
# =========================


@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Check passwords
        if password != confirm_password:
            return "Passwords do not match."

        # Check if email already exists
        existing_user = users_collection.find_one({
            "email": email
        })

        if existing_user:
            return "An account with this email already exists."

        # Hash password
        password_hash = generate_password_hash(password)

        # Create user awaiting Super Admin approval
        user = {
            "name": name,
            "email": email,
            "password_hash": password_hash,
            "account_status": "pending",

            # First-time onboarding guide
            "onboarding_completed": False,
            "onboarding_skipped": False,

            "created_at": datetime.now(timezone.utc)
        }

        users_collection.insert_one(user)

        # Send user to the approval waiting page
        return redirect(url_for("account_pending"))

    return render_template("signup.html")


# =========================
# ACCOUNT APPROVAL WAITING PAGE
# =========================

@app.route("/account-pending")
def account_pending():
    return render_template("account_pending.html")


# =========================
# LOGIN
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # Find user
        user = users_collection.find_one({
            "email": email
        })

        # Check credentials
        if user and check_password_hash(
            user.get("password_hash", ""),
            password
        ):

            # Require Super Admin approval for new accounts
            account_status = user.get("account_status", "active")

            if account_status == "pending":
                return render_template("account_pending.html"), 403

            # Block rejected or deactivated accounts
            if account_status != "active":
                return render_template("account_deactivated.html"), 403

                # Block non-admin users during maintenance
            if (
                maintenance_mode_enabled()
                and user.get("email", "").lower() != SUPER_ADMIN_EMAIL
            ):
                return render_template("maintenance.html"), 503

            # Clear any previous login session
            session.clear()

            # Store user information in session
            session["user_id"] = str(user["_id"])
            session["user_name"] = user.get("name", "")
            session["user_email"] = user.get("email", "")

            # Workers must access their assigned business
            if user.get("role") == "worker":

                membership = business_memberships.find_one({
                    "user_id": str(user["_id"]),
                    "status": "active"
                })

                if not membership:
                    session.clear()
                    return "No active business assignment. Please contact the business owner.", 403

                business = businesses_collection.find_one({
                    "_id": ObjectId(membership["business_id"]),
                    "owner_id": membership["owner_id"]
                })

                if not business:
                    session.clear()
                    return "Assigned business not found or access denied.", 403

                session["role"] = "worker"
                session["business_id"] = str(business["_id"])
                session["business_owner_id"] = membership["owner_id"]

                # Send workers directly to their assigned business workspace
                return redirect(url_for(
                    "business_workspace",
                    business_id=str(business["_id"])
                ))

            # Business owner login, including the super administrator
            session["role"] = "owner"

            # Check whether this is a first-time user
            session["show_onboarding_guide"] = (
                "onboarding_completed" in user
                and not user.get("onboarding_completed", False)
                and not user.get("onboarding_skipped", False)
            )

     # Trigger the dashboard entrance animation only after login
            session["show_dashboard_intro"] = True

            return redirect(url_for("dashboard"))

        flash("Invalid email or password. Please try again.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


# =========================
# ACCOUNT RECOVERY
# =========================


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not email:
            return render_template(
                "forgot_password.html",
                error="Please enter your registered email address."
            )

        if len(new_password) < 8:
            return render_template(
                "forgot_password.html",
                error="Your new password must be at least 8 characters long."
            )

        if new_password != confirm_password:
            return render_template(
                "forgot_password.html",
                error="The passwords do not match."
            )

        user = users_collection.find_one({"email": email})

        if not user:
            return render_template(
                "forgot_password.html",
                error="No account was found with that email address."
            )

        existing_request = password_reset_requests.find_one({
            "user_id": str(user["_id"]),
            "status": "pending"
        })

        if existing_request:
            return render_template(
                "forgot_password.html",
                success=(
                    "Your password reset request is already awaiting "
                    "BIZFLOW administrator approval."
                )
            )

        password_reset_requests.insert_one({
            "user_id": str(user["_id"]),
            "email": user["email"],
            "proposed_password_hash": generate_password_hash(new_password),
            "status": "pending",
            "created_at": datetime.now(timezone.utc)
        })

        return render_template(
            "forgot_password.html",
            success=(
                "Your request has been submitted. Please contact BIZFLOW "
                "to approve your password reset."
            )
        )

    return render_template("forgot_password.html")

    # =========================
# WORKER DASHBOARD
# =========================


@app.route("/worker-dashboard/<business_id>")
def worker_dashboard(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Only worker accounts can access this dashboard.
    if session.get("role") != "worker":
        return "Access denied.", 403

    if not ObjectId.is_valid(business_id):
        return "Invalid business.", 400

    # Verify the worker's active assignment.
    membership = business_memberships.find_one({
        "business_id": business_id,
        "user_id": session["user_id"],
        "owner_id": session.get("business_owner_id"),
        "status": "active"
    })

    if not membership:
        return "Business access denied.", 403

    # Confirm the assigned business still belongs to its owner.
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": membership["owner_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Display today's sales without exposing costs or profit.
    eat = timezone(timedelta(hours=3))
    now = datetime.now(timezone.utc)
    today = now.astimezone(eat).date()

    local_start = datetime.combine(
        today,
        datetime.min.time(),
        tzinfo=eat
    )

    start_utc = local_start.astimezone(
        timezone.utc
    ).replace(tzinfo=None)

    end_utc = now.replace(tzinfo=None)

    today_sales = list(db["sales"].find({
        "business_id": business_id,
        "owner_id": membership["owner_id"],
        "status": "Completed",
        "created_at": {
            "$gte": start_utc,
            "$lte": end_utc
        }
    }))

    today_sales_count = len(today_sales)

    today_revenue = sum(
        float(sale.get("total", 0) or 0)
        for sale in today_sales
        if sale.get("payment_status") == "Paid"
    )

    return render_template(
        "worker_dashboard.html",
        business=business,
        worker_name=session.get("user_name", "Worker"),
        today_sales_count=today_sales_count,
        today_revenue=today_revenue
    )


# =========================
# DASHBOARD
# =========================


@app.route("/dashboard")
def dashboard():

    # Make sure user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Get only businesses belonging to the logged-in user
    businesses = list(
        businesses_collection.find({
            "owner_id": session["user_id"]
        })
    )

    # Get active platform announcements
    announcements = list(
        db["announcements"].find({
            "active": True
        }).sort("created_at", -1)
    )

    # Show the entrance animation only when redirected here after login
    show_dashboard_intro = session.pop("show_dashboard_intro", False)

    # Show the onboarding guide only for eligible first-time users
    show_onboarding_guide = session.pop("show_onboarding_guide", False)

    return render_template(
        "dashboard.html",
        user_name=session["user_name"],
        businesses=businesses,
        announcements=announcements,
        show_dashboard_intro=show_dashboard_intro,
        show_onboarding_guide=show_onboarding_guide
    )

# =========================
# COMPLETE ONBOARDING
# =========================


@app.route("/complete-onboarding", methods=["POST"])
def complete_onboarding():

    if "user_id" not in session:
        return redirect(url_for("login"))

    action = request.form.get("action")

    if action == "complete":
        users_collection.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": {
                "onboarding_completed": True,
                "onboarding_skipped": False
            }}
        )

    elif action == "skip":
        users_collection.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": {
                "onboarding_completed": False,
                "onboarding_skipped": True
            }}
        )

    return redirect(url_for("dashboard"))

    # =========================
# SUPER ADMIN: RESET USER ACCOUNT DATA
# =========================


@app.route("/admin/reset-account", methods=["POST"])
def admin_reset_account():

    # Only logged-in super admin can perform this action.
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    selected_user_id = request.form.get("user_id", "").strip()

    # Validate the selected user ID.
    if not ObjectId.is_valid(selected_user_id):
        return "Invalid user account selected.", 400

    # Never allow resetting the super administrator.
    if selected_user_id == session["user_id"]:
        return "You cannot reset your own administrator account.", 400

    selected_user = users_collection.find_one({
        "_id": ObjectId(selected_user_id)
    })

    if not selected_user:
        return "Selected user account was not found.", 404

    # Do not reset another super administrator account.
    if selected_user.get("email", "").lower() == SUPER_ADMIN_EMAIL.lower():
        return "The super administrator account cannot be reset here.", 403

    # Find only businesses owned by the selected user.
    owned_businesses = list(
        businesses_collection.find({
            "owner_id": selected_user_id
        }, {
            "_id": 1
        })
    )

    business_ids = [str(business["_id"]) for business in owned_businesses]

    # Delete business records belonging to this user or their businesses.
    record_collections = [
        "products",
        "services",
        "bookings",
        "sales",
        "expenses",
        "categories",
        "stock_movements"
    ]

    for collection_name in record_collections:
        collection = db[collection_name]

        ownership_filter = {
            "business_id": {"$in": business_ids}
        }

        collection.delete_many(ownership_filter)

    # Remove worker assignments for the selected user's businesses.
    # This does not delete worker login accounts.
    business_memberships.delete_many({
        "business_id": {"$in": business_ids}

    })

    # Delete only the selected user's business workspaces.
    # Perform all business-data deletions in one transaction.
    try:
        with client.start_session() as mongo_session:
            with mongo_session.start_transaction():

                # Delete records linked to the selected user's businesses.
                for collection_name in record_collections:
                    db[collection_name].delete_many(
                        {"business_id": {"$in": business_ids}},
                        session=mongo_session
                    )

                # Remove assignments, but preserve worker login accounts.
                business_memberships.delete_many(
                    {"business_id": {"$in": business_ids}},
                    session=mongo_session
                )

                # Remove only the selected user's business workspaces.
                businesses_collection.delete_many(
                    {"owner_id": selected_user_id},
                    session=mongo_session
                )

    except PyMongoError:
        app.logger.exception(
            "Account reset failed for user %s",
            selected_user_id
        )
        return "Account reset failed. Please check the server logs.", 500

    # IMPORTANT:
    # Keep the user's login account in the users collection.
    # Keep system announcements and other users' business data.

    return redirect(url_for("admin_panel"))


# =========================
# BIZFLOW SUPER ADMIN PANEL
# =========================


@app.route("/admin")
def admin_panel():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    # Fetch users without exposing password hashes.
    users = list(
        users_collection.find(
            {},
            {"password_hash": 0}
        ).sort("name", 1)
    )

    # Count businesses owned by each user.
    for user in users:
        user_id = str(user["_id"])
        user["business_count"] = businesses_collection.count_documents({
            "owner_id": user_id
        })

    # =========================
    # SYSTEM HEALTH CHECK
    # =========================

    try:
        db.command("ping")
        database_status = "Connected"
    except PyMongoError:
        database_status = "Unavailable"

    # =========================
    # DATABASE STORAGE METRICS
    # =========================

    # Configured display capacity: 500 MB
    storage_capacity_bytes = 500 * 1024 * 1024

    try:
        database_stats = db.command("dbStats")

        used_storage_bytes = (
            database_stats.get("dataSize", 0)
            + database_stats.get("indexSize", 0)
        )

        percent_used = min(
            100,
            round(
                (used_storage_bytes / storage_capacity_bytes) * 100,
                2
            )
        )

        remaining_bytes = max(
            0,
            storage_capacity_bytes - used_storage_bytes
        )

        def format_storage_size(size_bytes):
            if size_bytes < 1024 * 1024:
                return f"{size_bytes / 1024:.2f} KB"

            return f"{size_bytes / (1024 * 1024):.2f} MB"

        storage_stats = {
            "percent_used": percent_used,
            "used_display": format_storage_size(used_storage_bytes),
            "total_display": "500 MB",
            "remaining_display": format_storage_size(remaining_bytes)
        }

    except PyMongoError:
        storage_stats = {
            "percent_used": 0,
            "used_display": "Unavailable",
            "total_display": "500 MB",
            "remaining_display": "Unavailable"
        }

    # =========================
    # SYSTEM OVERVIEW STATISTICS
    # =========================

    total_users = users_collection.count_documents({})

    active_users = users_collection.count_documents({
        "account_status": {"$ne": "inactive"}
    })

    inactive_users = users_collection.count_documents({
        "account_status": "inactive"
    })

    total_businesses = businesses_collection.count_documents({})

    total_products = db["products"].count_documents({})

    total_services = db["services"].count_documents({})

    total_bookings = db["bookings"].count_documents({})

    total_sales = db["sales"].count_documents({})

    total_expenses = db["expenses"].count_documents({})

    # Financial totals from recorded product sales.
    sales_collection = db["sales"]
    expenses_collection = db["expenses"]

    sales_totals = list(sales_collection.aggregate([
        {
            "$group": {
                "_id": None,
                "revenue_received": {
                    "$sum": {"$ifNull": ["$amount_paid", 0]}
                },
                "outstanding_balance": {
                    "$sum": {"$ifNull": ["$balance", 0]}
                },
                "total_cost": {
                    "$sum": {"$ifNull": ["$total_cost", 0]}
                },
                "gross_profit": {
                    "$sum": {"$ifNull": ["$gross_profit", 0]}
                }
            }
        }
    ]))

    expense_totals = list(expenses_collection.aggregate([
        {
            "$group": {
                "_id": None,
                "total_expense_amount": {
                    "$sum": {"$ifNull": ["$amount", 0]}
                }
            }
        }
    ]))

    sales_summary = sales_totals[0] if sales_totals else {}
    expense_summary = expense_totals[0] if expense_totals else {}

    revenue_received = round(
        float(sales_summary.get("revenue_received", 0)), 2
    )

    outstanding_balance = round(
        float(sales_summary.get("outstanding_balance", 0)), 2
    )

    total_cost = round(
        float(sales_summary.get("total_cost", 0)), 2
    )

    gross_profit = round(
        float(sales_summary.get("gross_profit", 0)), 2
    )

    total_expense_amount = round(
        float(expense_summary.get("total_expense_amount", 0)), 2
    )

    estimated_net_profit = round(
        gross_profit - total_expense_amount, 2
    )

    overview_stats = {
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": inactive_users,
        "total_businesses": total_businesses,
        "total_products": total_products,
        "total_services": total_services,
        "total_bookings": total_bookings,
        "total_sales": total_sales,
        "total_expenses": total_expenses,
        "revenue_received": revenue_received,
        "outstanding_balance": outstanding_balance,
        "total_cost": total_cost,
        "gross_profit": gross_profit,
        "total_expense_amount": total_expense_amount,
        "estimated_net_profit": estimated_net_profit
    }

    # Optional selected user from the URL.
    selected_user_id = request.args.get("user_id", "").strip()
    selected_user = None
    selected_businesses = []

    if selected_user_id:
        if ObjectId.is_valid(selected_user_id):
            selected_user = users_collection.find_one(
                {"_id": ObjectId(selected_user_id)},
                {"password_hash": 0}
            )

    if selected_user:
        selected_owner_id = str(selected_user["_id"])

        selected_businesses = list(
            businesses_collection.find({
                "owner_id": selected_owner_id
            }).sort("name", 1)
        )

        # Count records belonging to each selected user's business.
        record_collections = {
            "sales_count": db["sales"],
            "products_count": db["products"],
            "services_count": db["services"],
            "bookings_count": db["bookings"],
            "expenses_count": db["expenses"],
            "categories_count": db["categories"],
            "stock_movements_count": db["stock_movements"]
        }

        for business in selected_businesses:
            business_id = str(business["_id"])

            for count_field, collection in record_collections.items():
                business[count_field] = collection.count_documents({
                    "business_id": business_id,
                    "owner_id": selected_owner_id
                })

    # Count records belonging to each selected user's business.
    record_collections = {
        "sales_count": db["sales"],
        "products_count": db["products"],
        "services_count": db["services"],
        "bookings_count": db["bookings"],
        "expenses_count": db["expenses"],
        "categories_count": db["categories"],
        "stock_movements_count": db["stock_movements"]
    }

    for business in selected_businesses:
        business_id = str(business["_id"])

        for count_field, collection in record_collections.items():
            business[count_field] = collection.count_documents({
                "business_id": business_id,
                "owner_id": selected_owner_id
            })

    # =========================
    # LOAD ADMIN ANNOUNCEMENTS
    # =========================

    announcements = list(
        db["announcements"].find().sort("created_at", -1)
    )

    # =========================
    # RECENT PLATFORM ACTIVITY
    # =========================

    recent_activity = []

    activity_sources = [
        ("User Registration", users_collection, "name"),
        ("Business Created", businesses_collection, "name"),
        ("Sale Recorded", db["sales"], "reference"),
        ("Booking Created", db["bookings"], "service_name"),
        ("Expense Recorded", db["expenses"], "name")
    ]

    for activity_type, collection, detail_field in activity_sources:
        records = list(
            collection.find(
                {"created_at": {"$exists": True}},
                {"password_hash": 0}
            ).sort("created_at", -1).limit(10)
        )

        for record in records:
            activity_date = record.get("created_at")

            if not activity_date:
                continue

            detail = record.get(detail_field)

            if not detail:
                detail = record.get("reference", "Record created")

            recent_activity.append({
                "type": activity_type,
                "detail": str(detail),
                "date": activity_date
            })

    recent_activity.sort(
        key=lambda activity: activity["date"],
        reverse=True
    )

    recent_activity = recent_activity[:10]

    # =========================
    # MAINTENANCE USER LIST
    # =========================

    maintenance_users = list(
        users_collection.find(
            {},
            {
                "password_hash": 0
            }
        ).sort("name", 1)
    )

    # =========================
    # PENDING PASSWORD RESET REQUESTS
    # =========================

    pending_password_resets = list(
        password_reset_requests.find({
            "status": "pending"
        }).sort("created_at", -1)
    )

    # =========================
    # PENDING ACCOUNT APPROVALS
    # =========================

    pending_account_approvals = list(
        users_collection.find({
            "account_status": "pending"
        }).sort("created_at", -1)
    )

    return render_template(
        "admin_panel.html",
        users=users,
        selected_user=selected_user,
        selected_businesses=selected_businesses,
        overview_stats=overview_stats,
        recent_activity=recent_activity,
        database_status=database_status,
        announcements=announcements,
        storage_stats=storage_stats,
        maintenance_users=maintenance_users,
        maintenance_enabled=maintenance_mode_enabled(),
        pending_password_resets=pending_password_resets,
        pending_account_approvals=pending_account_approvals,
    )

# =========================
# ADMIN: TOGGLE MAINTENANCE MODE
# =========================


@app.route("/admin/maintenance", methods=["POST"])
def admin_toggle_maintenance():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    enabled_value = request.form.get("enabled", "")

    if enabled_value not in ("true", "false"):
        return "Invalid maintenance setting.", 400

    new_state = enabled_value == "true"

    system_settings.update_one(
        {"_id": "maintenance_mode"},
        {
            "$set": {
                "enabled": new_state,
                "updated_at": datetime.now(timezone.utc)
            }
        },
        upsert=True
    )

    return redirect(url_for("admin_panel"))


# =========================
# ADMIN PASSWORD RESET REVIEW
# =========================

@app.route(
    "/admin/password-reset/<request_id>/<decision>",
    methods=["POST"]
)
def admin_review_password_reset(request_id, decision):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if decision not in ("approve", "reject"):
        return "Invalid password reset decision.", 400

    if not ObjectId.is_valid(request_id):
        return "Invalid password reset request.", 400

    reset_request = password_reset_requests.find_one({
        "_id": ObjectId(request_id),
        "status": "pending"
    })

    if not reset_request:
        return "This request has already been processed or does not exist.", 404

    if decision == "reject":
        result = password_reset_requests.update_one(
            {
                "_id": ObjectId(request_id),
                "status": "pending"
            },
            {
                "$set": {
                    "status": "rejected",
                    "reviewed_at": datetime.now(timezone.utc),
                    "reviewed_by": session.get("user_email", "")
                }
            }
        )

        if result.modified_count != 1:
            return "This request has already been processed.", 409

    else:
        proposed_password_hash = reset_request.get(
            "proposed_password_hash"
        )

        if not proposed_password_hash:
            return "This request has no proposed password.", 400

        user = users_collection.find_one({
            "_id": ObjectId(reset_request["user_id"])
        })

        if not user:
            return "The account associated with this request was not found.", 404

        # Mark the request as approved only if it is still pending.
        result = password_reset_requests.update_one(
            {
                "_id": ObjectId(request_id),
                "status": "pending"
            },
            {
                "$set": {
                    "status": "approved",
                    "reviewed_at": datetime.now(timezone.utc),
                    "reviewed_by": session.get("user_email", "")
                }
            }
        )

        if result.modified_count != 1:
            return "This request has already been processed.", 409

        # Activate the proposed password.
        users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password_hash": proposed_password_hash
                }
            }
        )

    return redirect(url_for("admin_panel"))


# =========================
# ADMIN ACCOUNT APPROVAL REVIEW
# =========================

@app.route(
    "/admin/account-approval/<user_id>/<decision>",
    methods=["POST"]
)
def admin_review_account(user_id, decision):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if decision not in ("approve", "reject"):
        return "Invalid account approval decision.", 400

    if not ObjectId.is_valid(user_id):
        return "Invalid user account.", 400

    account = users_collection.find_one({
        "_id": ObjectId(user_id),
        "account_status": "pending"
    })

    if not account:
        return "This account has already been processed or does not exist.", 404

    new_status = "active" if decision == "approve" else "rejected"

    result = users_collection.update_one(
        {
            "_id": ObjectId(user_id),
            "account_status": "pending"
        },
        {
            "$set": {
                "account_status": new_status,
                "account_reviewed_at": datetime.now(timezone.utc),
                "account_reviewed_by": session.get("user_email", "")
            }
        }
    )

    if result.modified_count != 1:
        return "This account has already been processed.", 409

    return redirect(url_for("admin_panel"))


# =========================
# ADMIN: CREATE ANNOUNCEMENT
# =========================

@app.route("/admin/announcements/create", methods=["POST"])
def admin_create_announcement():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    title = request.form.get("title", "").strip()
    message = request.form.get("message", "").strip()

    if not title or not message:
        return "Announcement title and message are required.", 400

    if len(title) > 150 or len(message) > 3000:
        return "Announcement title or message is too long.", 400

    announcement = {
        "title": title,
        "message": message,
        "created_by": session["user_id"],
        "created_at": datetime.now(timezone.utc),
        "active": True
    }

    db["announcements"].insert_one(announcement)

    return redirect(url_for("admin_panel") + "#announcements")


# =========================
# ADMIN: TOGGLE ANNOUNCEMENT STATUS
# =========================

@app.route(
    "/admin/announcements/<announcement_id>/toggle",
    methods=["POST"]
)
def admin_toggle_announcement(announcement_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(announcement_id):
        return "Invalid announcement ID.", 400

    announcement = db["announcements"].find_one({
        "_id": ObjectId(announcement_id)
    })

    if not announcement:
        return "Announcement not found.", 404

    new_status = not announcement.get("active", True)

    db["announcements"].update_one(
        {"_id": ObjectId(announcement_id)},
        {"$set": {"active": new_status}}
    )

    return redirect(url_for("admin_panel") + "#announcements")


# =========================
# ADMIN: DELETE ANNOUNCEMENT
# =========================

@app.route(
    "/admin/announcements/<announcement_id>/delete",
    methods=["POST"]
)
def admin_delete_announcement(announcement_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(announcement_id):
        return "Invalid announcement ID.", 400

    result = db["announcements"].delete_one({
        "_id": ObjectId(announcement_id)
    })

    if result.deleted_count == 0:
        return "Announcement not found.", 404

    return redirect(url_for("admin_panel") + "#announcements")


@app.route("/admin/users/<user_id>/toggle-status", methods=["POST"])
def admin_toggle_user_status(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(user_id):
        return "Invalid user ID.", 400

    target_user = users_collection.find_one({
        "_id": ObjectId(user_id)
    })

    if not target_user:
        return "User not found.", 404

    # Never allow this route to deactivate the super administrator.
    if target_user.get("email", "").lower() == "kimanialvin2003@gmail.com":
        return "The super administrator account cannot be deactivated.", 403

    current_status = target_user.get("account_status", "active")

    new_status = (
        "inactive" if current_status == "active" else "active"
    )

    users_collection.update_one(
        {"_id": target_user["_id"]},
        {"$set": {"account_status": new_status}}
    )

    return redirect(url_for(
        "admin_panel",
        user_id=user_id
    ))


# =========================
# ADMIN PERMANENT USER DELETION
# =========================

@app.route("/admin/delete-user/<user_id>", methods=["POST"])
def admin_delete_user(user_id):

    # Require login
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Only Super Admin can delete accounts
    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    # Validate user ID
    if not ObjectId.is_valid(user_id):
        return "Invalid user account ID.", 400

    user_object_id = ObjectId(user_id)

    # Find the account
    user_to_delete = users_collection.find_one({
        "_id": user_object_id
    })

    if not user_to_delete:
        return "User account not found.", 404

    # Protect Super Admin
    if user_to_delete.get("email", "").lower() == SUPER_ADMIN_EMAIL.lower():
        return "The Super Admin account cannot be deleted.", 403

    # Never allow deletion of the currently logged-in account
    if str(user_to_delete["_id"]) == session.get("user_id"):
        return "You cannot delete your own logged-in account.", 403

    owner_id = str(user_object_id)

    # Find businesses owned by this user
    owned_businesses = list(
        businesses_collection.find({
            "owner_id": owner_id
        }, {"_id": 1})
    )

    business_ids = [str(business["_id"]) for business in owned_businesses]

    # Collections containing records inside an owned business
    record_collections = [
        "products",
        "services",
        "bookings",
        "sales",
        "expenses",
        "categories",
        "stock_movements"
    ]

    # Delete records only inside businesses verified as owned by this user
    for business_id in business_ids:

        # Remove worker memberships linked to this business
        business_memberships.delete_many({
            "business_id": business_id
        })

        # Remove all records belonging to this business
        for collection_name in record_collections:
            db[collection_name].delete_many({
                "business_id": business_id
            })

        # Delete the business after its records are removed
        businesses_collection.delete_one({
            "_id": ObjectId(business_id),
            "owner_id": owner_id
        })

    # Remove worker memberships for this user
    business_memberships.delete_many({
        "user_id": owner_id
    })

    # Remove pending password recovery requests
    password_reset_requests.delete_many({
        "user_id": owner_id
    })

    # Finally, delete the user account only if it is not the Super Admin
    delete_result = users_collection.delete_one({
        "_id": user_object_id,
        "email": {"$ne": SUPER_ADMIN_EMAIL}
    })

    if delete_result.deleted_count != 1:
        return "Account was not deleted. Please verify its status.", 409

    return redirect(url_for("admin_panel"))


@app.route("/admin/business/<business_id>/sales")
def admin_business_sales(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(business_id):
        return "Invalid business ID.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id)
    })

    if not business:
        return "Business not found.", 404

    owner_id = str(business["owner_id"])
    business_id_string = str(business["_id"])

    sales = list(
        db["sales"].find({
            "business_id": business_id_string,
            "owner_id": owner_id
        }).sort("created_at", -1).limit(200)
    )

    return render_template(
        "admin_business_sales.html",
        business=business,
        sales=sales
    )


@app.route("/admin/business/<business_id>/sales/<reference>/receipt")
def admin_sale_receipt(business_id, reference):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(business_id):
        return "Invalid business ID.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id)
    })

    if not business:
        return "Business not found.", 404

    sale = db["sales"].find_one({
        "business_id": str(business["_id"]),
        "owner_id": str(business["owner_id"]),
        "reference": reference
    })

    if not sale:
        return "Sale receipt not found.", 404

    return render_template(
        "sale_receipt.html",
        business=business,
        sale=sale
    )


@app.route("/admin/business/<business_id>/bookings")
def admin_business_bookings(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(business_id):
        return "Invalid business ID.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id)
    })

    if not business:
        return "Business not found.", 404

    bookings_list = list(
        db["bookings"].find({
            "business_id": str(business["_id"]),
            "owner_id": str(business["owner_id"])
        }).sort("created_at", -1).limit(200)
    )

    return render_template(
        "admin_business_bookings.html",
        business=business,
        bookings_list=bookings_list
    )


@app.route("/admin/business/<business_id>/products")
def admin_business_products(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(business_id):
        return "Invalid business ID.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id)
    })

    if not business:
        return "Business not found.", 404

    products_list = list(
        db["products"].find({
            "business_id": str(business["_id"]),
            "owner_id": str(business["owner_id"])
        }).sort("name", 1).limit(500)
    )

    return render_template(
        "admin_business_products.html",
        business=business,
        products_list=products_list
    )


@app.route("/admin/business/<business_id>/services")
def admin_business_services(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(business_id):
        return "Invalid business ID.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id)
    })

    if not business:
        return "Business not found.", 404

    services_list = list(
        db["services"].find({
            "business_id": str(business["_id"]),
            "owner_id": str(business["owner_id"])
        }).sort("name", 1).limit(500)
    )

    return render_template(
        "admin_business_services.html",
        business=business,
        services_list=services_list
    )


@app.route("/admin/business/<business_id>/expenses")
def admin_business_expenses(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(business_id):
        return "Invalid business ID.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id)
    })

    if not business:
        return "Business not found.", 404

    expenses_list = list(
        db["expenses"].find({
            "business_id": str(business["_id"]),
            "owner_id": str(business["owner_id"])
        }).sort("created_at", -1).limit(500)
    )

    return render_template(
        "admin_business_expenses.html",
        business=business,
        expenses_list=expenses_list
    )


@app.route("/admin/business/<business_id>/workers")
def admin_business_workers(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(business_id):
        return "Invalid business ID.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id)
    })

    if not business:
        return "Business not found.", 404

    workers_list = list(
        business_memberships.find({
            "business_id": str(business["_id"]),
            "status": "active",
            "role": {"$ne": "owner"}
        }).sort("created_at", -1).limit(500)
    )

    for worker in workers_list:
        worker_user_id = worker.get("user_id", "")

        worker_user = None

        if ObjectId.is_valid(worker_user_id):
            worker_user = users_collection.find_one(
                {"_id": ObjectId(worker_user_id)},
                {"password_hash": 0}
            )

        worker["worker_name"] = (
            worker_user.get("name", "Unknown worker")
            if worker_user else "Unknown worker"
        )

        worker["worker_email"] = (
            worker_user.get("email", "—")
            if worker_user else "—"
        )

    return render_template(
        "admin_business_workers.html",
        business=business,
        workers_list=workers_list
    )


@app.route("/admin/business/<business_id>/categories")
def admin_business_categories(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(business_id):
        return "Invalid business ID.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id)
    })

    if not business:
        return "Business not found.", 404

    categories_list = list(
        db["categories"].find({
            "business_id": str(business["_id"]),
            "owner_id": str(business["owner_id"])
        }).sort("name", 1).limit(500)
    )

    return render_template(
        "admin_business_categories.html",
        business=business,
        categories_list=categories_list
    )


@app.route("/admin/business/<business_id>/stock-movements")
def admin_business_stock_movements(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(business_id):
        return "Invalid business ID.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id)
    })

    if not business:
        return "Business not found.", 404

    movements_list = list(
        db["stock_movements"].find({
            "business_id": str(business["_id"]),
            "owner_id": str(business["owner_id"])
        }).sort("created_at", -1).limit(500)
    )

    return render_template(
        "admin_business_stock_movements.html",
        business=business,
        movements_list=movements_list
    )


@app.route("/admin/business/<business_id>/details")
def admin_business_details(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_super_admin():
        return "Access denied. Super administrator only.", 403

    if not ObjectId.is_valid(business_id):
        return "Invalid business ID.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id)
    })

    if not business:
        return "Business not found.", 404

    owner_id = str(business.get("owner_id", ""))
    owner = None

    if ObjectId.is_valid(owner_id):
        owner = users_collection.find_one(
            {"_id": ObjectId(owner_id)},
            {"password_hash": 0}
        )

    return render_template(
        "admin_business_details.html",
        business=business,
        owner=owner
    )


# =========================
# CREATE BUSINESS PAGE
# =========================

@app.route("/create-business", methods=["GET", "POST"])
def create_business():

    # Make sure user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        business_name = request.form["business_name"].strip()
        business_type = request.form["business_type"].strip()
        description = request.form["description"].strip()

        # Create business document
        business = {
            "owner_id": session["user_id"],
            "name": business_name,
            "type": business_type,
            "description": description
        }

        # Save business to MongoDB
        businesses_collection.insert_one(business)

        # Return to dashboard
        return redirect(url_for("dashboard"))

    return render_template("create_business.html")

# =========================
# BUSINESS WORKSPACE
# =========================


# =========================
# BUSINESS WORKSPACE
# =========================

@app.route("/business/<business_id>")
def business_workspace(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Allow the owner or an assigned worker.
    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    if role not in ("owner", "worker"):
        return "Access denied.", 403

    return render_template(
        "business_workspace.html",
        business=business,
        role=role
    )


@app.route("/business/<business_id>/loan-customer-search")
def loan_customer_search(business_id):

    if "user_id" not in session:
        return jsonify({"names": []}), 401

    business, role = get_business_access(business_id)

    if not business:
        return jsonify({"names": []}), 404

    if role not in ("owner", "worker"):
        return jsonify({"names": []}), 403

    owner_id = str(business["owner_id"])

    query = request.args.get("q", "").strip()

    # Start searching after the first letter is typed.
    if not query or len(query) > 150:
        return jsonify({"names": []})

    # Match names beginning with the typed letters.
    prefix = "^" + re.escape(query)

    matching_names = db["sales"].distinct(
        "customer_name",
        {
            "business_id": str(business["_id"]),
            "owner_id": owner_id,
            "sale_type": "loan",
            "customer_name": {
                "$regex": prefix,
                "$options": "i"
            }
        }
    )

    names = sorted(
        {
            name.strip()
            for name in matching_names
            if isinstance(name, str) and name.strip()
        },
        key=str.casefold
    )

    return jsonify({"names": names[:10]})


# =========================
# REPORTS & ANALYTICS
# =========================


@app.route("/business/<business_id>/reports")
def reports(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(business_id):
        return "Invalid business.", 400

    # Only the logged-in owner's business can be viewed.
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Use Kenya local dates for reporting.
    eat = timezone(timedelta(hours=3))
    now = datetime.now(timezone.utc)
    today = now.astimezone(eat).date()

    week_start_date = today - timedelta(days=today.weekday())
    month_start_date = today.replace(day=1)
    trend_start_date = today - timedelta(days=29)

    # Query enough history for both this month's totals and the
    # 30-day trend, whichever requires the earlier start date.
    earliest_date = min(
        week_start_date,
        month_start_date,
        trend_start_date
    )

    local_start = datetime.combine(
        earliest_date,
        datetime.min.time(),
        tzinfo=eat
    )

    # PyMongo normally returns datetimes as naive UTC values.
    start_utc = local_start.astimezone(timezone.utc).replace(tzinfo=None)
    end_utc = now.replace(tzinfo=None)

    sales = list(db["sales"].find({
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"],
        "status": "Completed",
        "payment_status": "Paid",
        "created_at": {
            "$gte": start_utc,
            "$lte": end_utc
        }
    }).sort("created_at", 1))

    # Initialise daily, weekly and monthly summaries.
    today_revenue = today_cost = today_profit = 0.0
    weekly_revenue = weekly_cost = weekly_profit = 0.0
    monthly_revenue = monthly_cost = monthly_profit = 0.0

    # Create all 30 trend dates, including dates with no sales.
    trend_data = {}
    for offset in range(30):
        day = trend_start_date + timedelta(days=offset)
        trend_data[day] = {
            "revenue": 0.0,
            "profit": 0.0
        }

    product_totals = {}
    total_sales_30_days = 0

    for sale in sales:
        created_at = sale.get("created_at")
        if not created_at:
            continue

        # Handle PyMongo's usual naive-UTC datetime values safely.
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        sale_date = created_at.astimezone(eat).date()

        revenue = float(sale.get("total", 0) or 0)
        cost = float(sale.get("total_cost", 0) or 0)
        profit = float(
            sale.get("gross_profit", revenue - cost)
            if sale.get("gross_profit") is not None
            else revenue - cost
        )

        if sale_date == today:
            today_revenue += revenue
            today_cost += cost
            today_profit += profit

        if week_start_date <= sale_date <= today:
            weekly_revenue += revenue
            weekly_cost += cost
            weekly_profit += profit

        if sale_date.year == today.year and sale_date.month == today.month:
            monthly_revenue += revenue
            monthly_cost += cost
            monthly_profit += profit

        # Build the 30-day trend and best-selling product ranking.
        if trend_start_date <= sale_date <= today:
            total_sales_30_days += 1

            trend_data[sale_date]["revenue"] += revenue
            trend_data[sale_date]["profit"] += profit

            for item in sale.get("items", []):
                product_id = item.get(
                    "product_id") or item.get("name", "unknown")
                product_name = item.get("name", "Unknown product")
                quantity = float(item.get("quantity", 0) or 0)
                line_revenue = float(
                    item.get("line_total", 0) or 0
                )
                line_profit = float(
                    item.get("line_profit", 0) or 0
                )

                if product_id not in product_totals:
                    product_totals[product_id] = {
                        "name": product_name,
                        "quantity": 0.0,
                        "revenue": 0.0,
                        "profit": 0.0
                    }

                product_totals[product_id]["quantity"] += quantity
                product_totals[product_id]["revenue"] += line_revenue
                product_totals[product_id]["profit"] += line_profit

    # =========================
    # OPERATING EXPENSES
    # =========================

    # Exclude stock purchases and owner withdrawals from operating
    # expenses. Category comparisons ignore capitalization and spaces.
    excluded_expense_categories = {
        "stock purchases",
        "owner withdrawals",
        "owner withdrawal",
        "drawings",
    }

    expense_records = list(db["expenses"].find({
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"],
        "expense_date": {
            "$gte": trend_start_date.isoformat(),
            "$lte": today.isoformat()
        }
    }))

    today_expenses = 0.0
    weekly_expenses = 0.0
    monthly_expenses = 0.0

    # Track operating expenses by date for the 30-day chart.
    for expense in expense_records:
        category = " ".join(
            str(expense.get("category", "")).lower().split()
        )

        if category in excluded_expense_categories:
            continue

        try:
            amount = float(expense.get("amount", 0) or 0)
        except (TypeError, ValueError):
            continue

        expense_date_text = expense.get("expense_date", "")

        try:
            expense_date = datetime.strptime(
                expense_date_text, "%Y-%m-%d"
            ).date()
        except (TypeError, ValueError):
            continue

        if expense_date == today:
            today_expenses += amount

        if week_start_date <= expense_date <= today:
            weekly_expenses += amount

        if (
            expense_date.year == today.year
            and expense_date.month == today.month
        ):
            monthly_expenses += amount

        if trend_start_date <= expense_date <= today:
            trend_data[expense_date]["profit"] -= amount

    # Convert gross profit into profit after operating expenses.
    today_profit -= today_expenses
    weekly_profit -= weekly_expenses
    monthly_profit -= monthly_expenses

    # Highest quantity sold appears first.
    best_sellers = sorted(
        product_totals.values(),
        key=lambda product: product["quantity"],
        reverse=True
    )[:5]

    # Highest quantity sold appears first.
    best_sellers = sorted(
        product_totals.values(),
        key=lambda product: product["quantity"],
        reverse=True
    )[:5]

    trend_labels = [
        day.strftime("%d %b")
        for day in trend_data
    ]

    trend_revenue = [
        round(values["revenue"], 2)
        for values in trend_data.values()
    ]

    trend_profit = [
        round(values["profit"], 2)
        for values in trend_data.values()
    ]

    return render_template(
        "reports.html",
        business=business,

        today_revenue=round(today_revenue, 2),
        today_cost=round(today_cost, 2),
        today_profit=round(today_profit, 2),
        today_expenses=round(today_expenses, 2),

        weekly_revenue=round(weekly_revenue, 2),
        weekly_cost=round(weekly_cost, 2),
        weekly_profit=round(weekly_profit, 2),
        weekly_expenses=round(weekly_expenses, 2),

        monthly_revenue=round(monthly_revenue, 2),
        monthly_cost=round(monthly_cost, 2),
        monthly_profit=round(monthly_profit, 2),
        monthly_expenses=round(monthly_expenses, 2),

        best_sellers=best_sellers,
        total_sales_30_days=total_sales_30_days,
        trend_labels=trend_labels,
        trend_revenue=trend_revenue,
        trend_profit=trend_profit
    )

    # =========================
# CREATE PRODUCT WORKSPACE
# =========================


@app.route("/business/<business_id>/products/create", methods=["GET", "POST"])
def create_product(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Make sure the business belongs to the logged-in user
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Create category
    if request.method == "POST":

        category_name = request.form["category_name"].strip()

        if not category_name:
            return "Category name is required.", 400

        category = {
            "business_id": str(business["_id"]),
            "owner_id": session["user_id"],
            "name": category_name,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }

        db["categories"].insert_one(category)

        return redirect(
            url_for(
                "create_product",
                business_id=business["_id"]
            )
        )

    # Get categories belonging ONLY to this business
    categories = list(
        db["categories"].find({
            "business_id": str(business["_id"]),
            "owner_id": session["user_id"]
        }).sort("name", 1)
    )

    return render_template(
        "create_product.html",
        business=business,
        categories=categories
    )


# =========================
# DELETE CATEGORY
# =========================

@app.route(
    "/business/<business_id>/products/category/<category_id>/delete",
    methods=["POST"]
)
def delete_category(business_id, category_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(business_id) or not ObjectId.is_valid(category_id):
        return "Invalid business or category ID.", 400

    # Verify that the logged-in user owns this business.
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Verify that this category belongs to this business and user.
    category_query = {
        "_id": ObjectId(category_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    }

    category = db["categories"].find_one(category_query)

    if not category:
        return "Category not found or access denied.", 404

    # Prevent deletion while the category still contains products.
    products_in_category = db["products"].find_one({
        "category_id": str(category["_id"]),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    })

    if products_in_category:
        return (
            "This category contains products. "
            "Move or remove its products before deleting the category."
        ), 400

    db["categories"].delete_one(category_query)

    return redirect(url_for(
        "products",
        business_id=business_id
    ))

    # =========================
# CATEGORY WORKSPACE
# =========================


@app.route("/business/<business_id>/products/category/<category_id>")
def category_workspace(business_id, category_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    category = db["categories"].find_one({
        "_id": ObjectId(category_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    })

    if not category:
        return "Category not found or access denied.", 404

    products = list(
        db["products"].find({
            "business_id": str(business["_id"]),
            "category_id": str(category["_id"]),
            "owner_id": session["user_id"]
        }).sort("name", 1)
    )

    return render_template(
        "category_workspace.html",
        business=business,
        category=category,
        products=products
    )

    # =========================
# CREATE PRODUCT IN CATEGORY
# =========================


@app.route("/business/<business_id>/products/category/<category_id>/create", methods=["GET", "POST"])
def create_product_in_category(business_id, category_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Verify business belongs to logged-in user
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Verify category belongs to this business and user
    category = db["categories"].find_one({
        "_id": ObjectId(category_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    })

    if not category:
        return "Category not found or access denied.", 404

    if request.method == "POST":

        product_name = request.form["product_name"].strip()
        sku = request.form["sku"].strip()
        description = request.form["description"].strip()

        measurement_type = request.form["measurement_type"]

        opening_quantity = float(request.form["opening_quantity"])
        low_stock_threshold = float(request.form["low_stock_threshold"])

        buying_price = float(request.form["buying_price"])
        selling_price = float(request.form["selling_price"])

        allowed_measurements = {
            "Piece",
            "Kilogram",
            "Gram",
            "Litre",
            "Millilitre",
            "KEG",
            "MALA"
        }

        if measurement_type not in allowed_measurements:
            return "Please select a valid measurement type.", 400

        has_selling_sizes = (
            measurement_type in {"KEG", "MALA"}
            and request.form.get("has_selling_sizes", "no") == "yes"
        )

        selling_sizes = []
        large_cups_per_keg = None
        small_cups_per_keg = None

        if has_selling_sizes:
            try:
                large_cups_per_keg = int(
                    request.form.get("large_cups_per_keg", 0)
                )
                small_cups_per_keg = int(
                    request.form.get("small_cups_per_keg", 0)
                )
                large_cup_price = float(
                    request.form.get("large_cup_price", 0)
                )
                small_cup_price = float(
                    request.form.get("small_cup_price", 0)
                )
            except (ValueError, TypeError):
                return "Enter valid serving quantities and prices.", 400

            if large_cups_per_keg <= 0 or small_cups_per_keg <= 0:
                return "Cup servings per keg must be greater than zero.", 400

            if (
                not math.isfinite(large_cup_price)
                or not math.isfinite(small_cup_price)
                or large_cup_price <= 0
                or small_cup_price <= 0
            ):
                return "Enter valid prices for both cup sizes.", 400

            selling_sizes = [
                {
                    "name": "Large Cup",
                    "price": large_cup_price,
                    "servings_per_piece": large_cups_per_keg
                },
                {
                    "name": "Small Cup",
                    "price": small_cup_price,
                    "servings_per_piece": small_cups_per_keg
                }
            ]

        if not product_name:
            return "Product name is required.", 400

        product = {
            "business_id": str(business["_id"]),
            "category_id": str(category["_id"]),
            "owner_id": session["user_id"],

            "name": product_name,
            "sku": sku,
            "description": description,

            "measurement_type": measurement_type,

            "opening_quantity": opening_quantity,
            "quantity": opening_quantity,
            "low_stock_threshold": low_stock_threshold,

            "buying_price": buying_price,
            "selling_price": selling_price,
            "selling_sizes": selling_sizes,
            "large_cups_per_keg": large_cups_per_keg,
            "small_cups_per_keg": small_cups_per_keg,

            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }

        db["products"].insert_one(product)

        return redirect(
            url_for(
                "category_workspace",
                business_id=business["_id"],
                category_id=category["_id"]
            )
        )

    return render_template(
        "create_product_in_category.html",
        business=business,
        category=category
    )


# =========================
# SELL PRODUCT - CUSTOMER CORNER
# =========================

@app.route("/business/<business_id>/products/sell")
def sell_products(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(business_id):
        return "Invalid business.", 400

    user_id = session["user_id"]
    role = session.get("role", "owner")

    # Workers may only access the business assigned to their session.
    if role == "worker":
        if session.get("business_id") != business_id:
            return "Access denied.", 403

        membership = business_memberships.find_one({
            "business_id": business_id,
            "user_id": user_id,
            "owner_id": session.get("business_owner_id"),
            "status": "active"
        })

        if not membership:
            return "Your business assignment is no longer active.", 403

        owner_id = membership["owner_id"]

    elif role == "owner":
        owner_id = user_id

    else:
        return "Access denied.", 403

    # Always load the business using its actual owner's ID.
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": owner_id
    })

    if not business:
        return "Business not found or access denied.", 404

    # Search only products belonging to this business and its owner.
    search_term = request.args.get("q", "").strip()

    product_query = {
        "business_id": str(business["_id"]),
        "owner_id": owner_id
    }

    if search_term:
        safe_search = re.escape(search_term)
        product_query["$or"] = [
            {"name": {"$regex": safe_search, "$options": "i"}},
            {"sku": {"$regex": safe_search, "$options": "i"}},
            {"description": {"$regex": safe_search, "$options": "i"}}
        ]

    products = list(
        db["products"].find(product_query).sort("name", 1)
    )

    return render_template(
        "sell_product.html",
        business=business,
        products=products,
        search_term=search_term,
        sale_token=secrets.token_urlsafe(24)
    )


# =========================
# CONFIRM PRODUCT SALE
# =========================

@app.route(
    "/business/<business_id>/products/confirm-sale",
    methods=["POST"]
)
def confirm_product_sale(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Validate the business ID.
    if not ObjectId.is_valid(business_id):
        return "Invalid business.", 400

    user_id = session["user_id"]
    role = session.get("role", "owner")

    # Resolve the real business owner.
    if role == "worker":
        if session.get("business_id") != business_id:
            return "Access denied.", 403

        membership = business_memberships.find_one({
            "business_id": business_id,
            "user_id": user_id,
            "owner_id": session.get("business_owner_id"),
            "status": "active"
        })

        if not membership:
            return "Your business assignment is no longer active.", 403

        owner_id = membership["owner_id"]

    elif role == "owner":
        owner_id = user_id

    else:
        return "Access denied.", 403

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": owner_id
    })

    if not business:
        return "Business not found or access denied.", 404

    business_id_string = str(business["_id"])

    # Read submitted form data
    cart_data = request.form.get("cart_data", "")
    payment_method = request.form.get("payment_method", "").strip()
    sale_token = request.form.get("sale_token", "").strip()
    draft_id = request.form.get("draft_id", "").strip()

    sale_type = request.form.get("sale_type", "paid").strip().lower()
    customer_name = request.form.get("customer_name", "").strip()

    if sale_type not in {"paid", "loan"}:
        return "Invalid sale type.", 400

    if sale_type == "loan" and not customer_name:
        return "Enter the customer's name for a loan sale.", 400

    allowed_methods = {
        "Cash",
        "M-Pesa",
        "Card",
        "Bank Transfer",
        "Other"
    }

    if sale_type == "paid" and payment_method not in allowed_methods:
        return "Please select a valid payment method.", 400
    if sale_type == "loan":
        payment_method = "Credit"

    if not sale_token or len(sale_token) > 200:
        return "Invalid sale submission. Refresh the page and try again.", 400

    try:

        cart = json.loads(cart_data)

        if not isinstance(cart, list) or not cart:
            return "Your cart is empty or invalid.", 400

        if len(cart) > 100:
            return "Too many items in one sale.", 400

        requested_items = []

        for item in cart:

            if not isinstance(item, dict):
                return "Invalid cart item.", 400

            product_id = str(item.get("product_id", "")).strip()

            if not ObjectId.is_valid(product_id):
                return "Invalid product in cart.", 400

            try:
                quantity = float(item.get("quantity", 0))
            except (ValueError, TypeError):
                return "Invalid quantity in cart.", 400

            if not math.isfinite(quantity) or quantity <= 0:
                return "Every item must have a valid quantity.", 400

            selling_size = str(
                item.get("selling_size", "")
            ).strip()

            requested_items.append({
                "product_id": ObjectId(product_id),
                "quantity": quantity,
                "selling_size": selling_size
            })

    except (ValueError, TypeError, json.JSONDecodeError):
        return "Invalid cart data. Please refresh and try again.", 400

    sales_collection = db["sales"]

    try:
        # Ensure repeated submissions cannot create duplicate sales.
        sales_collection.create_index(
            [
                ("business_id", 1),
                ("owner_id", 1),
                ("sale_token", 1)
            ],
            unique=True,
            partialFilterExpression={
                "sale_token": {"$type": "string"}
            },
            name="unique_product_sale_submission"
        )

        # If this same submission was already saved, reuse it.
        existing_sale = sales_collection.find_one({
            "business_id": business_id_string,
            "owner_id": owner_id,
            "sale_token": sale_token
        })

        if existing_sale:
            return redirect(
                url_for(
                    "sell_products",
                    business_id=business["_id"],
                    sale="success",
                    reference=existing_sale["reference"]
                )
            )

        sale_reference = (
            "SALE-"
            + datetime.now(timezone.utc).strftime("%Y%m%d")
            + "-"
            + secrets.token_hex(4).upper()
        )

        sale_time = datetime.now(timezone.utc)

        # MongoDB transaction: stock updates and sale record
        # either commit together or roll back together.
        with client.start_session() as mongo_session:
            with mongo_session.start_transaction():

                line_items = []
                total_revenue = 0.0
                total_cost = 0.0

                # Always retrieve prices and stock from MongoDB.
                for requested in requested_items:

                    product = db["products"].find_one(
                        {
                            "_id": requested["product_id"],
                            "business_id": business_id_string,
                            "owner_id": owner_id
                        },
                        session=mongo_session
                    )

                    if not product:
                        raise ValueError(
                            "A product was not found in this business."
                        )

                    quantity = requested["quantity"]
                    selling_size = requested["selling_size"]
                    stock = float(product.get("quantity", 0))
                    unit = product.get("measurement_type", "Piece")

                    selling_price = float(
                        product.get("selling_price", 0)
                    )
                    buying_price = float(
                        product.get("buying_price", 0)
                    )

                    stock_used = quantity
                    unit_cost = buying_price
                    size_servings = 1

                    if selling_size:
                        sizes = product.get("selling_sizes", [])

                        selected_size = next(
                            (
                                size for size in sizes
                                if size.get("name") == selling_size
                            ),
                            None
                        )

                        if not selected_size:
                            raise ValueError(
                                f"Invalid selling size for {product['name']}."
                            )

                        selling_price = float(
                            selected_size.get("price", 0)
                        )
                        size_servings = float(
                            selected_size.get("servings_per_piece", 0)
                        )

                        if (
                            not math.isfinite(size_servings)
                            or size_servings <= 0
                        ):
                            raise ValueError(
                                f"Invalid serving configuration for "
                                f"{product['name']}."
                            )

                        stock_used = round(quantity / size_servings, 8)
                        unit_cost = buying_price / size_servings

                    whole_units = {
                        "piece", "pieces", "item", "items"
                    }

                    if (
                        not selling_size
                        and unit.strip().lower() in whole_units
                        and not quantity.is_integer()
                    ):
                        raise ValueError(
                            f"{product['name']} must be sold in whole units."
                        )

                    if (
                        not math.isfinite(selling_price)
                        or not math.isfinite(buying_price)
                        or selling_price < 0
                        or buying_price < 0
                    ):
                        raise ValueError(
                            f"Invalid price recorded for {product['name']}."
                        )

                    if stock_used > stock + 1e-9:
                        raise ValueError(
                            f"Insufficient stock for {product['name']}. "
                            f"Available: {stock:g} {unit}."
                        )

                    line_revenue = round(quantity * selling_price, 2)
                    line_cost = round(quantity * unit_cost, 2)

                    line_items.append({
                        "product_id": str(product["_id"]),
                        "name": product["name"],
                        "sku": product.get("sku", ""),
                        "measurement_type": (
                            selling_size or unit
                        ),
                        "quantity": quantity,
                        "selling_size": selling_size,
                        "stock_used": stock_used,
                        "stock_unit": unit,
                        "unit_selling_price": selling_price,
                        "unit_cost": unit_cost,
                        "line_total": line_revenue,
                        "line_cost": line_cost,
                        "line_profit": round(
                            line_revenue - line_cost, 2
                        )
                    })

                    total_revenue += line_revenue
                    total_cost += line_cost

                # Validate combined stock usage for each product.
                combined_stock_usage = {}

                for item in line_items:
                    product_id = item["product_id"]

                    combined_stock_usage[product_id] = (
                        combined_stock_usage.get(product_id, 0.0)
                        + float(item["stock_used"])
                    )

                for product_id, stock_used in combined_stock_usage.items():

                    product = db["products"].find_one(
                        {
                            "_id": ObjectId(product_id),
                            "business_id": business_id_string,
                            "owner_id": owner_id
                        },
                        session=mongo_session
                    )

                    if not product:
                        raise ValueError(
                            "A product was not found in this business."
                        )

                    available_stock = float(product.get("quantity", 0))

                    if stock_used > available_stock + 1e-9:
                        raise ValueError(
                            f"Insufficient combined stock for "
                            f"{product.get('name', 'product')}. "
                            f"Required: {stock_used:g}; "
                            f"available: {available_stock:g}."
                        )

                # Deduct stock once per product using the combined usage.
                for product_id, stock_used in combined_stock_usage.items():

                    result = db["products"].update_one(
                        {
                            "_id": ObjectId(product_id),
                            "business_id": business_id_string,
                            "owner_id": owner_id,
                            "quantity": {"$gte": stock_used}
                        },
                        {
                            "$inc": {
                                "quantity": -stock_used
                            },
                            "$set": {
                                "updated_at": datetime.now(timezone.utc)
                            }
                        },
                        session=mongo_session
                    )

                    if result.modified_count != 1:
                        raise ValueError(
                            "Stock changed while processing the sale. "
                            "Refresh Customer Corner and try again."
                        )

                total_revenue = round(total_revenue, 2)
                total_cost = round(total_cost, 2)
                gross_profit = round(
                    total_revenue - total_cost, 2
                )
                payment_status = "Paid" if sale_type == "paid" else "Unpaid"

                amount_paid = total_revenue if sale_type == "paid" else 0.0
                balance = round(total_revenue - amount_paid, 2)

                sale = {
                    "reference": sale_reference,
                    "sale_token": sale_token,
                    "draft_id": draft_id if draft_id else None,
                    "business_id": business_id_string,
                    "owner_id": owner_id,
                    "processed_by": user_id,
                    "processed_by_role": role,
                    "items": line_items,
                    "total": total_revenue,
                    "total_cost": total_cost,
                    "gross_profit": gross_profit,
                    "sale_type": sale_type,
                    "customer_name": customer_name if sale_type == "loan" else "",
                    "payment_method": payment_method,
                    "payment_status": payment_status,
                    "amount_paid": amount_paid,
                    "balance": balance,
                    "payments": [],
                    "status": "Completed",
                    "created_at": sale_time
                }

                sales_collection.insert_one(
                    sale,
                    session=mongo_session
                )

                # Close the customer tab only after the sale commits.
                # Close the customer tab within the same transaction.
                # If this update fails, the sale transaction rolls back.
                if draft_id:
                    if not ObjectId.is_valid(draft_id):
                        raise ValueError("Invalid customer tab ID.")

                    draft_result = sales_drafts_collection.update_one(
                        {
                            "_id": ObjectId(draft_id),
                            "business_id": business_id_string,
                            "owner_id": owner_id,
                            "status": "open"
                        },
                        {
                            "$set": {
                                "status": "completed",
                                "completed_sale_reference": sale_reference,
                                "completed_at": datetime.now(timezone.utc),
                                "completed_by": user_id
                            }
                        },
                        session=mongo_session
                    )

                    if draft_result.modified_count != 1:
                        raise ValueError(
                            "The customer tab is no longer open. "
                            "Refresh the tabs and check whether the sale "
                            "was already completed."
                        )
        return redirect(
            url_for(
                "sale_receipt",
                business_id=business["_id"],
                reference=sale_reference,
                next_sale=1
            )
        )

    except ValueError as error:
        return str(error), 400

    except DuplicateKeyError:
        # A repeated submission may already have been recorded.
        existing_sale = sales_collection.find_one({
            "business_id": business_id_string,
            "owner_id": owner_id,
            "sale_token": sale_token
        })

        if existing_sale:
            # If this sale belongs to a customer tab, close that
            # tab only when it matches the recorded sale.
            existing_draft_id = existing_sale.get("draft_id")

            if existing_draft_id and ObjectId.is_valid(existing_draft_id):
                sales_drafts_collection.update_one(
                    {
                        "_id": ObjectId(existing_draft_id),
                        "business_id": business_id_string,
                        "owner_id": owner_id,
                        "status": "open"
                    },
                    {
                        "$set": {
                            "status": "completed",
                            "completed_sale_reference": existing_sale["reference"],
                            "completed_at": datetime.now(timezone.utc),
                            "completed_by": user_id
                        }
                    }
                )

            return redirect(
                url_for(
                    "sale_receipt",
                    business_id=business["_id"],
                    reference=existing_sale["reference"]
                )
            )

        return "This sale submission already exists.", 409

    except PyMongoError:
        app.logger.exception("Product sale transaction failed.")
        return (
            "The sale could not be completed. "
            "Check the database connection and try again.",
            500
        )


# =========================
# OPEN CUSTOMER TABS
# =========================


@app.route(
    "/business/<business_id>/sales-drafts/save",
    methods=["POST"]
)
def save_sales_draft(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    business, access_role = get_business_access(business_id)

    if not business or access_role not in {"owner", "worker"}:
        return "Business not found or access denied.", 403

    try:
        cart_data = request.form.get("cart_data", "")
        customer_name = request.form.get("customer_name", "").strip()
        draft_id = request.form.get("draft_id", "").strip()

        if not customer_name or len(customer_name) > 150:
            return "Enter a customer name or tab reference (maximum 150 characters).", 400

        cart = json.loads(cart_data)

        if not isinstance(cart, dict) or not cart or len(cart) > 100:
            return "Add between 1 and 100 products to the draft.", 400

        items = []

        for cart_key, item in cart.items():
            if not isinstance(item, dict):
                return "Invalid product in draft.", 400

            # Get the real product ID from the cart item.
            product_id = str(item.get("productId", "")).strip()

            # Support older cart data that used product IDs as keys.
            if not product_id:
                product_id = str(cart_key).split("::", 1)[0].strip()

            if not ObjectId.is_valid(product_id):
                return "Invalid product in draft.", 400

            try:
                quantity = float(item.get("quantity", 0))
            except (ValueError, TypeError):
                return "Invalid quantity in draft.", 400

            if not math.isfinite(quantity) or quantity <= 0:
                return "Every product must have a valid quantity.", 400

            selling_size = str(
                item.get("sellingSize", "") or ""
            ).strip()

            product = db["products"].find_one({
                "_id": ObjectId(product_id),
                "business_id": str(business["_id"]),
                "owner_id": business["owner_id"]
            })

            if not product:
                return "A product was not found in this business.", 400

            unit = product.get("measurement_type", "Piece")

            if not isinstance(unit, str):
                unit = "Piece"

            servings_per_piece = 1

            if selling_size:
                matching_size = next(
                    (
                        size for size in product.get("selling_sizes", [])
                        if size.get("name") == selling_size
                    ),
                    None
                )

                if not matching_size:
                    return (
                        f"The selling size '{selling_size}' is no longer "
                        f"available for {product['name']}."
                    ), 400

                servings_per_piece = float(
                    matching_size.get("servings_per_piece", 0)
                )

                if (
                    not math.isfinite(servings_per_piece)
                    or servings_per_piece <= 0
                ):
                    return "Invalid selling-size configuration.", 400

            if (
                not selling_size
                and unit.strip().lower() in {
                    "piece", "pieces", "item", "items"
                }
                and not quantity.is_integer()
            ):
                return f"{product['name']} must be sold in whole units.", 400

            items.append({
                "product_id": str(product["_id"]),
                "quantity": quantity,
                "selling_size": selling_size,
                "servings_per_piece": servings_per_piece,
                "price": float(
                    matching_size["price"] if selling_size
                    else item.get("price", product.get("selling_price", 0))
                ),
                "name": product["name"],
                "sku": product.get("sku", ""),
                "unit": selling_size or unit
            })

        now = datetime.now(timezone.utc)

        if draft_id:
            if not ObjectId.is_valid(draft_id):
                return "Invalid customer tab ID.", 400

            existing_draft = sales_drafts_collection.find_one({
                "_id": ObjectId(draft_id),
                "business_id": str(business["_id"]),
                "owner_id": business["owner_id"],
                "status": "open"
            })

            if not existing_draft:
                return "Open customer tab not found. Refresh the tab list.", 404

            result = sales_drafts_collection.update_one(
                {
                    "_id": ObjectId(draft_id),
                    "business_id": str(business["_id"]),
                    "owner_id": business["owner_id"],
                    "status": "open"
                },
                {
                    "$set": {
                        "customer_name": customer_name,
                        "items": items,
                        "updated_by": session["user_id"],
                        "updated_at": now
                    }
                }
            )

            if result.matched_count != 1:
                return "Customer tab could not be updated. Please refresh.", 409

            saved_draft_id = draft_id

        else:
            draft = {
                "business_id": str(business["_id"]),
                "owner_id": business["owner_id"],
                "customer_name": customer_name,
                "items": items,
                "status": "open",
                "created_by": session["user_id"],
                "updated_by": session["user_id"],
                "created_at": now,
                "updated_at": now
            }

            result = sales_drafts_collection.insert_one(draft)
            saved_draft_id = str(result.inserted_id)

        return redirect(url_for(
            "sell_products",
            business_id=business["_id"],
            draft_saved=saved_draft_id
        ))

    except (ValueError, TypeError, json.JSONDecodeError):
        return "Invalid draft data. Please check the cart and try again.", 400

    except PyMongoError:
        app.logger.exception("Could not save customer tab.")
        return "The customer tab could not be saved. Please try again.", 500


@app.route("/business/<business_id>/sales-drafts", methods=["GET"])
def list_sales_drafts(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    business, access_role = get_business_access(business_id)

    if not business or access_role not in {"owner", "worker"}:
        return "Business not found or access denied.", 403

    drafts = list(sales_drafts_collection.find({
        "business_id": str(business["_id"]),
        "owner_id": business["owner_id"],
        "status": "open"
    }).sort("updated_at", -1).limit(100))

    results = []

    for draft in drafts:
        total = 0.0
        item_count = 0

        for item in draft.get("items", []):
            product = db["products"].find_one({
                "_id": ObjectId(item["product_id"]),
                "business_id": str(business["_id"]),
                "owner_id": business["owner_id"]
            })

            if product:
                quantity = float(item.get("quantity", 0))
                selling_size = item.get("selling_size", "")

                if selling_size:
                    matching_size = next(
                        (
                            size for size in product.get("selling_sizes", [])
                            if size.get("name") == selling_size
                        ),
                        None
                    )

                    price = float(
                        matching_size.get("price", 0)
                    ) if matching_size else 0.0
                else:
                    price = float(
                        item.get(
                            "price",
                            product.get("selling_price", 0)
                        )
                    )

                total += quantity * price
                item_count += 1

        results.append({
            "id": str(draft["_id"]),
            "customer_name": draft.get("customer_name", "Customer"),
            "total": round(total, 2),
            "item_count": item_count,
            "updated_at": draft.get("updated_at")
        })

    return {
        "drafts": results
    }


@app.route(
    "/business/<business_id>/sales-drafts/<draft_id>",
    methods=["GET"]
)
def get_sales_draft(business_id, draft_id):
    if "user_id" not in session:
        return {"error": "Please log in."}, 401

    business, access_role = get_business_access(business_id)

    if not business or access_role not in {"owner", "worker"}:
        return {"error": "Access denied."}, 403

    if not ObjectId.is_valid(draft_id):
        return {"error": "Invalid customer tab."}, 400

    draft = sales_drafts_collection.find_one({
        "_id": ObjectId(draft_id),
        "business_id": str(business["_id"]),
        "owner_id": business["owner_id"],
        "status": "open"
    })

    if not draft:
        return {"error": "Open customer tab not found."}, 404

    items = []

    for item in draft.get("items", []):
        if not ObjectId.is_valid(item.get("product_id", "")):
            continue

        product = db["products"].find_one({
            "_id": ObjectId(item["product_id"]),
            "business_id": str(business["_id"]),
            "owner_id": business["owner_id"]
        })

        if product:
            selling_size = item.get("selling_size", "") or ""
            matching_size = None

            if selling_size:
                matching_size = next(
                    (
                        size for size in product.get("selling_sizes", [])
                        if size.get("name") == selling_size
                    ),
                    None
                )

                # Skip sizes that are no longer configured.
                if not matching_size:
                    continue

            price = (
                float(matching_size.get("price", 0))
                if matching_size
                else float(item.get(
                    "price",
                    product.get("selling_price", 0)
                ))
            )

            items.append({
                "product_id": str(product["_id"]),
                "name": product.get("name", ""),
                "sku": product.get("sku", ""),
                "price": price,
                "stock": float(product.get("quantity", 0)),
                "unit": (
                    selling_size
                    or product.get("measurement_type", "Piece")
                ),
                "quantity": float(item.get("quantity", 0)),
                "selling_size": selling_size,
                "servings_per_piece": float(
                    matching_size.get("servings_per_piece", 1)
                ) if matching_size else 1
            })

    return {
        "id": str(draft["_id"]),
        "customer_name": draft.get("customer_name", ""),
        "items": items
    }


@app.route("/business/<business_id>/orders/create", methods=["POST"])
def create_order(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    # Only the owner can create orders and enter production costs.
    if role != "owner":
        return "Only the business owner can create orders.", 403

    from decimal import Decimal, InvalidOperation

    def read_money(value, field_name):
        try:
            amount = Decimal(value or "0")
        except (InvalidOperation, ValueError):
            raise ValueError(f"Invalid amount for {field_name}.")

        if not amount.is_finite() or amount < 0:
            raise ValueError(f"{field_name} cannot be negative.")

        return amount

    try:
        customer_name = request.form.get("customer_name", "").strip()
        customer_contact = request.form.get("customer_contact", "").strip()
        order_description = request.form.get("order_description", "").strip()

        if not customer_name:
            return "Customer or institution name is required.", 400

        agreed_total = read_money(
            request.form.get("agreed_total"),
            "Agreed total"
        )

        deposit = read_money(
            request.form.get("deposit"),
            "Deposit"
        )

        if agreed_total <= 0:
            return "The agreed order price must be greater than zero.", 400

        if deposit > agreed_total:
            return "The deposit cannot exceed the agreed order price.", 400

        item_names = request.form.getlist("item_name[]")
        item_quantities = request.form.getlist("item_quantity[]")
        item_units = request.form.getlist("item_unit[]")
        item_selling_prices = request.form.getlist("item_selling_price[]")
        item_unit_costs = request.form.getlist("item_unit_cost[]")

        row_counts = {
            len(item_names),
            len(item_quantities),
            len(item_units),
            len(item_selling_prices),
            len(item_unit_costs)
        }

        if len(row_counts) != 1 or not item_names:
            return "Please provide complete details for every order item.", 400

        items = []
        total_cost = Decimal("0")
        items_selling_total = Decimal("0")

        allowed_units = {
            "pieces", "pairs", "boxes", "kilograms", "grams",
            "litres", "millilitres", "metres", "centimetres",
            "sets", "packets", "rolls", "services", "other"
        }

        for index in range(len(item_names)):

            name = item_names[index].strip()
            unit = item_units[index].strip().lower()

            if not name:
                return f"Item {index + 1} needs a name.", 400

            if unit not in allowed_units:
                return f"Item {index + 1} has an invalid unit.", 400

            try:
                quantity = Decimal(item_quantities[index])
            except (InvalidOperation, ValueError):
                return f"Item {index + 1} has an invalid quantity.", 400

            if not quantity.is_finite() or quantity <= 0:
                return f"Item {index + 1} quantity must be greater than zero.", 400

            selling_price = read_money(
                item_selling_prices[index],
                f"Item {index + 1} selling price"
            )

            unit_cost = read_money(
                item_unit_costs[index],
                f"Item {index + 1} production cost"
            )

            line_total = quantity * selling_price
            line_cost = quantity * unit_cost
            line_profit = line_total - line_cost

            items_selling_total += line_total
            total_cost += line_cost

            items.append({
                "name": name,
                "quantity": float(quantity),
                "unit": unit,
                "unit_selling_price": float(selling_price),
                "unit_cost": float(unit_cost),
                "line_total": float(line_total),
                "line_cost": float(line_cost),
                "line_profit": float(line_profit)
            })

        # The agreed order price may differ from the sum of item prices.
        total_profit = agreed_total - total_cost
        balance = agreed_total - deposit

        production_status = request.form.get(
            "production_status", "Pending"
        )

        delivery_status = request.form.get(
            "delivery_status", "Not Delivered"
        )

        if production_status not in {
            "Pending", "In Progress", "Completed"
        }:
            return "Invalid production status.", 400

        if delivery_status not in {
            "Not Delivered", "Partially Delivered", "Delivered"
        }:
            return "Invalid delivery status.", 400

        now = datetime.now(timezone.utc)

        order = {
            "business_id": str(business["_id"]),
            "owner_id": str(business["owner_id"]),
            "customer_name": customer_name,
            "customer_contact": customer_contact,
            "order_description": order_description,
            "items": items,
            "items_selling_total": float(items_selling_total),
            "agreed_total": float(agreed_total),
            "total_cost": float(total_cost),
            "total_profit": float(total_profit),
            "deposit": float(deposit),
            "total_paid": float(deposit),
            "balance": float(balance),
            "payments": [],
            "production_status": production_status,
            "delivery_status": delivery_status,
            "payment_status": (
                "Paid" if balance == 0 else
                "Partially Paid" if deposit > 0 else "Unpaid"
            ),
            "created_by": str(session["user_id"]),
            "created_at": now,
            "updated_at": now
        }

        if deposit > 0:
            order["payments"].append({
                "amount": float(deposit),
                "payment_type": "Deposit",
                "recorded_by": str(session["user_id"]),
                "created_at": now
            })

        orders_collection.insert_one(order)

        return redirect(
            url_for("business_orders", business_id=business_id)
        )

    except ValueError as error:
        return str(error), 400


@app.route(
    "/business/<business_id>/orders/<order_id>/edit",
    methods=["GET", "POST"]
)
def edit_order(business_id, order_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    if role != "owner":
        return "Only the business owner can edit orders.", 403

    try:
        order_object_id = ObjectId(order_id)
    except Exception:
        return "Invalid order ID.", 400

    order = orders_collection.find_one({
        "_id": order_object_id,
        "business_id": str(business["_id"]),
        "owner_id": str(business["owner_id"])
    })

    if not order:
        return "Order not found.", 404

    if request.method == "POST":

        customer_name = request.form.get("customer_name", "").strip()
        customer_contact = request.form.get("customer_contact", "").strip()
        order_description = request.form.get("order_description", "").strip()

        production_status = request.form.get("production_status", "")
        delivery_status = request.form.get("delivery_status", "")

        if not customer_name:
            return "Customer or institution name is required.", 400

        if production_status not in {
            "Pending", "In Progress", "Completed"
        }:
            return "Invalid production status.", 400

        if delivery_status not in {
            "Not Delivered", "Partially Delivered", "Delivered"
        }:
            return "Invalid delivery status.", 400

        orders_collection.update_one(
            {
                "_id": order_object_id,
                "business_id": str(business["_id"]),
                "owner_id": str(business["owner_id"])
            },
            {
                "$set": {
                    "customer_name": customer_name,
                    "customer_contact": customer_contact,
                    "order_description": order_description,
                    "production_status": production_status,
                    "delivery_status": delivery_status,
                    "updated_at": datetime.now(timezone.utc)
                }
            }
        )

        return redirect(
            url_for("business_orders", business_id=business_id)
        )

    return render_template(
        "edit_order.html",
        business=business,
        order=order
    )


@app.route(
    "/business/<business_id>/orders/<order_id>/payment",
    methods=["POST"]
)
def record_order_payment(business_id, order_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    # Workers cannot record payments in this initial version.
    if role != "owner":
        return "Only the business owner can record order payments.", 403

    from decimal import Decimal, InvalidOperation
    from bson.objectid import ObjectId
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError

    try:
        order_object_id = ObjectId(order_id)
    except Exception:
        return "Invalid order ID.", 400

    order = orders_collection.find_one({
        "_id": order_object_id,
        "business_id": str(business["_id"]),
        "owner_id": str(business["owner_id"])
    })

    if not order:
        return "Order not found.", 404

    try:
        amount = Decimal(request.form.get("amount", "").strip())
    except (InvalidOperation, ValueError):
        return "Enter a valid payment amount.", 400

    if not amount.is_finite() or amount <= 0:
        return "Payment amount must be greater than zero.", 400

    balance = Decimal(str(order.get("balance", 0)))

    if balance <= 0:
        return "This order is already fully paid.", 400

    if amount > balance:
        return "Payment cannot exceed the outstanding balance.", 400

    now = datetime.now(timezone.utc)

    new_total_paid = Decimal(str(order.get("total_paid", 0))) + amount
    new_balance = Decimal(str(order["agreed_total"])) - new_total_paid

    payment = {
        "amount": float(amount),
        "payment_type": "Instalment",
        "recorded_by": str(session["user_id"]),
        "created_at": now
    }

    if new_balance == 0:
        payment_status = "Paid"
    elif new_total_paid > 0:
        payment_status = "Partially Paid"
    else:
        payment_status = "Unpaid"

    try:
        result = orders_collection.update_one(
            {
                "_id": order_object_id,
                "business_id": str(business["_id"]),
                "owner_id": str(business["owner_id"]),
                "balance": order["balance"]
            },
            {
                "$push": {"payments": payment},
                "$set": {
                    "total_paid": float(new_total_paid),
                    "balance": float(new_balance),
                    "payment_status": payment_status,
                    "updated_at": now
                }
            }
        )
    except PyMongoError:
        return "Could not save the payment. Please try again.", 500

    if result.modified_count != 1:
        return "The order changed while recording payment. Refresh and try again.", 409

    return redirect(
        url_for("business_orders", business_id=business_id)
    )


@app.route("/business/<business_id>/orders")
def business_orders(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Allow the business owner or an assigned worker.
    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    if role not in ("owner", "worker"):
        return "Access denied.", 403

    business_id_string = str(business["_id"])
    owner_id = str(business["owner_id"])

    # Load only orders belonging to this business.
    orders = list(
        orders_collection.find({
            "business_id": business_id_string,
            "owner_id": owner_id
        }).sort("created_at", -1).limit(100)
    )

    # Hide confidential costs and profits from workers.
    if role == "worker":
        for order in orders:
            order.pop("total_cost", None)
            order.pop("total_profit", None)

            for item in order.get("items", []):
                item.pop("unit_cost", None)
                item.pop("line_cost", None)
                item.pop("line_profit", None)

    return render_template(
        "orders.html",
        business=business,
        role=role,
        orders=orders
    )


@app.route("/business/<business_id>/loans")
def business_loans(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Allow the business owner or an assigned worker
    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied", 404

    if role not in ("owner", "worker"):
        return "Access denied", 403

    owner_id = str(business["owner_id"])

    # Load loans belonging to this business
    loan_records = list(db["sales"].find({
        "business_id": str(business["_id"]),
        "owner_id": owner_id,
        "sale_type": "loan"
    }).sort("created_at", 1))

    # Group separate credit purchases by customer
    customers = {}

    for loan in loan_records:
        customer_name = (loan.get("customer_name") or "").strip()

        if not customer_name:
            customer_name = "Unnamed customer"

        customer_key = customer_name.casefold()

        if customer_key not in customers:
            customers[customer_key] = {
                "customer_name": customer_name,
                "loans": [],
                "total_loan_value": 0.0,
                "total_paid": 0.0,
                "total_outstanding": 0.0,
                "repayment_reference": None
            }

        customer = customers[customer_key]

        loan_total = float(loan.get("total", 0) or 0)
        amount_paid = float(loan.get("amount_paid", 0) or 0)

        balance = float(
            loan.get(
                "balance",
                max(loan_total - amount_paid, 0)
            ) or 0
        )

        loan["display_balance"] = max(balance, 0)
        loan["display_amount_paid"] = amount_paid

        if balance > 0 and not customer["repayment_reference"]:
            customer["repayment_reference"] = loan.get("reference")

        customer["loans"].append(loan)
        customer["total_loan_value"] += loan_total
        customer["total_paid"] += amount_paid
        customer["total_outstanding"] += max(balance, 0)

    customer_loans = list(customers.values())

    total_loan_value = sum(
        customer["total_loan_value"]
        for customer in customer_loans
    )

    total_paid = sum(
        customer["total_paid"]
        for customer in customer_loans
    )

    total_outstanding = sum(
        customer["total_outstanding"]
        for customer in customer_loans
    )

    return render_template(
        "loans.html",
        business=business,
        loans=customer_loans,
        total_loan_value=total_loan_value,
        total_paid=total_paid,
        total_outstanding=total_outstanding,
        role=role
    )


@app.route(
    "/business/<business_id>/loans/<reference>/repayment",
    methods=["POST"]
)
def record_loan_repayment(business_id, reference):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Allow the owner or an assigned worker
    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    if role not in ("owner", "worker"):
        return "Access denied.", 403

    owner_id = str(business["owner_id"])
    business_id_str = str(business["_id"])

    try:
        amount = round(
            float(request.form.get("amount", "0")), 2
        )
    except (ValueError, TypeError):
        return "Enter a valid repayment amount.", 400

    if not math.isfinite(amount) or amount <= 0:
        return "Repayment must be greater than zero.", 400

    payment_method = request.form.get(
        "payment_method", ""
    ).strip()

    allowed_methods = {
        "Cash", "M-Pesa", "Card", "Bank Transfer", "Other"
    }

    if payment_method not in allowed_methods:
        return "Select a valid payment method.", 400

    sales_collection = db["sales"]

    seed_loan = sales_collection.find_one({
        "business_id": business_id_str,
        "owner_id": owner_id,
        "reference": reference,
        "sale_type": "loan"
    })

    if not seed_loan:
        return "Loan not found.", 404

    customer_name = (
        seed_loan.get("customer_name") or ""
    ).strip()

    if not customer_name:
        return "This loan has no customer name.", 400

    # Find all loans for this customer in this business
    all_loans = list(sales_collection.find({
        "business_id": business_id_str,
        "owner_id": owner_id,
        "sale_type": "loan"
    }).sort("created_at", 1))

    customer_loans = []

    for loan in all_loans:
        loan_customer = (
            loan.get("customer_name") or ""
        ).strip()

        if loan_customer.casefold() == customer_name.casefold():

            loan_total = float(loan.get("total", 0) or 0)
            amount_paid = float(
                loan.get("amount_paid", 0) or 0
            )

            balance = float(
                loan.get(
                    "balance",
                    max(loan_total - amount_paid, 0)
                ) or 0
            )

            loan["_calculated_balance"] = round(
                max(balance, 0), 2
            )

            customer_loans.append(loan)

    combined_balance = round(
        sum(
            loan["_calculated_balance"]
            for loan in customer_loans
        ),
        2
    )

    if combined_balance <= 0:
        return "This customer has no outstanding loan balance.", 400

    if amount > combined_balance:
        return (
            f"Repayment exceeds the customer's combined "
            f"outstanding balance of KSh {combined_balance:,.2f}.",
            400
        )

    now = datetime.now(timezone.utc)
    remaining_payment = amount

    try:
        # Allocate payment to the oldest outstanding loans first.
        # MongoDB transaction keeps the updates together.
        with client.start_session() as mongo_session:
            with mongo_session.start_transaction():

                for loan in customer_loans:

                    if remaining_payment <= 0:
                        break

                    balance = loan["_calculated_balance"]

                    if balance <= 0:
                        continue

                    applied_amount = round(
                        min(remaining_payment, balance), 2
                    )

                    old_paid = round(
                        float(loan.get("amount_paid", 0) or 0),
                        2
                    )

                    new_paid = round(
                        old_paid + applied_amount, 2
                    )

                    new_balance = round(
                        balance - applied_amount, 2
                    )

                    new_status = (
                        "Paid" if new_balance == 0
                        else "Partial"
                    )

                    # Match the current balance safely, including
                    # older loan records without a balance field.
                    update_filter = {
                        "_id": loan["_id"],
                        "business_id": business_id_str,
                        "owner_id": owner_id,
                        "sale_type": "loan"
                    }

                    if "balance" in loan:
                        update_filter["balance"] = loan["balance"]
                    else:
                        update_filter["balance"] = {
                            "$exists": False
                        }

                    result = sales_collection.update_one(
                        update_filter,
                        {
                            "$set": {
                                "amount_paid": new_paid,
                                "balance": new_balance,
                                "payment_status": new_status,
                                "updated_at": now
                            },
                            "$push": {
                                "payments": {
                                    "amount": applied_amount,
                                    "payment_method": payment_method,
                                    "paid_at": now,
                                    "recorded_by": session["user_id"]
                                }
                            }
                        },
                        session=mongo_session
                    )

                    if result.modified_count != 1:
                        raise RuntimeError(
                            "A loan changed during repayment."
                        )

                    remaining_payment = round(
                        remaining_payment - applied_amount, 2
                    )

    except RuntimeError:
        return (
            "A loan changed while recording the repayment. "
            "Refresh and try again.",
            409
        )

    except PyMongoError:
        app.logger.exception("Loan repayment failed.")
        return "Could not record the repayment. Try again.", 500

    return redirect(
        url_for(
            "business_loans",
            business_id=business_id_str
        )
    )


# =========================
# VIEW SALES RECEIPT
# =========================


@app.route("/business/<business_id>/sales/<reference>/receipt")
def sale_receipt(business_id, reference):

    if "user_id" not in session:
        return redirect(url_for("login"))

    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    if role not in ("owner", "worker"):
        return "Access denied.", 403

    owner_id = str(business["owner_id"])

    sale_query = {
        "business_id": str(business["_id"]),
        "owner_id": owner_id,
        "reference": reference
    }

    sale = db["sales"].find_one(sale_query)

    if not sale:
        return "Sale receipt not found.", 404

    return render_template(
        "sale_receipt.html",
        business=business,
        sale=sale
    )


@app.route("/business/<business_id>/sales")
def sales_history(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(business_id):
        return "Invalid business.", 400

    user_id = session["user_id"]
    role = session.get("role", "owner")

    # Verify the user's access to this business.
    if role == "worker":
        if session.get("business_id") != business_id:
            return "Access denied.", 403

        membership = business_memberships.find_one({
            "business_id": business_id,
            "user_id": user_id,
            "owner_id": session.get("business_owner_id"),
            "status": "active"
        })

        if not membership:
            return "Your business assignment is no longer active.", 403

        owner_id = membership["owner_id"]

    elif role == "owner":
        owner_id = user_id

    else:
        return "Access denied.", 403

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": owner_id
    })

    if not business:
        return "Business not found or access denied.", 404

    # Kenya uses East Africa Time (UTC+3).
    eat = timezone(timedelta(hours=3))
    today = datetime.now(timezone.utc).astimezone(eat).date()

    period = request.args.get("period", "all")
    start_value = request.args.get("start_date", "").strip()
    end_value = request.args.get("end_date", "").strip()

    start_date = None
    end_date = None

    if period == "today":
        start_date = today
        end_date = today

    elif period == "week":
        start_date = today - timedelta(days=today.weekday())
        end_date = today

    elif period == "month":
        start_date = today.replace(day=1)
        end_date = today

    elif period == "custom":
        try:
            if start_value:
                start_date = datetime.strptime(
                    start_value, "%Y-%m-%d"
                ).date()

            if end_value:
                end_date = datetime.strptime(
                    end_value, "%Y-%m-%d"
                ).date()

        except ValueError:
            return "Invalid date. Please use the date filter.", 400

        if start_date and end_date and start_date > end_date:
            return "Start date cannot be after end date.", 400

    else:
        period = "all"

    # Convert Kenya local midnight into UTC-naive datetimes.
    date_filter = {}

    if start_date:
        local_start = datetime(
            start_date.year, start_date.month, start_date.day,
            tzinfo=eat
        )
        date_filter["$gte"] = (
            local_start.astimezone(timezone.utc).replace(tzinfo=None)
        )

    if end_date:
        day_after = end_date + timedelta(days=1)
        local_end = datetime(
            day_after.year, day_after.month, day_after.day,
            tzinfo=eat
        )
        date_filter["$lt"] = (
            local_end.astimezone(timezone.utc).replace(tzinfo=None)
        )

    # Owners see all business sales; workers see only their own.
    query = {
        "business_id": str(business["_id"]),
        "owner_id": str(owner_id)
    }

    if role == "worker":
        query["processed_by"] = user_id

    if date_filter:
        query["created_at"] = date_filter

    sales = list(
        db["sales"].find(query).sort("created_at", -1)
    )

    # Only owners receive confidential financial summaries.
    if role == "owner":
        total_revenue = sum(
            float(sale.get("total", 0) or 0)
            for sale in sales
        )

        total_cost = sum(
            float(sale.get("total_cost", 0) or 0)
            for sale in sales
        )

        total_profit = sum(
            float(
                sale.get(
                    "gross_profit",
                    float(sale.get("total", 0) or 0)
                    - float(sale.get("total_cost", 0) or 0)
                ) or 0
            )
            for sale in sales
        )
    else:
        total_revenue = 0
        total_cost = 0
        total_profit = 0

    return render_template(
        "sales_history.html",
        business=business,
        sales=sales,
        period=period,
        start_date=start_date.isoformat() if start_date else start_value,
        end_date=end_date.isoformat() if end_date else end_value,
        total_revenue=round(total_revenue, 2),
        total_cost=round(total_cost, 2),
        total_profit=round(total_profit, 2),
        role=role
    )

  # =========================
# PRODUCTS
# =========================


@app.route("/business/<business_id>/products")
def products(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    if role not in ("owner", "worker"):
        return "Access denied.", 403

    owner_id = str(business["owner_id"])

    products = list(
        db["products"].find({
            "business_id": str(business["_id"]),
            "owner_id": owner_id
        })
    )

    return render_template(
        "products.html",
        business=business,
        products=products
    )

    # =========================
# VIEW INVENTORY
# =========================


@app.route("/business/<business_id>/inventory")
def view_inventory(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(business_id):
        return "Invalid business.", 400

    # Allow the owner and assigned workers to view inventory.
    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    if role not in ("owner", "worker"):
        return "Access denied.", 403

    owner_id = str(business["owner_id"])

    # Retrieve physical products belonging to this business.
    products = list(db["products"].find({
        "business_id": str(business["_id"]),
        "owner_id": owner_id
    }).sort("name", 1))

    total_products = len(products)
    total_units = 0.0
    total_stock_cost = 0.0
    low_stock_count = 0
    out_of_stock_count = 0

    for product in products:
        quantity = float(product.get("quantity", 0) or 0)
        threshold = float(
            product.get("low_stock_threshold", 0) or 0
        )

        # Only calculate confidential stock cost for the owner.
        if role == "owner":
            buying_price = float(
                product.get("buying_price", 0) or 0
            )
            total_stock_cost += quantity * buying_price

        total_units += quantity

        if quantity <= 0:
            out_of_stock_count += 1
            product["inventory_status"] = "Out of stock"
        elif quantity <= threshold:
            low_stock_count += 1
            product["inventory_status"] = "Low stock"
        else:
            product["inventory_status"] = "In stock"

        # Do not expose buying costs to workers through the template.
        if role == "worker":
            product.pop("buying_price", None)

    return render_template(
        "inventory.html",
        business=business,
        products=products,
        total_products=total_products,
        total_units=total_units,
        total_stock_cost=(
            round(total_stock_cost, 2) if role == "owner" else None
        ),
        low_stock_count=low_stock_count,
        out_of_stock_count=out_of_stock_count,
        role=role
    )


# =========================
# VIEW PRODUCT
# =========================

@app.route("/business/<business_id>/products/<product_id>")
def view_product(business_id, product_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Verify business ownership
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Find product belonging to this business and user
    product = db["products"].find_one({
        "_id": ObjectId(product_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    })

    if not product:
        return "Product not found or access denied.", 404

    return render_template(
        "view_product.html",
        business=business,
        product=product
    )

# =========================
# EDIT PRODUCT
# =========================


@app.route(
    "/business/<business_id>/products/<product_id>/edit",
    methods=["GET", "POST"]
)
def edit_product(business_id, product_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Verify business ownership
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Find product and verify ownership
    product = db["products"].find_one({
        "_id": ObjectId(product_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    })

    if not product:
        return "Product not found or access denied.", 404

    if request.method == "POST":

        name = request.form["name"].strip()
        category = request.form["category"].strip()
        description = request.form["description"].strip()

        buying_price = float(request.form["buying_price"])
        selling_price = float(request.form["selling_price"])
        quantity = int(request.form["quantity"])
        low_stock_threshold = int(
            request.form["low_stock_threshold"]
        )

        db["products"].update_one(
            {
                "_id": ObjectId(product_id),
                "business_id": str(business["_id"]),
                "owner_id": session["user_id"]
            },
            {
                "$set": {
                    "name": name,
                    "category": category,
                    "description": description,
                    "buying_price": buying_price,
                    "selling_price": selling_price,
                    "quantity": quantity,
                    "low_stock_threshold": low_stock_threshold
                }
            }
        )

        return redirect(
            url_for(
                "view_product",
                business_id=business["_id"],
                product_id=product["_id"]
            )
        )

    return render_template(
        "edit_product.html",
        business=business,
        product=product
    )


# =========================
# DELETE PRODUCT
# =========================

@app.route(
    "/business/<business_id>/products/<product_id>/delete",
    methods=["POST"]
)
def delete_product(business_id, product_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Verify business ownership
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Delete only if product belongs to
    # this business AND this user
    result = db["products"].delete_one({
        "_id": ObjectId(product_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    })

    if result.deleted_count == 0:
        return "Product not found or access denied.", 404

    return redirect(
        url_for(
            "products",
            business_id=business["_id"]
        )
    )
# =========================
# ADD PRODUCT
# =========================


@app.route("/business/<business_id>/products/add", methods=["GET", "POST"])
def add_product(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    if request.method == "POST":

        name = request.form["name"].strip()
        category = request.form["category"].strip()
        description = request.form["description"].strip()

        buying_price = float(request.form["buying_price"])
        selling_price = float(request.form["selling_price"])
        quantity = int(request.form["quantity"])
        low_stock_threshold = int(
            request.form["low_stock_threshold"]
        )

        measurement_type = request.form.get(
            "measurement_type", "Piece"
        ).strip()

        has_selling_sizes = (
            measurement_type in {"KEG", "MALA"}
            and request.form.get("has_selling_sizes", "no") == "yes"
        )

        selling_sizes = []
        large_cups_per_keg = None
        small_cups_per_keg = None

        if has_selling_sizes:

            large_cups_per_keg = int(
                request.form.get("large_cups_per_keg", 0)
            )

            small_cups_per_keg = int(
                request.form.get("small_cups_per_keg", 0)
            )

            large_cup_price = float(
                request.form.get("large_cup_price", 0)
            )

            small_cup_price = float(
                request.form.get("small_cup_price", 0)
            )

            if large_cups_per_keg <= 0 or small_cups_per_keg <= 0:
                return "Cup servings per keg must be greater than zero.", 400

            if large_cup_price <= 0 or small_cup_price <= 0:
                return "Enter a valid price for both cup sizes.", 400

            selling_sizes = [
                {
                    "name": "Large Cup",
                    "price": large_cup_price,
                    "servings_per_piece": large_cups_per_keg
                },
                {
                    "name": "Small Cup",
                    "price": small_cup_price,
                    "servings_per_piece": small_cups_per_keg
                }
            ]

        product = {
            "business_id": str(business["_id"]),
            "owner_id": session["user_id"],
            "name": name,
            "category": category,
            "description": description,
            "buying_price": buying_price,
            "selling_price": selling_price,
            "selling_sizes": selling_sizes,
            "large_cups_per_keg": large_cups_per_keg,
            "small_cups_per_keg": small_cups_per_keg,
            "quantity": quantity,
            "low_stock_threshold": low_stock_threshold
        }

        db["products"].insert_one(product)

        return redirect(
            url_for("products", business_id=business["_id"])
        )

    return render_template(
        "add_product.html",
        business=business
    )


# =========================
# SERVICES
# =========================

@app.route("/business/<business_id>/services")
def services(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Verify that this business belongs to the logged-in user
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Get services belonging to this business
    services = list(
        db["services"].find({
            "business_id": str(business["_id"]),
            "owner_id": session["user_id"]
        })
    )

    return render_template(
        "services.html",
        business=business,
        services=services
    )

# =========================
# VIEW SERVICE
# =========================


@app.route("/business/<business_id>/services/<service_id>")
def view_service(business_id, service_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Verify business ownership
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Find service belonging to this business and user
    service = db["services"].find_one({
        "_id": ObjectId(service_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    })

    if not service:
        return "Service not found or access denied.", 404

    return render_template(
        "view_service.html",
        business=business,
        service=service
    )

    # =========================
# EDIT SERVICE
# =========================


@app.route(
    "/business/<business_id>/services/<service_id>/edit",
    methods=["GET", "POST"]
)
def edit_service(business_id, service_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Verify business ownership
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Find service and verify ownership
    service = db["services"].find_one({
        "_id": ObjectId(service_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    })

    if not service:
        return "Service not found or access denied.", 404

    # Update service
    if request.method == "POST":

        name = request.form["name"].strip()
        category = request.form["category"].strip()
        description = request.form["description"].strip()

        cost = float(request.form["cost"])
        selling_price = float(request.form["selling_price"])

        duration = request.form["duration"].strip()
        available = request.form.get("available") == "on"

        db["services"].update_one(
            {
                "_id": ObjectId(service_id),
                "business_id": str(business["_id"]),
                "owner_id": session["user_id"]
            },
            {
                "$set": {
                    "name": name,
                    "category": category,
                    "description": description,
                    "cost": cost,
                    "selling_price": selling_price,
                    "duration": duration,
                    "available": available
                }
            }
        )

        return redirect(
            url_for(
                "view_service",
                business_id=business["_id"],
                service_id=service["_id"]
            )
        )

    return render_template(
        "edit_service.html",
        business=business,
        service=service
    )


# =========================
# DELETE SERVICE
# =========================

@app.route(
    "/business/<business_id>/services/<service_id>/delete",
    methods=["POST"]
)
def delete_service(business_id, service_id):

    # Make sure user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Verify business ownership
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Delete only if the service belongs to
    # this business AND this user
    result = db["services"].delete_one({
        "_id": ObjectId(service_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    })

    if result.deleted_count == 0:
        return "Service not found or access denied.", 404

    return redirect(
        url_for(
            "services",
            business_id=business["_id"]
        )
    )
# =========================
# ADD SERVICE
# =========================


@app.route(
    "/business/<business_id>/services/add",
    methods=["GET", "POST"]
)
def add_service(business_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Verify business ownership
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    if request.method == "POST":

        name = request.form["name"].strip()
        category = request.form["category"].strip()
        description = request.form["description"].strip()

        cost = float(request.form["cost"])
        selling_price = float(request.form["selling_price"])

        duration = request.form["duration"].strip()
        available = request.form.get("available") == "on"

        service = {
            "business_id": str(business["_id"]),
            "owner_id": session["user_id"],
            "name": name,
            "category": category,
            "description": description,
            "cost": cost,
            "selling_price": selling_price,
            "duration": duration,
            "available": available
        }

        db["services"].insert_one(service)

        return redirect(
            url_for(
                "services",
                business_id=business["_id"]
            )
        )

    return render_template(
        "add_service.html",
        business=business
    )

    # =========================
# BOOKINGS
# =========================


@app.route(
    "/business/<business_id>/bookings",
    methods=["GET", "POST"]
)
def bookings(business_id):

    # Make sure user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

     # Verify owner or assigned worker access
    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    if role not in ("owner", "worker"):
        return "Access denied.", 403

    owner_id = str(business["owner_id"])
    user_id = session["user_id"]

    # =========================
    # CREATE BOOKING
    # =========================

    if request.method == "POST":

        customer = request.form.get("customer", "").strip()
        contact = request.form.get("contact", "").strip()

        # Read all selected service IDs from the multiple-select field
        selected_service_ids = request.form.getlist("services")

        # Remove duplicates while preserving the selected order
        selected_service_ids = list(dict.fromkeys(selected_service_ids))

        booking_date = request.form.get("booking_date", "").strip()
        appointment_time = request.form.get("appointment_time", "").strip()
        duration = request.form.get("duration", "").strip()

        status = request.form.get("status", "Pending").strip()

        if not customer:
            return "Enter the customer's name.", 400

        if not selected_service_ids:
            return "Select at least one service.", 400

        # Find and validate each selected service belonging to this business
        selected_services = []
        amount = 0.0

        for service_id in selected_service_ids:

            if not ObjectId.is_valid(service_id):
                return "One of the selected services is invalid.", 400

            service_record = db["services"].find_one({
                "_id": ObjectId(service_id),
                "business_id": str(business["_id"]),
                "owner_id": owner_id,
                "available": True
            })

            if not service_record:
                return (
                    "One of the selected services was not found "
                    "or is unavailable.",
                    400
                )

            try:
                service_price = float(service_record["selling_price"])
            except (ValueError, TypeError, KeyError):
                return "A selected service has an invalid price.", 400

            if not math.isfinite(service_price) or service_price < 0:
                return "A selected service has an invalid price.", 400

            service_price = round(service_price, 2)
            amount += service_price

            selected_services.append({
                "service_id": str(service_record["_id"]),
                "name": service_record["name"],
                "price": service_price
            })

        amount = round(amount, 2)

        try:
            amount_paid = float(
                request.form.get("amount_paid", "0") or 0
            )
        except (ValueError, TypeError):
            return "Enter a valid amount paid.", 400

        if not math.isfinite(amount_paid) or amount_paid < 0:
            return "Enter a valid amount paid.", 400

        if amount_paid > amount:
            return "Amount paid cannot be greater than the booking total.", 400

        amount_paid = round(amount_paid, 2)

        # Determine payment status using the total for all selected services
        if amount_paid == 0:
            payment_status = "Unpaid"
        elif amount_paid < amount:
            payment_status = "Partial"
        else:
            payment_status = "Paid"

        payment_method = request.form.get(
            "payment_method", ""
        ).strip()

        notes = request.form.get("notes", "").strip()

        booking = {
            "owner_id": owner_id,
            "created_by": user_id,
            "created_by_role": role,
            "business_id": str(business["_id"]),

            "customer": customer,
            "contact": contact,

            # Store every selected service and its official price
            "services": selected_services,

            # Keep a combined service name for older templates
            "service": ", ".join(
                item["name"] for item in selected_services
            ),

            "booking_date": booking_date,
            "appointment_time": appointment_time,
            "duration": duration,

            "status": status,

            "payment_status": payment_status,
            "amount": amount,
            "amount_paid": amount_paid,
            "balance": round(amount - amount_paid, 2),
            "payment_method": payment_method,
            "notes": notes,

            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }

        db["bookings"].insert_one(booking)

        return redirect(
            url_for(
                "bookings",
                business_id=business["_id"]
            )
        )

    # =========================
    # GET BOOKINGS
    # =========================

    bookings = list(
        db["bookings"].find({
            "business_id": str(business["_id"]),
            "owner_id": owner_id
        }).sort("created_at", -1)

    )

    # =========================
    # BOOKING STATISTICS
    # =========================

    total_bookings = len(bookings)

    total_booking_value = sum(
        float(booking.get("amount", 0) or 0)
        for booking in bookings
    )

    total_customers = len(set(
        booking.get("customer", "").strip().lower()
        for booking in bookings
        if booking.get("customer")
    ))

    paid_payment_count = sum(
        1 for booking in bookings
        if booking.get("payment_status") == "Paid"
    )

    partial_payment_count = sum(
        1 for booking in bookings
        if booking.get("payment_status") == "Partial"
    )

    unpaid_payment_count = sum(
        1 for booking in bookings
        if booking.get("payment_status") == "Unpaid"
    )

    pending_bookings = sum(
        1 for booking in bookings
        if booking.get("status") == "Pending"
    )

    confirmed_bookings = sum(
        1 for booking in bookings
        if booking.get("status") == "Confirmed"
    )

    completed_bookings = sum(
        1 for booking in bookings
        if booking.get("status") == "Completed"
    )

    in_progress_bookings = sum(
        1 for booking in bookings
        if booking.get("status") == "In Progress"
    )

    cancelled_bookings = sum(
        1 for booking in bookings
        if booking.get("status") == "Cancelled"
    )

    no_show_bookings = sum(
        1 for booking in bookings
        if booking.get("status") == "No-show"
    )

    # =========================
    # DATE TRACKING
    # =========================

    today = datetime.now().date()

    # Monday
    week_start = today - timedelta(days=today.weekday())

    # Sunday
    week_end = week_start + timedelta(days=6)

    # Current month
    month_year = today.strftime("%Y-%m")

    today_bookings = 0
    this_week_bookings = 0
    this_month_bookings = 0

    for booking in bookings:

        booking_date_string = booking.get("booking_date")

        if not booking_date_string:
            continue

        try:

            booking_date = datetime.strptime(
                booking_date_string,
                "%Y-%m-%d"
            ).date()

        except ValueError:

            continue

        # TODAY
        if booking_date == today:
            today_bookings += 1

        # THIS WEEK
        if week_start <= booking_date <= week_end:
            this_week_bookings += 1

        # THIS MONTH
        if booking_date.strftime("%Y-%m") == month_year:
            this_month_bookings += 1

    # =========================
    # BOOKING REVENUE
    # =========================

    today_revenue = 0
    this_week_revenue = 0
    this_month_revenue = 0

    paid_bookings = 0
    pending_payment_bookings = 0
    partial_payment_bookings = 0
    total_outstanding = 0

    for booking in bookings:

        # =========================
        # PAYMENT STATUS
        # =========================

        payment_status = booking.get("payment_status")

        if payment_status == "Paid":

            paid_bookings += 1

        elif payment_status == "Unpaid":

            pending_payment_bookings += 1

        elif payment_status == "Partial":

            partial_payment_bookings += 1

            # =========================
        # BOOKING AMOUNT
        # =========================

        amount = booking.get("amount", 0) or 0

        try:

            amount = float(amount)

        except (TypeError, ValueError):

            amount = 0

        # Actual amount received
            # Actual amount received
        amount_paid = booking.get("amount_paid")

        if amount_paid is None:

            if payment_status == "Paid":
                amount_paid = amount
            else:
                amount_paid = 0

        else:

            try:
                amount_paid = float(amount_paid)

            except (TypeError, ValueError):
                amount_paid = 0

                # Outstanding balance
        balance = amount - amount_paid

        if balance > 0 and payment_status != "Refunded":
            total_outstanding += balance

        # =========================
        # BOOKING DATE
        # =========================

        booking_date_string = booking.get("booking_date")

        if not booking_date_string:
            continue

        try:

            booking_date = datetime.strptime(
                booking_date_string,
                "%Y-%m-%d"
            ).date()

        except ValueError:

            continue

        # =========================
        # REVENUE
        # =========================

        # Only PAID bookings count as revenue
        if payment_status in ("Paid", "Partial"):

            # TODAY
            if booking_date == today:
                today_revenue += amount_paid

            # THIS WEEK
            if week_start <= booking_date <= week_end:
                this_week_revenue += amount_paid

            # THIS MONTH
            if booking_date.strftime("%Y-%m") == month_year:
                this_month_revenue += amount_paid

    # =========================
    # SERVICES
    # =========================

    services = list(
        db["services"].find({
            "business_id": str(business["_id"]),
            "owner_id": owner_id
        })
    )

    # =========================
    # DISPLAY BOOKINGS PAGE
    # =========================

    return render_template(
        "bookings.html",

        business=business,
        bookings=bookings,
        services=services,

        total_bookings=total_bookings,

        pending_bookings=pending_bookings,
        confirmed_bookings=confirmed_bookings,
        completed_bookings=completed_bookings,

        in_progress_bookings=in_progress_bookings,
        cancelled_bookings=cancelled_bookings,
        no_show_bookings=no_show_bookings,

        today_bookings=today_bookings,
        this_week_bookings=this_week_bookings,
        this_month_bookings=this_month_bookings,

        today_revenue=today_revenue,
        this_week_revenue=this_week_revenue,
        this_month_revenue=this_month_revenue,

        paid_bookings=paid_bookings,
        pending_payment_bookings=pending_payment_bookings,
        partial_payment_bookings=partial_payment_bookings,
        paid_payment_count=paid_payment_count,
        partial_payment_count=partial_payment_count,
        unpaid_payment_count=unpaid_payment_count,
        total_outstanding=total_outstanding,

        total_booking_value=total_booking_value,
        total_customers=total_customers
    )


# =========================
# NEW BOOKING
# =========================
    # =========================
# NEW BOOKING
# =========================


@app.route(
    "/business/<business_id>/bookings/new",
    methods=["GET"]
)
def new_booking(business_id):

    # Make sure user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Allow the owner or an assigned worker to access the business
    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    if role not in ("owner", "worker"):
        return "Access denied.", 403

    # Get services created for this business by its owner
    services = list(
        db["services"].find({
            "business_id": str(business["_id"]),
            "owner_id": str(business["owner_id"])
        })
    )

    return render_template(
        "new_booking.html",
        business=business,
        services=services
    )


# =========================
# LOGOUT
# =========================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


@app.route(
    "/business/<business_id>/bookings/<booking_id>/complete",
    methods=["POST"]
)
def complete_booking(business_id, booking_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    business = db["businesses"].find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    booking = db["bookings"].find_one({
        "_id": ObjectId(booking_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    })

    if not booking:
        return "Booking not found.", 404

    db["bookings"].update_one(
        {
            "_id": ObjectId(booking_id),
            "business_id": str(business["_id"]),
            "owner_id": session["user_id"]
        },
        {
            "$set": {
                "status": "Completed",
                "updated_at": datetime.now(timezone.utc)
            }
        }
    )

    return redirect(
        url_for(
            "bookings",
            business_id=business["_id"]
        )
    )


# =========================
# EXPENSES MANAGEMENT
# =========================

@app.route("/business/<business_id>/expenses")
def expenses(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(business_id):
        return "Invalid business.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    expense_collection = db["expenses"]

    # Optional filters
    category = request.args.get("category", "").strip()
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    query = {
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    }

    if category:
        query["category"] = category

    if start_date or end_date:
        date_filter = {}

        if start_date:
            try:
                datetime.strptime(start_date, "%Y-%m-%d")
                date_filter["$gte"] = start_date
            except ValueError:
                return "Invalid start date.", 400

        if end_date:
            try:
                datetime.strptime(end_date, "%Y-%m-%d")
                date_filter["$lte"] = end_date
            except ValueError:
                return "Invalid end date.", 400

        if start_date and end_date and start_date > end_date:
            return "Start date cannot be after end date.", 400

        query["expense_date"] = date_filter

    expense_records = list(
        expense_collection.find(query).sort([
            ("expense_date", -1),
            ("created_at", -1)
        ])
    )

    total_expenses = sum(
        float(item.get("amount", 0) or 0)
        for item in expense_records
    )

    categories = expense_collection.distinct(
        "category",
        {
            "business_id": str(business["_id"]),
            "owner_id": session["user_id"]
        }
    )

    return render_template(
        "expenses.html",
        business=business,
        expenses=expense_records,
        total_expenses=round(total_expenses, 2),
        categories=sorted(c for c in categories if c),
        selected_category=category,
        start_date=start_date,
        end_date=end_date
    )


@app.route(
    "/business/<business_id>/expenses/add",
    methods=["GET", "POST"]
)
def add_expense(business_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(business_id):
        return "Invalid business.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()
        description = request.form.get("description", "").strip()
        payment_method = request.form.get(
            "payment_method", ""
        ).strip()
        expense_date = request.form.get(
            "expense_date", ""
        ).strip()
        amount_text = request.form.get("amount", "").strip()

        if not name or not category or not expense_date or not amount_text:
            return "Please complete all required fields.", 400

        try:
            amount = float(amount_text)
            datetime.strptime(expense_date, "%Y-%m-%d")
        except ValueError:
            return "Enter a valid amount and date.", 400

        if not math.isfinite(amount) or amount <= 0:
            return "Expense amount must be greater than zero.", 400

        expense = {
            "business_id": str(business["_id"]),
            "owner_id": session["user_id"],
            "name": name,
            "category": category,
            "description": description,
            "amount": round(amount, 2),
            "payment_method": payment_method,
            "expense_date": expense_date,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }

        db["expenses"].insert_one(expense)

        return redirect(url_for(
            "expenses",
            business_id=business["_id"]
        ))

    return render_template(
        "add_expense.html",
        business=business
    )


@app.route(
    "/business/<business_id>/expenses/<expense_id>/edit",
    methods=["GET", "POST"]
)
def edit_expense(business_id, expense_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(business_id) or not ObjectId.is_valid(expense_id):
        return "Invalid business or expense.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    expense_filter = {
        "_id": ObjectId(expense_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    }

    expense = db["expenses"].find_one(expense_filter)

    if not expense:
        return "Expense not found or access denied.", 404

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()
        description = request.form.get("description", "").strip()
        payment_method = request.form.get(
            "payment_method", ""
        ).strip()
        expense_date = request.form.get(
            "expense_date", ""
        ).strip()
        amount_text = request.form.get("amount", "").strip()

        if not name or not category or not expense_date or not amount_text:
            return "Please complete all required fields.", 400

        try:
            amount = float(amount_text)
            datetime.strptime(expense_date, "%Y-%m-%d")
        except ValueError:
            return "Enter a valid amount and date.", 400

        if not math.isfinite(amount) or amount <= 0:
            return "Expense amount must be greater than zero.", 400

        db["expenses"].update_one(
            expense_filter,
            {
                "$set": {
                    "name": name,
                    "category": category,
                    "description": description,
                    "amount": round(amount, 2),
                    "payment_method": payment_method,
                    "expense_date": expense_date,
                    "updated_at": datetime.now(timezone.utc)
                }
            }
        )

        return redirect(url_for(
            "expenses",
            business_id=business["_id"]
        ))

    return render_template(
        "edit_expense.html",
        business=business,
        expense=expense
    )


@app.route(
    "/business/<business_id>/expenses/<expense_id>/delete",
    methods=["POST"]
)
def delete_expense(business_id, expense_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(business_id) or not ObjectId.is_valid(expense_id):
        return "Invalid business or expense.", 400

    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    result = db["expenses"].delete_one({
        "_id": ObjectId(expense_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    })

    if result.deleted_count == 0:
        return "Expense not found or access denied.", 404

    return redirect(url_for(
        "expenses",
        business_id=business["_id"]
    ))


@app.route(
    "/business/<business_id>/bookings/<booking_id>",
    methods=["GET"]
)
def view_booking(business_id, booking_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Allow the owner or an assigned worker
    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    owner_id = str(business["owner_id"])

    try:
        booking_object_id = ObjectId(booking_id)
    except Exception:
        return "Booking not found.", 404

    # Only retrieve bookings belonging to this business
    booking = db["bookings"].find_one({
        "_id": booking_object_id,
        "business_id": str(business["_id"]),
        "owner_id": owner_id
    })

    if not booking:
        return "Booking not found.", 404

    return render_template(
        "view_booking.html",
        business=business,
        booking=booking,
        role=role
    )


@app.route(
    "/business/<business_id>/bookings/<booking_id>/edit",
    methods=["GET", "POST"]
)
def edit_booking(business_id, booking_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Allow the owner or an assigned worker
    business, role = get_business_access(business_id)

    if not business:
        return "Business not found or access denied.", 404

    owner_id = str(business["owner_id"])

    try:
        booking_object_id = ObjectId(booking_id)
    except Exception:
        return "Booking not found.", 404

    # Find the booking belonging to this business
    booking = db["bookings"].find_one({
        "_id": booking_object_id,
        "business_id": str(business["_id"]),
        "owner_id": owner_id
    })

    if not booking:
        return "Booking not found or access denied.", 404

    if request.method == "POST":

        customer = request.form.get("customer", "").strip()
        contact = request.form.get("contact", "").strip()

        # Read multiple selected services
        selected_service_ids = list(dict.fromkeys(
            request.form.getlist("services")
        ))

        booking_date = request.form.get("booking_date", "").strip()
        appointment_time = request.form.get("appointment_time", "").strip()
        duration = request.form.get("duration", "").strip()
        status = request.form.get("status", "").strip()

        payment_method = request.form.get(
            "payment_method", ""
        ).strip()
        notes = request.form.get("notes", "").strip()

        try:
            datetime.strptime(booking_date, "%Y-%m-%d")
            datetime.strptime(appointment_time, "%H:%M")
        except ValueError:
            return "Enter a valid booking date and appointment time.", 400

        if not all([
            customer, contact, booking_date,
            appointment_time, duration, status
        ]):
            return "Please complete all required booking fields.", 400

        if not selected_service_ids:
            return "Select at least one service.", 400

        # Validate services and calculate their official total
        selected_services = []
        amount = 0.0

        for service_id in selected_service_ids:

            if not ObjectId.is_valid(service_id):
                return "One of the selected services is invalid.", 400

            service_record = db["services"].find_one({
                "_id": ObjectId(service_id),
                "business_id": str(business["_id"]),
                "owner_id": owner_id,
                "available": True
            })

            if not service_record:
                return (
                    "A selected service was not found or is unavailable.",
                    400
                )

            try:
                service_price = float(service_record["selling_price"])
            except (ValueError, TypeError, KeyError):
                return "A selected service has an invalid price.", 400

            if not math.isfinite(service_price) or service_price < 0:
                return "A selected service has an invalid price.", 400

            service_price = round(service_price, 2)
            amount += service_price

            selected_services.append({
                "service_id": str(service_record["_id"]),
                "name": service_record["name"],
                "price": service_price
            })

        amount = round(amount, 2)

        try:
            amount_paid = float(
                request.form.get("amount_paid", "0") or 0
            )
        except (ValueError, TypeError):
            return "Enter a valid amount paid.", 400

        if not math.isfinite(amount_paid) or amount_paid < 0:
            return "Amount paid must be a valid non-negative number.", 400

        if amount_paid > amount:
            return "Amount paid cannot exceed the booking total.", 400

        amount_paid = round(amount_paid, 2)

        if amount_paid == 0:
            payment_status = "Unpaid"
        elif amount_paid < amount:
            payment_status = "Partial"
        else:
            payment_status = "Paid"

        db["bookings"].update_one(
            {
                "_id": booking_object_id,
                "business_id": str(business["_id"]),
                "owner_id": owner_id
            },
            {
                "$set": {
                    "customer": customer,
                    "contact": contact,
                    "services": selected_services,
                    "service": ", ".join(
                        item["name"] for item in selected_services
                    ),
                    "booking_date": booking_date,
                    "appointment_time": appointment_time,
                    "duration": duration,
                    "status": status,
                    "payment_status": payment_status,
                    "amount": amount,
                    "amount_paid": amount_paid,
                    "balance": round(amount - amount_paid, 2),
                    "payment_method": payment_method,
                    "notes": notes,
                    "updated_at": datetime.now(timezone.utc)
                }
            }
        )

        return redirect(
            url_for(
                "bookings",
                business_id=business["_id"]
            )
        )

    # Load services belonging to the business owner
    services = list(db["services"].find({
        "business_id": str(business["_id"]),
        "owner_id": owner_id,
        "available": True
    }))

    return render_template(
        "edit_booking.html",
        business=business,
        booking=booking,
        services=services,
        role=role
    )


# =========================
# RESTOCK PRODUCT
# =========================

@app.route(
    "/business/<business_id>/products/<product_id>/restock",
    methods=["GET", "POST"]
)
def restock_product(business_id, product_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if not ObjectId.is_valid(business_id) or not ObjectId.is_valid(product_id):
        return "Invalid business or product ID.", 400

    # Verify business ownership.
    business = businesses_collection.find_one({
        "_id": ObjectId(business_id),
        "owner_id": session["user_id"]
    })

    if not business:
        return "Business not found or access denied.", 404

    # Verify product belongs to this business and owner.
    product_query = {
        "_id": ObjectId(product_id),
        "business_id": str(business["_id"]),
        "owner_id": session["user_id"]
    }

    product = db["products"].find_one(product_query)

    if not product:
        return "Product not found or access denied.", 404

    error = None

    if request.method == "POST":
        try:
            quantity_to_add = float(request.form.get("quantity", ""))
            unit_cost = float(request.form.get("buying_price", ""))
            supplier = request.form.get("supplier", "").strip()
            purchase_date = request.form.get("purchase_date", "").strip()

            if (
                not math.isfinite(quantity_to_add)
                or quantity_to_add <= 0
            ):
                raise ValueError("Enter a valid quantity greater than zero.")

            if not math.isfinite(unit_cost) or unit_cost < 0:
                raise ValueError("Enter a valid buying price.")

            # Whole-item products cannot be restocked fractionally.
            unit = str(product.get("measurement_type", "Piece")
                       ).strip().lower()
            whole_units = {"piece", "pieces", "item", "items"}

            if unit in whole_units and not quantity_to_add.is_integer():
                raise ValueError(
                    "This product must be restocked in whole units.")

            if not purchase_date:
                purchase_date = datetime.now(
                    timezone.utc
                ).date().isoformat()
            else:
                datetime.strptime(purchase_date, "%Y-%m-%d")

            quantity_to_add = round(quantity_to_add, 6)
            unit_cost = round(unit_cost, 2)
            total_cost = round(quantity_to_add * unit_cost, 2)

            # Use a transaction so the quantity update and history
            # record are saved together.
            with client.start_session() as mongo_session:
                with mongo_session.start_transaction():

                    current_product = db["products"].find_one(
                        product_query,
                        session=mongo_session
                    )

                    if not current_product:
                        raise ValueError("Product not found.")

                    previous_quantity = float(
                        current_product.get("quantity", 0) or 0
                    )

                    new_quantity = round(
                        previous_quantity + quantity_to_add, 6
                    )

                    result = db["products"].update_one(
                        product_query,
                        {
                            "$inc": {"quantity": quantity_to_add},
                            "$set": {
                                "buying_price": unit_cost,
                                "updated_at": datetime.now(timezone.utc)
                            }
                        },
                        session=mongo_session
                    )

                    if result.modified_count != 1:
                        raise ValueError(
                            "The stock could not be updated. Please try again."
                        )

                    db["stock_movements"].insert_one(
                        {
                            "business_id": str(business["_id"]),
                            "owner_id": session["user_id"],
                            "product_id": str(product["_id"]),
                            "product_name": product["name"],
                            "movement_type": "Restock",
                            "previous_quantity": previous_quantity,
                            "quantity_added": quantity_to_add,
                            "new_quantity": new_quantity,
                            "unit_cost": unit_cost,
                            "total_cost": total_cost,
                            "supplier": supplier,
                            "purchase_date": purchase_date,
                            "recorded_at": datetime.now(timezone.utc)
                        },
                        session=mongo_session
                    )

            return redirect(
                url_for(
                    "view_product",
                    business_id=business["_id"],
                    product_id=product["_id"]
                )
            )

        except (ValueError, TypeError) as exc:
            error = str(exc) or "Please enter valid restocking details."

        except PyMongoError:
            app.logger.exception("Product restocking failed.")
            error = (
                "Restocking could not be completed. "
                "Please check your database connection and try again."
            )

    # Refresh the displayed product information.
    product = db["products"].find_one(product_query)

    return render_template(
        "restock_product.html",
        business=business,
        product=product,
        error=error
    )


# =========================
# RUN APPLICATION
# =========================
if __name__ == "__main__":
    app.run(debug=True)
