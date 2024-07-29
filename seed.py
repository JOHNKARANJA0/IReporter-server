#!/usr/bin/env python3

from datetime import datetime, timezone
from app import app, db  # Make sure these are imported from your Flask application
from models import User, Redflags, Intervention

def seed_data():
    # Create some users
    print("Creating Users...")
    user1 = User(
        name="John Doe",
        email="john@example.com",
        role="user"
    )
    user1.password_hash = "password123"  # This will automatically hash the password

    user2 = User(
        name="Jane Smith",
        email="jane@example.com",
        role="admin"
    )
    user2.password_hash = "securepassword"  # This will automatically hash the password

    print("Users Created")
    print("Creating Redflags...")
    # Create some redflags
    redflag1 = Redflags(
        redflag="Broken bridge",
        description="A bridge is broken on the main road.",
        geolocation="34.052235, -118.243683",
        image="",
        video="",
        date_added=datetime.now(tz=timezone.utc),
        status="",
        user=user1
    )

    redflag2 = Redflags(
        redflag="Flooded street",
        description="The main street is flooded.",
        geolocation="40.712776, -74.005974",
        image="",
        video="",
        date_added=datetime.now(tz=timezone.utc),
        status="",
        user=user2
    )
    print("Redflags Created")
    print("Creating Intervention...")
    # Create some interventions
    intervention1 = Intervention(
        intervention="Clean park",
        description="Clean up the local park.",
        geolocation="51.507351, -0.127758",
        image="",
        video="",
        date_added=datetime.now(tz=timezone.utc),
        status="",
        user=user1
    )

    intervention2 = Intervention(
        intervention="Repair road",
        description="Repair the potholes on 5th Avenue.",
        geolocation="37.774929, -122.419416",
        image="",
        video="",
        date_added=datetime.now(tz=timezone.utc),
        status="",
        user=user2
    )
    print("Intervention Created")

    # Add users to the session
    db.session.add(user1)
    db.session.add(user2)

    # Add redflags and interventions to the session
    db.session.add(redflag1)
    db.session.add(redflag2)
    db.session.add(intervention1)
    db.session.add(intervention2)

    # Commit the session to the database
    db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        # Drop all tables and recreate them (optional)
        db.drop_all()
        db.create_all()
        
        # Seed the database with initial data
        seed_data()
        print("Database seeded!")