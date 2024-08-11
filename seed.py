#!/usr/bin/env python3

from datetime import datetime, timezone
from faker import Faker
from app import app, db 
from models import User, Redflags, Intervention
import random

fake = Faker()

def generate_random_geolocation():
    """Generate a random geolocation (latitude, longitude)."""
    latitude = round(random.uniform(-90, 90), 6)
    longitude = round(random.uniform(-180, 180), 6)
    return f"{latitude}, {longitude}"

def seed_data():
    # Create some users
    print("Creating Users...")
    user1 = User(
        name="John Doe",
        email="john@example.com",
        role="user",
        token_verified= True
    )
    user1.password_hash = "password123" 

    user2 = User(
        name="Jane Smith",
        email="jane@example.com",
        role="admin",
        token_verified= True
    )
    user2.password_hash = "password123" 
    user3 = User(
        name="Perry Jackson",
        email="perry@example.com",
        role="admin",
        token_verified=True
    )
    user3.password_hash = "password123"  

    user4 = User(
        name="Victor Adams",
        email="victor@example.com",
        role="user",
        token_verified=True
    )
    user4.password_hash = "password123" 

    print("Users Created")

    print("Creating Redflags...")
    # Create some redflags
    for _ in range(15):
        redflag = Redflags(
            redflag=fake.sentence(),
            description=fake.text(max_nb_chars=100),
            geolocation=generate_random_geolocation(),
            image="", 
            video="",  
            user=random.choice([user1,user4])
        )
        db.session.add(redflag)

    print("Redflags Created")

    print("Creating Interventions...")
    # Create some interventions
    for _ in range(15):
        intervention = Intervention(
            intervention=fake.sentence(),
            description=fake.text(max_nb_chars=100),
            geolocation=generate_random_geolocation(),
            image="",  
            video="",  
            user=random.choice([user1,user4])
        )
        db.session.add(intervention)

    print("Interventions Created")
    db.session.add(user1)
    db.session.add(user2)
    db.session.add(user3)
    db.session.add(user4)
    # Commit the session to the database
    db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        # Drop all tables and recreate them (optional)
        db.drop_all()
        print("Tables Deleted")
        db.create_all()
        print("Tables Created")
        
        # Seed the database with initial data
        seed_data()
        print("Database seeded!")