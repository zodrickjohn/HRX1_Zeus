
#!/usr/bin/env python3
import subprocess
import sys
import os

def install_requirements():
    """Install Python requirements"""
    print("Installing Python dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def setup_database():
    """Initialize the database"""
    print("Setting up database...")
    from app import app, db
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

def main():
    print("=== Flask Backend Setup ===")
    
    # Install requirements
    install_requirements()
    
    # Setup database
    setup_database()
    
    print("\n✅ Setup complete!")
    print("\nTo start the Flask server, run:")
    print("cd flask-backend && python app.py")
    print("\nThe server will be available at: http://localhost:5000")

if __name__ == "__main__":
    main()
