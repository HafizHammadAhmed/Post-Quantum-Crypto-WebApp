from app import create_app

app = create_app()

# Change your run.py to use HTTP instead of HTTPS
if __name__ == "__main__":
    app.run(debug=True)  
