"""Development entry point: python app.py"""
from compliance_scanner.routes import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
