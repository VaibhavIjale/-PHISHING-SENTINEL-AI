from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    result = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status_class = db.Column(db.String(20))

    def __repr__(self):
        return f'<Scan {self.url} - {self.result}>'

def init_db(app):
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_scans.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    with app.app_context():
        db.create_all()
