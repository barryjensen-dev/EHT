from app import db
from datetime import datetime

class Category(db.Model):
    """Model representing a script category."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    icon = db.Column(db.String(50), nullable=True)
    scripts = db.relationship('Script', backref='category', lazy=True)
    
    def __init__(self, **kwargs):
        super(Category, self).__init__(**kwargs)
    
    def __repr__(self):
        return f"<Category {self.name}>"

class Script(db.Model):
    """Model representing a script in the toolkit."""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    module_path = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    
    def __init__(self, **kwargs):
        super(Script, self).__init__(**kwargs)
    
    def __repr__(self):
        return f"<Script {self.title}>"
