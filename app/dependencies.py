"""
Shared dependencies for the application.
"""
# Global templates instance - this will be set by main.py
templates = None

def get_templates():
    """Get the global templates instance."""
    return templates

def set_templates(template_instance):
    """Set the global templates instance."""
    global templates
    templates = template_instance
