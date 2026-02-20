import json
from pathlib import Path

TICKETS_FILE = Path("state/servicenow_tickets.json")

# storing key -> value relationship (alert to INCxxxxxx)
def load_ticket_map():
    # ticket file doesn't exist return an empty dictionary
    if not TICKETS_FILE.exists():
        return {}
    try:
        # read_text() to read the entire file contents as a string
        # json.loads() parses the string into a dict
        return json.loads(TICKETS_FILE.read_text())
    except Exception:
        return {}

def save_ticket_map(ticket_map: dict):
    # creates state/ folder if missing
    TICKETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    # convert dict -> JSON string and write the contents to the .json
    TICKETS_FILE.write_text(json.dumps(ticket_map, indent=2))
