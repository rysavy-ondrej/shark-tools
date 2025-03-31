import pandas as pd
import json
import sys

def json_to_csv():
    """
    Reads NDJSON (Newline Delimited JSON) data from stdin, normalizes it using pandas.json_normalize(),
    and writes the output to stdout in CSV format.

    Returns:
    --------
    None
    """
    try:
        # Read NDJSON from stdin line by line
        data = [json.loads(line) for line in sys.stdin]
        
        # Normalize JSON data
        df = pd.json_normalize(data)
        
        # Write to stdout in CSV format
        df.to_csv(sys.stdout.buffer, index=False)
        
    except Exception as e:
        print(f"Error processing data: {e}", file=sys.stderr)

if __name__ == "__main__":
    json_to_csv()
