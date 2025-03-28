import sqlite3
import pandas as pd
from datetime import datetime, timedelta

# Database path (same as capture.py)
DB_PATH = "data/logs.db"

def fetch_logs(time_window_hours=None):
    """Fetch logs from the database, optionally within a time window."""
    try:
        conn = sqlite3.connect(DB_PATH)
        query = "SELECT timestamp, event_type, details FROM logs"
        
        if time_window_hours:
            cutoff = (datetime.now() - timedelta(hours=time_window_hours)).strftime("%Y-%m-%d %H:%M:%S")
            query += f" WHERE timestamp >= '{cutoff}'"
        
        df = pd.read_sql_query(query, conn, parse_dates=["timestamp"])
        conn.close()
        return df
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return pd.DataFrame()

def detect_anomalies(df):
    """Analyze logs for potential security threats."""
    alerts = []
    
    # Rule 1: Too many process starts in a short time (e.g., 5 in 1 minute)
    process_df = df[df["event_type"] == "Process Started"]
    if not process_df.empty:
        process_df["timestamp"] = pd.to_datetime(process_df["timestamp"])
        time_window = pd.Timedelta(minutes=1)
        process_counts = process_df.groupby(pd.Grouper(key="timestamp", freq="1min")).size()
        suspicious = process_counts[process_counts >= 5]
        for timestamp, count in suspicious.items():
            alerts.append({
                "timestamp": timestamp,
                "type": "High Process Activity",
                "details": f"{count} processes started within 1 minute"
            })

    # Rule 2: Critical file modifications (e.g., in monitored directory)
    file_df = df[df["event_type"].isin(["File Modified", "File Created", "File Deleted"])]
    critical_files = [".exe", ".dll", ".sys"]  # Example critical extensions
    for _, row in file_df.iterrows():
        if any(ext in row["details"] for ext in critical_files):
            alerts.append({
                "timestamp": row["timestamp"],
                "type": "Critical File Change",
                "details": f"Suspicious file activity: {row['details']}"
            })

    return alerts

def summarize_logs(df):
    """Generate basic statistics from logs."""
    summary = {
        "total_events": len(df),
        "event_types": df["event_type"].value_counts().to_dict(),
        "recent_events": df.tail(5).to_dict(orient="records")  # Last 5 events
    }
    return summary

def analyze_logs(time_window_hours=1):
    """Main analysis function."""
    # Fetch logs from the last hour (or specified time window)
    df = fetch_logs(time_window_hours)
    if df.empty:
        print("No logs to analyze.")
        return {"alerts": [], "summary": {}}

    # Detect anomalies
    alerts = detect_anomalies(df)
    
    # Summarize logs
    summary = summarize_logs(df)
    
    # Print results (for now; later this can feed into UI)
    print("\n=== Analysis Report ===")
    print(f"Time Window: Last {time_window_hours} hour(s)")
    print("Summary:", summary)
    if alerts:
        print("Alerts:")
        for alert in alerts:
            print(f"- {alert['timestamp']}: {alert['type']} - {alert['details']}")
    else:
        print("No alerts detected.")
    
    return {"alerts": alerts, "summary": summary}

if __name__ == "__main__":
    # Run analysis on the last hour of logs
    result = analyze_logs(time_window_hours=1)