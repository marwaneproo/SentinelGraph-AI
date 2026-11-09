from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List
from fastapi import APIRouter, Depends

from backend.app.db.mongodb import mongo_manager
from backend.app.services.alert_service import alert_service
from backend.app.core.rbac import require_any_authenticated

router = APIRouter(prefix="/analytics", tags=["SIEM Analytics & Dashboard"])

@router.get("/dashboard")
async def get_dashboard_analytics(user_payload: dict = Depends(require_any_authenticated)):
    """Computes comprehensive SIEM metrics, KPI counters, and trend distributions."""
    logs_col = mongo_manager.get_collection("logs")
    alerts_col = mongo_manager.get_collection("alerts")
    servers_col = mongo_manager.get_collection("servers")

    total_logs = await logs_col.count_documents({})
    alert_stats = await alert_service.get_alert_stats()
    server_count = await servers_col.count_documents({})

    # Fetch recent 500 logs to compute distributions
    recent_logs = await logs_col.find({}).sort("timestamp", -1).limit(500).to_list(500)

    # Top suspicious IPs
    ip_counts: Dict[str, int] = {}
    user_counts: Dict[str, int] = {}
    server_counts: Dict[str, int] = {}
    event_counts: Dict[str, int] = {}
    timeline_map: Dict[str, int] = {}

    for l in recent_logs:
        ip = l.get("source_ip")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        u = l.get("username")
        if u:
            user_counts[u] = user_counts.get(u, 0) + 1

        srv = l.get("server_id") or l.get("server_name")
        if srv:
            server_counts[srv] = server_counts.get(srv, 0) + 1

        ev = l.get("event_type", "OTHER")
        event_counts[ev] = event_counts.get(ev, 0) + 1

        # Format timestamp for hourly/interval trend
        ts_str = str(l.get("timestamp", ""))
        bucket = ts_str[:13] if len(ts_str) >= 13 else "Recent"
        timeline_map[bucket] = timeline_map.get(bucket, 0) + 1

    top_ips = sorted([{"ip": k, "count": v} for k, v in ip_counts.items()], key=lambda x: x["count"], reverse=True)[:5]
    top_users = sorted([{"user": k, "count": v} for k, v in user_counts.items()], key=lambda x: x["count"], reverse=True)[:5]
    top_servers = sorted([{"server": k, "count": v} for k, v in server_counts.items()], key=lambda x: x["count"], reverse=True)[:5]
    event_distribution = [{"type": k, "count": v} for k, v in event_counts.items()]
    timeline = sorted([{"time": k, "events": v} for k, v in timeline_map.items()], key=lambda x: x["time"])

    # Recent alerts
    recent_alerts_cursor = alerts_col.find({}).sort("timestamp", -1).limit(5)
    recent_alerts = await recent_alerts_cursor.to_list(5)
    for a in recent_alerts:
        if "_id" in a:
            a["_id"] = str(a["_id"])

    return {
        "kpis": {
            "total_logs": total_logs,
            "total_alerts": alert_stats["total_alerts"],
            "critical_high_alerts": alert_stats["critical_or_high"],
            "active_servers": server_count,
            "by_severity": alert_stats["by_severity"],
            "by_status": alert_stats["by_status"]
        },
        "top_ips": top_ips,
        "top_users": top_users,
        "top_servers": top_servers,
        "event_distribution": event_distribution,
        "timeline": timeline,
        "recent_alerts": recent_alerts
    }
