"""
dashboard/attack_map.py

Purpose: Build geographic attack-origin data structures and Plotly choropleth /
         scatter-geo figures for the SENTINEL IPS v2.0 world attack map panel.
         Aggregates GeoResult records from the Geolocator into per-country and
         per-IP attack tallies, then renders a Plotly scatter-geo bubble map
         and a choropleth heatmap that Streamlit can display via st.plotly_chart.

Inputs:  List of geo-annotated event dicts (must contain lat, lon, country_code,
         attack_type, severity fields).
Outputs: plotly.graph_objects.Figure objects ready for st.plotly_chart().

Usage:
    from dashboard.attack_map import AttackMap
    amap   = AttackMap()
    amap.ingest(event_with_geo)
    fig_scatter = amap.scatter_geo_figure(title="Live Attack Origins")
    fig_choro   = amap.choropleth_figure()
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)

# Attack type -> display colour
_ATTACK_COLOURS: dict[str, str] = {
    "DDoS":         "#E53935",
    "DoS":          "#FB8C00",
    "PortScan":     "#FDD835",
    "BruteForce":   "#AB47BC",
    "Bot":          "#EF5350",
    "Infiltration": "#B71C1C",
    "Heartbleed":   "#880E4F",
    "SQLInjection": "#1E88E5",
    "XSS":          "#00ACC1",
    "ZeroDay":      "#6D4C41",
    "APT":          "#37474F",
    "Unknown":      "#78909C",
}

_SEVERITY_SIZES: dict[str, int] = {
    "CRITICAL": 18,
    "HIGH":     14,
    "MEDIUM":   10,
    "LOW":       7,
    "INFO":      5,
}


@dataclass
class GeoHit:
    lat:         float
    lon:         float
    country:     str
    country_code: str
    city:        str
    src_ip:      str
    attack_type: str
    severity:    str
    count:       int = 1


class AttackMap:
    """
    Geographic aggregation and Plotly figure builder for the world attack map.

    ingest(event)         -- add one geo-annotated detection event
    scatter_geo_figure()  -- Plotly scatter-geo bubble map (one dot per unique IP)
    choropleth_figure()   -- Plotly choropleth heatmap (attack count per country)
    top_countries(n)      -- list of (country, count) tuples descending
    clear()               -- reset all aggregated data

    Thread-safe via internal Lock.
    """

    def __init__(self) -> None:
        self._lock           = Lock()
        self._ip_hits:       dict[str, GeoHit]      = {}
        self._country_counts: dict[str, int]         = defaultdict(int)
        self._country_codes:  dict[str, str]         = {}   # country_name -> iso-alpha3
        logger.info("AttackMap initialised")

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(self, event: dict) -> None:
        """
        Record one geo-annotated detection event.

        Expected keys: lat, lon, country, country_code (ISO-3166-1 alpha-3),
        city, src_ip, attack_type, severity.  Missing keys get safe defaults.
        """
        lat   = float(event.get("lat",  0.0))
        lon   = float(event.get("lon",  0.0))
        cname = str(event.get("country",      "Unknown"))
        ccode = str(event.get("country_code", ""))
        city  = str(event.get("city",         ""))
        ip    = str(event.get("src_ip",       "0.0.0.0"))
        atype = str(event.get("attack_type",  "Unknown"))
        sev   = str(event.get("severity",     "INFO"))

        with self._lock:
            if ip in self._ip_hits:
                self._ip_hits[ip].count += 1
                # Upgrade severity if worse
                existing = self._ip_hits[ip]
                sev_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                if sev_order.index(sev) > sev_order.index(existing.severity):
                    existing.severity = sev
            else:
                self._ip_hits[ip] = GeoHit(
                    lat=lat, lon=lon,
                    country=cname, country_code=ccode, city=city,
                    src_ip=ip, attack_type=atype, severity=sev,
                )
            self._country_counts[cname] += 1
            if ccode:
                self._country_codes[cname] = ccode

    def ingest_batch(self, events: list[dict]) -> None:
        """Ingest a list of geo-annotated events."""
        for ev in events:
            self.ingest(ev)

    # ------------------------------------------------------------------
    # Plotly figures
    # ------------------------------------------------------------------

    def scatter_geo_figure(
        self,
        title:    str = "SENTINEL IPS — Live Attack Origins",
        max_dots: int = 500,
    ):
        """
        Build a Plotly scatter-geo bubble map.

        Each unique source IP is one bubble; size encodes severity,
        colour encodes attack type.

        Inputs:  title, max_dots — cap on plotted points for performance
        Outputs: plotly.graph_objects.Figure (or None if plotly unavailable)
        """
        try:
            import plotly.graph_objects as go
        except ImportError:
            logger.warning("plotly not installed — attack map unavailable")
            return None

        with self._lock:
            hits = list(self._ip_hits.values())

        # Sort by count desc, take top max_dots
        hits.sort(key=lambda h: h.count, reverse=True)
        hits = hits[:max_dots]

        if not hits:
            # Return empty figure with message
            fig = go.Figure()
            fig.update_layout(
                title=title,
                geo=dict(showframe=False, showcoastlines=True,
                         projection_type="natural earth",
                         bgcolor="#0D1117"),
                paper_bgcolor="#0D1117",
                font_color="#E0E0E0",
                height=480,
            )
            return fig

        lats   = [h.lat          for h in hits]
        lons   = [h.lon          for h in hits]
        sizes  = [_SEVERITY_SIZES.get(h.severity, 7) * max(1, min(h.count, 10)) ** 0.4
                  for h in hits]
        colours = [_ATTACK_COLOURS.get(h.attack_type, "#78909C") for h in hits]
        texts  = [
            f"IP: {h.src_ip}<br>"
            f"Country: {h.country} ({h.city})<br>"
            f"Attack: {h.attack_type}<br>"
            f"Severity: {h.severity}<br>"
            f"Hits: {h.count}"
            for h in hits
        ]

        fig = go.Figure(go.Scattergeo(
            lat=lats,
            lon=lons,
            mode="markers",
            marker=dict(
                size=sizes,
                color=colours,
                opacity=0.80,
                line=dict(width=0.5, color="#FFFFFF"),
            ),
            text=texts,
            hoverinfo="text",
        ))

        fig.update_layout(
            title=dict(text=title, font=dict(size=16, color="#E0E0E0")),
            geo=dict(
                showframe=False,
                showcoastlines=True,
                showland=True,
                landcolor="#1C2833",
                showocean=True,
                oceancolor="#0D1117",
                showlakes=False,
                showcountries=True,
                countrycolor="#37474F",
                projection_type="natural earth",
                bgcolor="#0D1117",
            ),
            paper_bgcolor="#0D1117",
            plot_bgcolor="#0D1117",
            font=dict(color="#E0E0E0"),
            margin=dict(l=0, r=0, t=40, b=0),
            height=480,
        )

        return fig

    def choropleth_figure(
        self,
        title: str = "Attack Volume by Country",
    ):
        """
        Build a Plotly choropleth heatmap shaded by attack count per country.

        Inputs:  title
        Outputs: plotly.graph_objects.Figure or None
        """
        try:
            import plotly.graph_objects as go
        except ImportError:
            return None

        with self._lock:
            counts = dict(self._country_counts)
            codes  = dict(self._country_codes)

        if not counts:
            fig = go.Figure()
            fig.update_layout(title=title, height=420,
                              paper_bgcolor="#0D1117", font_color="#E0E0E0")
            return fig

        countries = list(counts.keys())
        values    = [counts[c] for c in countries]
        iso3      = [codes.get(c, "") for c in countries]

        fig = go.Figure(go.Choropleth(
            locations=iso3,
            z=values,
            text=countries,
            colorscale="Reds",
            autocolorscale=False,
            reversescale=False,
            marker_line_color="#37474F",
            marker_line_width=0.5,
            colorbar=dict(
                title=dict(text="Attacks", font=dict(color="#E0E0E0")),
                tickfont=dict(color="#E0E0E0"),
            ),
            hovertemplate="%{text}<br>Attacks: %{z}<extra></extra>",
        ))

        fig.update_layout(
            title=dict(text=title, font=dict(size=16, color="#E0E0E0")),
            geo=dict(
                showframe=False,
                showcoastlines=True,
                showland=True,
                landcolor="#1C2833",
                showocean=True,
                oceancolor="#0D1117",
                showcountries=True,
                countrycolor="#37474F",
                projection_type="natural earth",
                bgcolor="#0D1117",
            ),
            paper_bgcolor="#0D1117",
            font=dict(color="#E0E0E0"),
            margin=dict(l=0, r=0, t=40, b=0),
            height=420,
        )

        return fig

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def top_countries(self, n: int = 10) -> list[tuple[str, int]]:
        """Return top-n countries by attack count, descending."""
        with self._lock:
            counts = dict(self._country_counts)
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]

    def total_unique_ips(self) -> int:
        with self._lock:
            return len(self._ip_hits)

    def total_attacks(self) -> int:
        with self._lock:
            return sum(self._country_counts.values())

    def clear(self) -> None:
        with self._lock:
            self._ip_hits.clear()
            self._country_counts.clear()
            self._country_codes.clear()
        logger.info("AttackMap cleared")
