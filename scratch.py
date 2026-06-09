import xml.etree.ElementTree as ET

# Base structure
xml = """<mxGraphModel dx="1445" dy="795" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1654" pageHeight="1169" math="0" shadow="0">
  <root>
    <mxCell id="0" />
    <mxCell id="1" parent="0" />
"""

# Header
xml += '    <mxCell id="10" parent="1" style="rounded=1;arcSize=10;whiteSpace=wrap;html=1;fillColor=#0f172a;fontColor=#ffffff;strokeColor=none;fontSize=12;fontStyle=1;align=center;fontFamily=Helvetica;" value="Phase / Week" vertex="1"><mxGeometry height="40" width="100" x="170" y="100" as="geometry" /></mxCell>\n'

for i in range(1, 17):
    x = 280 + (i - 1) * 70
    xml += f'    <mxCell id="11_{i}" parent="1" style="rounded=1;arcSize=10;whiteSpace=wrap;html=1;fillColor=#f1f5f9;strokeColor=#cbd5e1;fontColor=#334155;fontSize=12;fontStyle=1;align=center;fontFamily=Helvetica;" value="W{i}" vertex="1"><mxGeometry height="40" width="66" x="{x+2}" y="100" as="geometry" /></mxCell>\n'

sprints = [
    ("Sprint 0", 4, "Research & Technical Bootcamp", "#4f46e5"), # Indigo
    ("Sprint 1", 2, "Core Architecture & Persistence", "#0ea5e9"), # Sky
    ("Sprint 2", 2, "Planning & Orchestration", "#0d9488"), # Teal
    ("Sprint 3", 2, "Execution & Tool Sandbox", "#10b981"), # Emerald
    ("Sprint 4", 2, "Analysis & Reporting Agents", "#eab308"), # Yellow
    ("Sprint 5", 2, "Interface Layer & HITL", "#f97316"), # Orange
    ("Sprint 6", 2, "Integration & Packaging", "#ef4444"), # Red
]

y = 156
start_week = 1
for i, (name, dur, label, color) in enumerate(sprints):
    x_start = 280 + (start_week - 1) * 70
    width = dur * 70
    
    # Left empty track
    if start_week > 1:
        left_width = (start_week - 1) * 70
        xml += f'    <mxCell id="track_l_{i}" parent="1" style="rounded=0;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#f1f5f9;" value="" vertex="1"><mxGeometry height="44" width="{left_width}" x="280" y="{y}" as="geometry" /></mxCell>\n'
        
    # Right empty track
    end_week = start_week + dur - 1
    if end_week < 16:
        right_width = (16 - end_week) * 70
        xml += f'    <mxCell id="track_r_{i}" parent="1" style="rounded=0;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#f1f5f9;" value="" vertex="1"><mxGeometry height="44" width="{right_width}" x="{x_start + width}" y="{y}" as="geometry" /></mxCell>\n'

    # Sprint Label
    xml += f'    <mxCell id="sprint_lbl_{i}" parent="1" style="rounded=1;arcSize=20;whiteSpace=wrap;html=1;fillColor=#334155;fontColor=#ffffff;strokeColor=none;fontSize=11;fontStyle=1;align=center;fontFamily=Helvetica;" value="{name}" vertex="1"><mxGeometry height="36" width="90" x="180" y="{y+4}" as="geometry" /></mxCell>\n'
    
    # Sprint Bar (Pill shaped)
    xml += f'    <mxCell id="sprint_bar_{i}" parent="1" style="rounded=1;arcSize=50;whiteSpace=wrap;html=1;fillColor={color};fontColor=#ffffff;strokeColor=none;fontSize=12;fontStyle=1;align=center;fontFamily=Helvetica;" value="{label}" vertex="1"><mxGeometry height="36" width="{width-8}" x="{x_start+4}" y="{y+4}" as="geometry" /></mxCell>\n'
    
    # Milestone Marker (Diamond)
    milestone_x = x_start + width - 20
    if i == len(sprints) - 1:
        # Rocket on last sprint
        xml += f'    <mxCell id="ms_{i}" parent="1" style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;fontSize=20;" value="🚀" vertex="1"><mxGeometry height="30" width="30" x="{milestone_x+10}" y="{y+7}" as="geometry" /></mxCell>\n'
    else:
        # Diamond milestone
        xml += f'    <mxCell id="ms_{i}" parent="1" style="shape=rhombus;html=1;fillColor=#ffffff;strokeColor={color};strokeWidth=2;" value="" vertex="1"><mxGeometry height="16" width="16" x="{milestone_x+5}" y="{y+14}" as="geometry" /></mxCell>\n'
    
    y += 50
    start_week += dur

# Legend
xml += '    <mxCell id="leg_1" parent="1" style="shape=rhombus;html=1;fillColor=#ffffff;strokeColor=#4f46e5;strokeWidth=2;" value="" vertex="1"><mxGeometry height="14" width="14" x="285" y="540" as="geometry" /></mxCell>\n'
xml += '    <mxCell id="leg_2" parent="1" style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontSize=11;fontFamily=Helvetica;fontColor=#475569;" value="Sprint Milestone Review" vertex="1"><mxGeometry height="20" width="160" x="310" y="537" as="geometry" /></mxCell>\n'

xml += '    <mxCell id="leg_3" parent="1" style="text;html=1;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;fontSize=16;" value="🚀" vertex="1"><mxGeometry height="20" width="20" x="500" y="537" as="geometry" /></mxCell>\n'
xml += '    <mxCell id="leg_4" parent="1" style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;fontSize=11;fontFamily=Helvetica;fontColor=#475569;" value="Final Defense / Delivery" vertex="1"><mxGeometry height="20" width="160" x="530" y="537" as="geometry" /></mxCell>\n'

xml += """
  </root>
</mxGraphModel>
"""

with open("scratch_chart.xml", "w") as f:
    f.write(xml)
print("Done")
