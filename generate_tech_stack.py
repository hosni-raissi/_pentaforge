import xml.etree.ElementTree as ET

def generate_diagram():
    mxfile = ET.Element("mxfile", host="Electron", type="device")
    diagram = ET.SubElement(mxfile, "diagram", id="tech_stack", name="Technology Stack")
    model = ET.SubElement(diagram, "mxGraphModel", dx="1000", dy="1000", grid="1", gridSize="10", guides="1", tooltips="1", connect="1", arrows="1", fold="1", page="1", pageScale="1", pageWidth="1000", pageHeight="600", math="0", shadow="0")
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", id="0")
    ET.SubElement(root, "mxCell", id="1", parent="0")

    cells = []

    def add_node(nid, value, x, y, w, h, style, parent="1"):
        cells.append({"id": nid, "value": value, "x": x, "y": y, "w": w, "h": h, "style": style, "parent": parent})

    data = [
        {"title": "FastAPI", "sub": "Backend API", "bg": "#E0F2FE", "fg": "#0369A1", "txt": "API"},
        {"title": "React", "sub": "User interface", "bg": "#ECFDF5", "fg": "#047857", "txt": "UI"},
        {"title": "Tauri", "sub": "Desktop application", "bg": "#FFEDD5", "fg": "#C2410C", "txt": "APP"},
        {"title": "Docker Compose", "sub": "Deployment", "bg": "#DCFCE7", "fg": "#15803D", "txt": "DOK"},
        {"title": "Redis", "sub": "Runtime cache", "bg": "#FCE7F3", "fg": "#BE185D", "txt": "RED"},
        {"title": "Qdrant", "sub": "Vector database", "bg": "#EDE9FE", "fg": "#6D28D9", "txt": "VEC"},
        {"title": "SQLite", "sub": "Project database", "bg": "#E0F2FE", "fg": "#0369A1", "txt": "SQL"},
        {"title": "LLMs", "sub": "AI agents", "bg": "#FCE7F3", "fg": "#BE185D", "txt": "AI"},
        {"title": "Security tools", "sub": "Execution layer", "bg": "#ECFDF5", "fg": "#047857", "txt": "SEC"}
    ]

    box_w = 280
    box_h = 140
    start_x = 40
    start_y = 40
    gap_x = 30
    gap_y = 30

    for i, item in enumerate(data):
        row = i // 3
        col = i % 3
        
        x = start_x + (col * (box_w + gap_x))
        y = start_y + (row * (box_h + gap_y))
        
        # Main Background Box
        s_bg = "rounded=1;whiteSpace=wrap;html=0;fillColor=#2A2D30;strokeColor=#45494E;strokeWidth=2;arcSize=8;"
        add_node(f"bg_{i}", "", x, y, box_w, box_h, s_bg)
        
        # Icon Box
        icon_w = 46
        icon_h = 46
        icon_x = x + (box_w / 2) - (icon_w / 2)
        icon_y = y + 20
        s_icon = f"rounded=1;whiteSpace=wrap;html=0;fillColor={item['bg']};strokeColor=none;fontColor={item['fg']};fontSize=14;fontStyle=1;arcSize=30;"
        add_node(f"icon_{i}", item['txt'], icon_x, icon_y, icon_w, icon_h, s_icon)

        # Title
        s_title = "text;html=0;strokeColor=none;fillColor=none;align=center;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontColor=#FFFFFF;fontSize=18;fontStyle=1;"
        add_node(f"title_{i}", item['title'], x + 20, y + 75, box_w - 40, 30, s_title)

        # Subtitle
        s_subtitle = "text;html=0;strokeColor=none;fillColor=none;align=center;verticalAlign=top;whiteSpace=wrap;rounded=0;fontColor=#9CA3AF;fontSize=14;"
        add_node(f"sub_{i}", item['sub'], x + 20, y + 105, box_w - 40, 25, s_subtitle)

    # Write XML
    for c in cells:
        cell = ET.SubElement(root, "mxCell", id=c["id"], value=c["value"], style=c["style"], vertex="1", parent=c["parent"])
        ET.SubElement(cell, "mxGeometry", x=str(c["x"]), y=str(c["y"]), width=str(c["w"]), height=str(c["h"]), **{"as": "geometry"})

    tree = ET.ElementTree(mxfile)
    ET.indent(tree, space="  ", level=0)
    tree.write("documents/diagrams/tech_stack.drawio", encoding="utf-8", xml_declaration=True)
    print("Tech Stack diagram generated.")

if __name__ == "__main__":
    generate_diagram()
