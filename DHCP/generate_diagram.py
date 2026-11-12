import os
import matplotlib
matplotlib.use('Agg')
os.environ['MPLCONFIGDIR'] = os.environ.get('TEMP', '/tmp')

import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, ArrowStyle

def create_architecture_diagram():
    fig = plt.figure(figsize=(19, 12), dpi=200)
    ax = fig.add_subplot(111)
    ax.set_facecolor('#0b0f19') # Deep tech dark background
    fig.patch.set_facecolor('#0b0f19')
    ax.set_xlim(0, 1900)
    ax.set_ylim(0, 1200)
    ax.axis('off')

    # Helper function for drawing modern glowing cards
    def draw_card(x, y, w, h, bg_color, border_color, border_width=1.5, radius=16, alpha=1.0):
        box = FancyBboxPatch(
            (x, y), w, h,
            boxstyle=f"round,pad=0,rounding_size={radius}",
            facecolor=bg_color,
            edgecolor=border_color,
            linewidth=border_width,
            alpha=alpha,
            zorder=2
        )
        ax.add_patch(box)
        return box

    # Helper for connector arrows
    def draw_arrow(x1, y1, x2, y2, color='#38bdf8', lw=2.0, style='->', ls='-', zorder=3):
        ax.annotate(
            '', xy=(x2, y2), xytext=(x1, y1),
            arrowprops=dict(
                arrowstyle=style,
                color=color,
                lw=lw,
                linestyle=ls,
                shrinkA=3,
                shrinkB=3,
                mutation_scale=16
            ),
            zorder=zorder
        )

    # =========================================================================
    # 1. HEADER TITLE SECTION
    # =========================================================================
    ax.text(950, 1150, "DISTRIBUTED & LOAD-BALANCED RFC 2131 DHCP SERVER CLUSTER",
            color='#f8fafc', fontsize=22, fontweight='bold', ha='center', va='center')
    ax.text(950, 1115, "Enterprise 6-Container Microservices Architecture  •  Subnet: 192.168.10.0/24  •  Java & Docker",
            color='#94a3b8', fontsize=13, ha='center', va='center')

    # Header decorative separator line
    ax.plot([150, 1750], [1085, 1085], color='#1e293b', lw=2)

    # =========================================================================
    # 2. CLIENT LAYER (TOP)
    # =========================================================================
    # Outer Client Container Box
    draw_card(140, 930, 1620, 130, '#111827', '#334155', border_width=1.5, radius=12)
    ax.text(170, 1035, "CLIENT INGRESS TIER (BROADCAST DOMAIN)", color='#38bdf8', fontsize=11, fontweight='bold', va='center')

    # Client Box 1: Physical PCs / Workstations
    draw_card(180, 950, 480, 68, '#1e293b', '#475569', radius=8)
    ax.text(420, 995, "Physical Workstations & PCs", color='#f8fafc', fontsize=12, fontweight='bold', ha='center')
    ax.text(420, 970, "Broadcast DHCPDISCOVER (255.255.255.255:67)", color='#94a3b8', fontsize=9.5, ha='center')

    # Client Box 2: Docker Alpine Client
    draw_card(710, 950, 480, 68, '#1e293b', '#475569', radius=8)
    ax.text(950, 995, "Real Linux Container (Alpine udhcpc)", color='#f8fafc', fontsize=12, fontweight='bold', ha='center')
    ax.text(950, 970, "Unmodified OS Kernel • Standard eth0 Request", color='#94a3b8', fontsize=9.5, ha='center')

    # Client Box 3: Multi-Client Simulator
    draw_card(1240, 950, 480, 68, '#1e293b', '#475569', radius=8)
    ax.text(1480, 995, "Multi-Threaded Client Simulator", color='#f8fafc', fontsize=12, fontweight='bold', ha='center')
    ax.text(1480, 970, "DORA Handshakes • Starvation Floods (40 pkts)", color='#94a3b8', fontsize=9.5, ha='center')

    # Arrows from Clients to Load Balancer
    draw_arrow(950, 930, 950, 830, color='#38bdf8', lw=2.5)
    ax.text(965, 875, "UDP 255.255.255.255:67 (Raw DHCP Ingress)", color='#38bdf8', fontsize=10.5, fontweight='bold', va='center')

    # =========================================================================
    # 3. LAYER-4 LOAD BALANCER & RELAY AGENT (MIDDLE-UPPER)
    # =========================================================================
    draw_card(140, 570, 1620, 260, '#0f172a', '#0284c7', border_width=2.5, radius=14)

    # LB Title and Specs Badge
    ax.text(180, 800, "dhcp-load-balancer  (192.168.10.200)", color='#38bdf8', fontsize=17, fontweight='bold', va='center')
    ax.text(180, 775, "L4 UDP Ingress Router  •  RFC 2131 DHCP Relay Agent (giaddr = 192.168.10.254, hops++)", color='#cbd5e1', fontsize=11, va='center')

    # LB Inner Component 1: Dual Rate Limiter
    draw_card(180, 600, 360, 150, '#1e293b', '#38bdf8', border_width=1.2, radius=10)
    ax.text(360, 720, "Dual-Engine Rate Limiter", color='#38bdf8', fontsize=13, fontweight='bold', ha='center')
    ax.text(360, 690, "Anti-Starvation DDoS Protection", color='#94a3b8', fontsize=10, ha='center')
    ax.text(360, 655, "• Token Bucket (30 Global / 20 MAC)", color='#e2e8f0', fontsize=10, ha='center')
    ax.text(360, 630, "• Sliding Window Counter (Cloudflare)", color='#e2e8f0', fontsize=10, ha='center')

    # LB Inner Component 2: Consistent Hash Ring
    draw_card(570, 600, 380, 150, '#1e293b', '#22c55e', border_width=1.2, radius=10)
    ax.text(760, 720, "Consistent Hash Router", color='#22c55e', fontsize=13, fontweight='bold', ha='center')
    ax.text(760, 690, "Deterministic Sticky Session Routing", color='#94a3b8', fontsize=10, ha='center')
    ax.text(760, 655, "• Ketama Ring: 32 Virtual Nodes/Host", color='#e2e8f0', fontsize=10, ha='center')
    ax.text(760, 630, "• Minimal Re-mapping O(1/N) on Node Death", color='#e2e8f0', fontsize=10, ha='center')

    # LB Inner Component 3: Heartbeat Monitor
    draw_card(980, 600, 360, 150, '#1e293b', '#f59e0b', border_width=1.2, radius=10)
    ax.text(1160, 720, "Heartbeat Health Detector", color='#f59e0b', fontsize=13, fontweight='bold', ha='center')
    ax.text(1160, 690, "Active Failure Detection & Failover", color='#94a3b8', fontsize=10, ha='center')
    ax.text(1160, 655, "• 700ms Ping / Pong Heartbeats", color='#e2e8f0', fontsize=10, ha='center')
    ax.text(1160, 630, "• 1.8s Timeout Eviction (Auto-Failover)", color='#e2e8f0', fontsize=10, ha='center')

    # LB Inner Component 4: Web Dashboard & REST Server
    draw_card(1370, 600, 350, 150, '#1e293b', '#a855f7', border_width=1.2, radius=10)
    ax.text(1545, 720, "Web Dashboard & REST API", color='#c084fc', fontsize=13, fontweight='bold', ha='center')
    ax.text(1545, 690, "Zero-Dependency Embedded HTTP Server", color='#94a3b8', fontsize=10, ha='center')
    ax.text(1545, 655, "• Port 8080 (http://localhost:8080)", color='#e2e8f0', fontsize=10, ha='center')
    ax.text(1545, 630, "• Real-Time JSON Telemetry (/api/state)", color='#e2e8f0', fontsize=10, ha='center')

    # =========================================================================
    # 4. BACKEND DHCP WORKER NODES (MIDDLE-LOWER)
    # =========================================================================
    # Connecting Arrows from LB to Nodes
    draw_arrow(430, 570, 430, 470, color='#38bdf8', lw=2.2)
    ax.text(370, 520, "UDP :6701", color='#38bdf8', fontsize=10.5, fontweight='bold', ha='right')

    draw_arrow(950, 570, 950, 470, color='#38bdf8', lw=2.2)
    ax.text(965, 520, "UDP :6702", color='#38bdf8', fontsize=10.5, fontweight='bold', ha='left')

    draw_arrow(1470, 570, 1470, 470, color='#38bdf8', lw=2.2)
    ax.text(1530, 520, "UDP :6703", color='#38bdf8', fontsize=10.5, fontweight='bold', ha='left')

    # Node 1 Card
    draw_card(180, 270, 460, 200, '#111827', '#38bdf8', border_width=2.0, radius=12)
    ax.text(410, 435, "dhcp-node-1", color='#38bdf8', fontsize=16, fontweight='bold', ha='center')
    ax.text(410, 410, "192.168.10.201 : 6701", color='#94a3b8', fontsize=11, fontweight='bold', ha='center')
    ax.text(410, 375, "• Dynamic IP Pool: 192.168.10.10 - .150", color='#e2e8f0', fontsize=10.5, ha='center')
    ax.text(410, 350, "• Static VIP Reservations & Lease TTL=120s", color='#e2e8f0', fontsize=10.5, ha='center')
    ax.text(410, 325, "• Disk Persistence WAL: leases_node1.db", color='#e2e8f0', fontsize=10.5, ha='center')
    ax.text(410, 300, "• 2-Second Lease Expiration Reaper Task", color='#e2e8f0', fontsize=10.5, ha='center')

    # Node 2 Card
    draw_card(720, 270, 460, 200, '#111827', '#22c55e', border_width=2.0, radius=12)
    ax.text(950, 435, "dhcp-node-2", color='#22c55e', fontsize=16, fontweight='bold', ha='center')
    ax.text(950, 410, "192.168.10.202 : 6702", color='#94a3b8', fontsize=11, fontweight='bold', ha='center')
    ax.text(950, 375, "• Dynamic IP Pool: 192.168.10.10 - .150", color='#e2e8f0', fontsize=10.5, ha='center')
    ax.text(950, 350, "• Static VIP Reservations & Lease TTL=120s", color='#e2e8f0', fontsize=10.5, ha='center')
    ax.text(950, 325, "• Disk Persistence WAL: leases_node2.db", color='#e2e8f0', fontsize=10.5, ha='center')
    ax.text(950, 300, "• 2-Second Lease Expiration Reaper Task", color='#e2e8f0', fontsize=10.5, ha='center')

    # Node 3 Card
    draw_card(1260, 270, 460, 200, '#111827', '#f59e0b', border_width=2.0, radius=12)
    ax.text(1490, 435, "dhcp-node-3", color='#f59e0b', fontsize=16, fontweight='bold', ha='center')
    ax.text(1490, 410, "192.168.10.203 : 6703", color='#94a3b8', fontsize=11, fontweight='bold', ha='center')
    ax.text(1490, 375, "• Dynamic IP Pool: 192.168.10.10 - .150", color='#e2e8f0', fontsize=10.5, ha='center')
    ax.text(1490, 350, "• Static VIP Reservations & Lease TTL=120s", color='#e2e8f0', fontsize=10.5, ha='center')
    ax.text(1490, 325, "• Disk Persistence WAL: leases_node3.db", color='#e2e8f0', fontsize=10.5, ha='center')
    ax.text(1490, 300, "• 2-Second Lease Expiration Reaper Task", color='#e2e8f0', fontsize=10.5, ha='center')

    # Gossip Synchronization Double-Headed Arrows between Nodes
    draw_arrow(640, 370, 720, 370, color='#ec4899', lw=2.5, style='<->')
    draw_arrow(1180, 370, 1260, 370, color='#ec4899', lw=2.5, style='<->')
    
    # Mesh connection between Node 1 and Node 3 routed cleanly below the cards
    ax.plot([410, 410, 1490, 1490], [270, 235, 235, 270], color='#ec4899', lw=2.0, linestyle='--', zorder=3)
    ax.scatter([410, 1490], [270, 270], color='#ec4899', s=35, zorder=4)
    ax.text(950, 245, "Active-Active Peer Gossip Replication Mesh (UDP Sub-millisecond Lease Sync)", color='#f472b6', fontsize=10, fontweight='bold', ha='center', va='bottom')

    # =========================================================================
    # 5. ENTERPRISE INFRASTRUCTURE & PERSISTENCE TIER (BOTTOM)
    # =========================================================================
    # Gateway VIP
    draw_card(180, 40, 720, 150, '#111827', '#06b6d4', border_width=2.0, radius=12)
    ax.text(210, 155, "gateway-admin-vip  (192.168.10.5)", color='#22d3ee', fontsize=15, fontweight='bold', va='center')
    ax.text(210, 130, "Core Gateway & Router (NGINX Reverse Proxy)  •  Port 8085", color='#94a3b8', fontsize=10.5, va='center')
    ax.text(210, 98, "• Permanent Static VIP MAC: 00:1A:2B:3C:4D:01  (Infinite TTL)", color='#e2e8f0', fontsize=10, va='center')
    ax.text(210, 73, "• Admin VIP Portal: http://localhost:8085  (Route table & Cluster status)", color='#e2e8f0', fontsize=10, va='center')

    # Database Primary VIP
    draw_card(1000, 40, 720, 150, '#111827', '#3b82f6', border_width=2.0, radius=12)
    ax.text(1030, 155, "prod-db-primary  (192.168.10.6:5432)", color='#60a5fa', fontsize=15, fontweight='bold', va='center')
    ax.text(1030, 130, "Production PostgreSQL 15 Relational Database  •  Port 5432", color='#94a3b8', fontsize=10.5, va='center')
    ax.text(1030, 98, "• Permanent Static VIP MAC: 00:1A:2B:3C:4D:02  (Infinite TTL)", color='#e2e8f0', fontsize=10, va='center')
    ax.text(1030, 73, "• Continuous JSON-to-SQL Sync Daemon (upserting into dhcp_leases)", color='#e2e8f0', fontsize=10, va='center')

    # Connect Gateway to LB (reverse proxy)
    draw_arrow(540, 190, 540, 240, color='#22d3ee', lw=1.8, style='->')
    ax.text(555, 215, "Reverse Proxy /cluster/", color='#22d3ee', fontsize=9.5, fontweight='bold')

    # Connect DB to LB (daemon polling)
    draw_arrow(1360, 190, 1360, 240, color='#60a5fa', lw=1.8, style='<-', ls='dashed')
    ax.text(1375, 215, "Continuous Polling /api/state", color='#60a5fa', fontsize=9.5, fontweight='bold')

    plt.tight_layout()
    output_path = r"c:\Users\aritr\OneDrive\Desktop\CN Project\DHCP\architecture_diagram.png"
    plt.savefig(output_path, facecolor=fig.get_facecolor(), edgecolor='none', dpi=200, bbox_inches='tight')
    plt.close()
    print(f"Architecture diagram generated successfully: {output_path}")

if __name__ == '__main__':
    create_architecture_diagram()
