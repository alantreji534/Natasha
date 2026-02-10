VERSION = "2.0.1"

def show():
    # Blue for ASCII art
    print("\033[94m")
    print(r"""
 ███╗   ██╗ █████╗ ████████╗ █████╗ ███████╗██╗  ██╗ █████╗
 ████╗  ██║██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██║  ██║██╔══██╗
 ██╔██╗ ██║███████║   ██║   ███████║███████╗███████║███████║
 ██║╚██╗██║██╔══██║   ██║   ██╔══██║╚════██║██╔══██║██╔══██║
 ██║ ╚████║██║  ██║   ██║   ██║  ██║███████║██║  ██║██║  ██║
 ╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
    """)

    # White for captions
    print("\033[97m")
    print(" ║  »—————— THE BLACK WIDOW OF CYBER SECURITY ——————«      ║")
    print(f" ║                    Version {VERSION}                        ║")
    print(" ║  High-Interaction Honeypot | SOC Deception | AI-Ready   ║\n")

    # Reset to default color
    print("\033[0m")
