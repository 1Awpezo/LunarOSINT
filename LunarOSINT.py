# All rights reserved for LunarOSINT - Made by Ezy
# We will file a dmca claim if this gets skidded
# Discord: g.hu | Telegram: t.me/awpez

import os
import re
import socket
import ssl
import requests
import phonenumbers
from phonenumbers import geocoder, carrier
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
import discord
import datetime
import uuid
from dotenv import load_dotenv
import json
import hashlib
import binascii
import dns.resolver
from bitcoinaddress import Wallet
import macaddress
from luhn import verify
import platform 

load_dotenv()
NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "YOUR_NUMVERIFY_API")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "YOUR_HUNTER_API")
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "YOUR_DISCORD_BOT_TOKEN")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY", "YOUR_WHOIS_API")
STEAM_API_KEY = os.getenv("STEAM_API_KEY", "YOUR_STEAM_API")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_API")
MAC_API_KEY = os.getenv("MAC_API_KEY", "YOUR_MAC_API")
TIMEZONEDB_API_KEY = os.getenv("TIMEZONEDB_API_KEY", "YOUR_TIMEZONE_API")
AVIATIONSTACK_API_KEY = os.getenv("AVIATIONSTACK_API_KEY", "YOUR_AVIATIONSTACK_API")

executor = ThreadPoolExecutor(max_workers=10)

# Gradient colors list
gradient_colors = [
    (255, 255, 255),
    (254, 254, 255),
    (253, 253, 255),
    (252, 252, 255),
    (251, 251, 255),
    (250, 250, 255),
    (249, 249, 255),
    (248, 248, 255),
    (247, 247, 255),
    (246, 246, 255),
    (245, 245, 255),
    (244, 244, 255),
    (243, 243, 255),
    (242, 242, 255),
    (241, 241, 255),
    (240, 240, 255),
    (239, 239, 255),
    (238, 238, 255),
    (237, 237, 255),
    (236, 236, 255),
    (235, 235, 255),
    (234, 234, 255),
    (233, 233, 255),
    (232, 232, 255),
    (231, 231, 255),
    (230, 230, 255),
    (229, 229, 255),
    (228, 228, 255),
    (227, 227, 255),
    (226, 226, 255),
    (225, 225, 255),
    (224, 224, 255),
    (223, 223, 255),
    (222, 222, 255),
    (221, 221, 255),
    (220, 220, 255),
    (219, 219, 255),
    (218, 218, 255),
    (217, 217, 255),
    (216, 216, 255),
    (215, 215, 255),
    (214, 214, 255),
    (213, 213, 255),
    (212, 212, 255),
    (211, 211, 255),
    (210, 210, 255),
    (209, 209, 255),
    (208, 208, 255),
    (207, 207, 255),
    (206, 206, 255),
    (205, 205, 255),
    (204, 204, 255),
    (203, 203, 255),
    (202, 202, 255),
    (201, 201, 255),
    (200, 200, 255),
    (199, 199, 255),
    (198, 198, 255),
    (197, 197, 255),
    (196, 196, 255),
    (195, 195, 255),
    (194, 194, 255),
    (193, 193, 255),
    (192, 192, 255),
    (191, 191, 255),
    (190, 190, 255),
    (189, 189, 255),
    (188, 188, 255),
    (187, 187, 255),
    (186, 186, 255),
    (185, 185, 255),
    (184, 184, 255),
    (183, 183, 255),
    (182, 182, 255),
    (181, 181, 255),
    (180, 180, 255),
    (179, 179, 255),
    (178, 178, 255),
    (177, 177, 255),
    (176, 176, 255),
    (175, 175, 255),
    (174, 174, 255),
    (173, 173, 255),
    (172, 172, 255),
    (171, 171, 255),
    (170, 170, 255),
    (169, 169, 255),
    (168, 168, 255),
    (167, 167, 255),
    (166, 166, 255),
    (165, 165, 255),
    (164, 164, 255),
    (163, 163, 255),
    (162, 162, 255),
    (161, 161, 255),
    (160, 160, 255),
    (159, 159, 255),
    (158, 158, 255),
    (157, 157, 255),
    (156, 156, 255),
    (155, 155, 255),
    (154, 154, 255),
    (153, 153, 255),
    (152, 152, 255),
    (151, 151, 255),
    (150, 150, 255),
    (149, 149, 255),
    (148, 148, 255),
    (147, 147, 255),
    (146, 146, 255),
    (145, 145, 255),
    (144, 144, 255),
    (143, 143, 255),
    (142, 142, 255),
    (141, 141, 255),
    (140, 140, 255),
    (139, 139, 255),
    (138, 138, 255),
    (137, 137, 255),
    (136, 136, 255),
    (135, 135, 255),
    (134, 134, 255),
    (133, 133, 255),
    (132, 132, 255),
    (131, 131, 255),
    (130, 130, 255),
    (5, 5, 255),
    (4, 4, 255),
    (3, 3, 255),
    (2, 2, 255),
    (1, 1, 255),
    (0, 0, 255),
    (0, 0, 255),
    (0, 0, 253),
    (0, 0, 251),
    (0, 0, 250),
    (0, 0, 248),
    (0, 0, 247),
    (0, 0, 245),
    (0, 0, 243),
    (0, 0, 242),
    (0, 0, 240),
    (0, 0, 239),
    (0, 0, 237),
    (0, 0, 235),
    (0, 0, 234),
    (0, 0, 232),
    (0, 0, 231),
    (0, 0, 229),
    (0, 0, 228),
    (0, 0, 226),
    (0, 0, 224),
    (0, 0, 223),
    (0, 0, 221),
    (0, 0, 220),
    (0, 0, 218),
    (0, 0, 216),
    (0, 0, 215),
    (0, 0, 213),
    (0, 0, 212),
    (0, 0, 210),
    (0, 0, 208),
    (0, 0, 207),
    (0, 0, 205),
    (0, 0, 204),
    (0, 0, 202),
    (0, 0, 201),
    (0, 0, 199),
    (0, 0, 197),
    (0, 0, 196),
    (0, 0, 194),
    (0, 0, 193),
    (0, 0, 191),
    (0, 0, 189),
    (0, 0, 188),
    (0, 0, 186),
    (0, 0, 185),
    (0, 0, 183),
    (0, 0, 181),
    (0, 0, 180),
    (0, 0, 178),
    (0, 0, 177),
    (0, 0, 175),
    (0, 0, 174),
    (0, 0, 172),
    (0, 0, 170),
    (0, 0, 169),
    (0, 0, 167),
    (0, 0, 166),
    (0, 0, 164),
    (0, 0, 162),
    (0, 0, 161),
    (0, 0, 159),
    (0, 0, 158),
    (0, 0, 156),
    (0, 0, 155),
    (0, 0, 155),
    (0, 0, 156),
    (0, 0, 158),
    (0, 0, 159),
    (0, 0, 161),
    (0, 0, 162),
    (0, 0, 164),
    (0, 0, 166),
    (0, 0, 167),
    (0, 0, 169),
    (0, 0, 170),
    (0, 0, 172),
    (0, 0, 174),
    (0, 0, 175),
    (0, 0, 177),
    (0, 0, 178),
    (0, 0, 180),
    (0, 0, 181),
    (0, 0, 183),
    (0, 0, 185),
    (0, 0, 186),
    (0, 0, 188),
    (0, 0, 189),
    (0, 0, 191),
    (0, 0, 193),
    (0, 0, 194),
    (0, 0, 196),
    (0, 0, 197),
    (0, 0, 199),
    (0, 0, 201),
    (0, 0, 202),
    (0, 0, 204),
    (0, 0, 205),
    (0, 0, 207),
    (0, 0, 208),
    (0, 0, 210),
    (0, 0, 212),
    (0, 0, 213),
    (0, 0, 215),
    (0, 0, 216),
    (0, 0, 218),
    (0, 0, 220),
    (0, 0, 221),
    (0, 0, 223),
    (0, 0, 224),
    (0, 0, 226),
    (0, 0, 228),
    (0, 0, 229),
    (0, 0, 231),
    (0, 0, 232),
    (0, 0, 234),
    (0, 0, 235),
    (0, 0, 237),
    (0, 0, 239),
    (0, 0, 240),
    (0, 0, 242),
    (0, 0, 243),
    (0, 0, 245),
    (0, 0, 247),
    (0, 0, 248),
    (0, 0, 250),
    (0, 0, 251),
    (0, 0, 253),
    (0, 0, 255),
    (1, 1, 255),
    (2, 2, 255),
    (3, 3, 255),
    (4, 4, 255),
    (5, 5, 255),
    (6, 6, 255),
    (7, 7, 255),
    (8, 8, 255),
    (9, 9, 255),
    (10, 10, 255),
    (11, 11, 255),
    (12, 12, 255),
    (13, 13, 255),
    (14, 14, 255),
    (15, 15, 255),
    (16, 16, 255),
    (17, 17, 255),
    (18, 18, 255),
    (19, 19, 255),
    (20, 20, 255),
    (21, 21, 255),
    (22, 22, 255),
    (23, 23, 255),
    (24, 24, 255),
    (25, 25, 255),
    (26, 26, 255),
    (27, 27, 255),
    (28, 28, 255),
    (29, 29, 255),
    (30, 30, 255),
    (31, 31, 255),
    (32, 32, 255),
    (33, 33, 255),
    (34, 34, 255),
    (35, 35, 255),
    (36, 36, 255),
    (37, 37, 255),
    (38, 38, 255),
    (39, 39, 255),
    (40, 40, 255),
    (41, 41, 255),
    (42, 42, 255),
    (43, 43, 255),
    (44, 44, 255),
    (45, 45, 255),
    (46, 46, 255),
    (47, 47, 255),
    (48, 48, 255),
    (49, 49, 255),
    (50, 50, 255),
    (51, 51, 255),
    (52, 52, 255),
    (53, 53, 255),
    (54, 54, 255),
    (55, 55, 255),
    (56, 56, 255),
    (57, 57, 255),
    (58, 58, 255),
    (59, 59, 255),
    (60, 60, 255),
    (61, 61, 255),
    (62, 62, 255),
    (63, 63, 255),
    (64, 64, 255),
    (65, 65, 255),
    (66, 66, 255),
    (67, 67, 255),
    (68, 68, 255),
    (69, 69, 255),
    (70, 70, 255),
    (71, 71, 255),
    (72, 72, 255),
    (73, 73, 255),
    (74, 74, 255),
    (75, 75, 255),
    (76, 76, 255),
    (77, 77, 255),
    (78, 78, 255),
    (79, 79, 255),
    (80, 80, 255),
    (81, 81, 255),
    (82, 82, 255),
    (83, 83, 255),
    (84, 84, 255),
    (85, 85, 255),
    (86, 86, 255),
    (87, 87, 255),
    (88, 88, 255),
    (89, 89, 255),
    (90, 90, 255),
    (91, 91, 255),
    (92, 92, 255),
    (93, 93, 255),
    (94, 94, 255),
    (95, 95, 255),
    (96, 96, 255),
    (97, 97, 255),
    (98, 98, 255),
    (99, 99, 255),
    (100, 100, 255),
    (101, 101, 255),
    (102, 102, 255),
    (103, 103, 255),
    (104, 104, 255),
    (105, 105, 255),
    (106, 106, 255),
    (107, 107, 255),
    (108, 108, 255),
    (109, 109, 255),
    (110, 110, 255),
    (111, 111, 255),
    (112, 112, 255),
    (113, 113, 255),
    (114, 114, 255),
    (115, 115, 255),
    (116, 116, 255),
    (117, 117, 255),
    (118, 118, 255),
    (119, 119, 255),
    (120, 120, 255),
    (121, 121, 255),
    (122, 122, 255),
    (123, 123, 255),
    (124, 124, 255),
    (125, 125, 255),
    (126, 126, 255),
    (127, 127, 255),
    (128, 128, 255),
    (129, 129, 255),
    (130, 130, 255),
    (131, 131, 255),
    (132, 132, 255),
    (133, 133, 255),
    (134, 134, 255),
    (135, 135, 255),
    (136, 136, 255),
    (137, 137, 255),
    (138, 138, 255),
    (139, 139, 255),
    (140, 140, 255),
    (141, 141, 255),
    (142, 142, 255),
    (143, 143, 255),
    (144, 144, 255),
    (145, 145, 255),
    (146, 146, 255),
    (147, 147, 255),
    (148, 148, 255),
    (149, 149, 255),
    (150, 150, 255),
    (151, 151, 255),
    (152, 152, 255),
    (153, 153, 255),
    (154, 154, 255),
    (155, 155, 255),
    (156, 156, 255),
    (157, 157, 255),
    (158, 158, 255),
    (159, 159, 255),
    (160, 160, 255),
    (161, 161, 255),
    (162, 162, 255),
    (163, 163, 255),
    (164, 164, 255),
    (165, 165, 255),
    (166, 166, 255),
    (167, 167, 255),
    (168, 168, 255),
    (169, 169, 255),
    (170, 170, 255),
    (171, 171, 255),
    (172, 172, 255),
    (173, 173, 255),
    (174, 174, 255),
    (175, 175, 255),
    (176, 176, 255),
    (177, 177, 255),
    (178, 178, 255),
    (179, 179, 255),
    (180, 180, 255),
    (181, 181, 255),
    (182, 182, 255),
    (183, 183, 255),
    (184, 184, 255),
    (185, 185, 255),
    (186, 186, 255),
    (187, 187, 255),
    (188, 188, 255),
    (189, 189, 255),
    (190, 190, 255),
    (191, 191, 255),
    (192, 192, 255),
    (193, 193, 255),
    (194, 194, 255),
    (195, 195, 255),
    (196, 196, 255),
    (197, 197, 255),
    (198, 198, 255),
    (199, 199, 255),
    (200, 200, 255),
    (201, 201, 255),
    (202, 202, 255),
    (203, 203, 255),
    (204, 204, 255),
    (205, 205, 255),
    (206, 206, 255),
    (207, 207, 255),
    (208, 208, 255),
    (209, 209, 255),
    (210, 210, 255),
    (211, 211, 255),
    (212, 212, 255),
    (213, 213, 255),
    (214, 214, 255),
    (215, 215, 255),
    (216, 216, 255),
    (217, 217, 255),
    (218, 218, 255),
    (219, 219, 255),
    (220, 220, 255),
    (221, 221, 255),
    (222, 222, 255),
    (223, 223, 255),
    (224, 224, 255),
    (225, 225, 255),
    (226, 226, 255),
    (227, 227, 255),
    (228, 228, 255),
    (229, 229, 255),
    (230, 230, 255),
    (231, 231, 255),
    (232, 232, 255),
    (233, 233, 255),
    (234, 234, 255),
    (235, 235, 255),
    (236, 236, 255),
    (237, 237, 255),
    (238, 238, 255),
    (239, 239, 255),
    (240, 240, 255),
    (241, 241, 255),
    (242, 242, 255),
    (243, 243, 255),
    (244, 244, 255),
    (245, 245, 255),
    (246, 246, 255),
    (247, 247, 255),
    (248, 248, 255),
    (249, 249, 255),
    (250, 250, 255),
    (251, 251, 255),
    (252, 252, 255),
    (253, 253, 255),
    (254, 254, 255),
    (255, 255, 255)
]

class LookupBot:
    def __init__(self):
        self.username_cache = {}
        self.ip_cache = {}
        self.phone_cache = {}
        self.discord_cache = {}
        self.email_verify_cache = {}
        self.steam_cache = {}
        self.domain_cache = {}
        self.url_cache = {}
        self.email_domain_cache = {}
        self.social_media_cache = {}
        self.bitcoin_cache = {}
        self.mac_cache = {}
        self.port_cache = {}
        self.credit_card_cache = {}
        self.zip_code_cache = {}
        self.isbn_cache = {}
        self.vin_cache = {}
        self.hash_cache = {}
        self.ssn_cache = {}
        self.airport_cache = {}
        self.timezone_cache = {}
        self.file_hash_cache = {}
        self.discord_client = discord.Client(intents=discord.Intents.default())

    def generate_map_html(self, latitude, longitude, title, output_file):
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <style>
        #map {{ height: 600px; width: 100%; }}
    </style>
</head>
<body>
    <h2>{title}</h2>
    <div id="map"></div>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        var map = L.map('map').setView([{latitude}, {longitude}], 10);
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        }}).addTo(map);
        L.marker([{latitude}, {longitude}]).addTo(map)
            .bindPopup('{title}').openPopup();
    </script>
</body>
</html>
"""
        os.makedirs("maps", exist_ok=True)
        file_path = os.path.join("maps", output_file)
        with open(file_path, "w") as f:
            f.write(html_content)
        return file_path

    async def username_lookup(self, username: str) -> str:
        if not username:
            return "Please provide a valid username."
        if username in self.username_cache:
            return self.username_cache[username]
        
        websites = {
            "GitHub": f"https://github.com/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "Reddit": f"https://www.reddit.com/user/{username}",
            "TikTok": f"https://www.tiktok.com/@{username}",
            "YouTube": f"https://www.youtube.com/@{username}",
            "Pinterest": f"https://www.pinterest.com/{username}/",
            "Steam": f"https://steamcommunity.com/id/{username}",
            "Twitch": f"https://www.twitch.tv/{username}",
            "SoundCloud": f"https://soundcloud.com/{username}",
            "DeviantArt": f"https://www.deviantart.com/{username}",
            "Medium": f"https://medium.com/@{username}",
            "Replit": f"https://replit.com/@{username}",
            "Facebook": f"https://www.facebook.com/{username}",
            "Telegram": f"https://www.t.me/{username}",
            "Snapchat": f"https://www.snapchat.com/add/{username}",
        }

        headers = {"User-Agent": "Mozilla/5.0"}
        def check_site(site, url):
            try:
                r = requests.head(url, headers=headers, timeout=5, allow_redirects=True)
                if r.status_code == 200:
                    return f"{site}: {url} [Taken]"
                elif r.status_code == 404:
                    return f"{site}: Available"
                else:
                    return f"{site}: Unknown (Status: {r.status_code})"
            except requests.RequestException:
                return f"{site}: Error"

        results = [f"\nUsername Lookup Results for: {username}\n{'-' * 40}"]
        futures = [executor.submit(check_site, site, url) for site, url in websites.items()]
        for future in as_completed(futures):
            results.append(future.result())
        output = "\n".join(results)
        self.username_cache[username] = output
        return output

    async def ip_lookup(self, ip: str) -> str:
        if not ip:
            return "Please provide an IP address."
        if not (re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip) or re.match(r"^[a-fA-F0-9:]+$", ip)):
            return "Invalid IP address format."
        if ip in self.ip_cache:
            return self.ip_cache[ip]

        def get_ip_info(ip_addr):
            try:
                r = requests.get(f"https://ipinfo.io/{ip_addr}/json", timeout=5)
                data = r.json()
                if "error" in data:
                    return f"Error: {data.get('reason', 'Unknown error')}"
                loc = data.get("loc", "N/A").split(',') if data.get("loc") else ["N/A", "N/A"]
                latitude = loc[0]
                longitude = loc[1]
                info = [
                    f"IP: {data.get('ip', 'N/A')}",
                    f"Hostname: {data.get('hostname', 'N/A')}",
                    f"City: {data.get('city', 'N/A')}",
                    f"Region: {data.get('region', 'N/A')}",
                    f"Country: {data.get('country', 'N/A')}",
                    f"Organization: {data.get('org', 'N/A')}",
                    f"Postal: {data.get('postal', 'N/A')}",
                    f"Timezone: {data.get('timezone', 'N/A')}",
                    f"Latitude: {latitude}",
                    f"Longitude: {longitude}",
                    f"Anycast: {'Yes' if data.get('anycast', False) else 'No'}",
                    f"Bogon: {'Yes' if data.get('bogon', False) else 'No'}",
                ]
                if "company" in data:
                    info.extend([f"Company: {data['company'].get('name', 'N/A')}", f"Company Type: {data['company'].get('type', 'N/A')}"])
                if "asn" in data:
                    info.extend([f"ASN: {data['asn'].get('asn', 'N/A')}", f"ASN Name: {data['asn'].get('name', 'N/A')}", f"ASN Domain: {data['asn'].get('domain', 'N/A')}"])
                if "abuse" in data:
                    info.append(f"Abuse Contact Email: {data['abuse'].get('email', 'N/A')}")
                if "carrier" in data:
                    info.append(f"Carrier: {data['carrier'].get('name', 'N/A')}")
                if "privacy" in data:
                    info.extend([
                        f"VPN: {'Yes' if data['privacy'].get('vpn', False) else 'No'}",
                        f"Proxy: {'Yes' if data['privacy'].get('proxy', False) else 'No'}",
                        f"Tor: {'Yes' if data['privacy'].get('tor', False) else 'No'}",
                        f"Relay: {'Yes' if data['privacy'].get('relay', False) else 'No'}",
                        f"Hosting: {'Yes' if data['privacy'].get('hosting', False) else 'No'}"
                    ])
                if latitude != "N/A" and longitude != "N/A":
                    map_file = self.generate_map_html(latitude, longitude, f"IP Location: {ip_addr}", f"ip_map_{ip_addr}_{uuid.uuid4().hex}.html")
                    info.append(f"Map: file:///{os.path.abspath(map_file)}")
                return "\n".join([f"\nIP Lookup Results for: {ip_addr}\n{'-' * 40}"] + info)
            except requests.RequestException:
                return "Request failed"

        result = get_ip_info(ip)
        self.ip_cache[ip] = result
        return result

    async def phone_lookup(self, phone: str) -> str:
        if not phone:
            return "Please provide a phone number."
        try:
            parsed = phonenumbers.parse(phone, None)
            if not phonenumbers.is_valid_number(parsed):
                return "Invalid phone number format. Please include country code (e.g., +12025550123)."
        except phonenumbers.phonenumberutil.NumberParseException:
            return "Invalid phone number format. Please include country code (e.g., +12025550123)."
        if phone in self.phone_cache:
            return self.phone_cache[phone]

        def get_phone_info(phone_number):
            parsed = phonenumbers.parse(phone_number, None)
            country = geocoder.description_for_number(parsed, "en")
            carrier_name = carrier.name_for_number(parsed, "en")
            url = f"http://apilayer.net/api/validate?access_key={NUMVERIFY_API_KEY}&number={phone_number}&format=1"
            response = requests.get(url, timeout=5)
            data = response.json()
            if not data.get("valid", False):
                return f"Phone number {phone_number} is invalid according to NumVerify."
            location = data.get('location', country or 'N/A')
            try:
                geo_response = requests.get(f"https://nominatim.openstreetmap.org/search?q={location}&format=json&limit=1", headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
                geo_data = geo_response.json()
                latitude = geo_data[0].get('lat', 'N/A') if geo_data else 'N/A'
                longitude = geo_data[0].get('lon', 'N/A') if geo_data else 'N/A'
            except:
                latitude = longitude = 'N/A'
            info = [
                f"Phone Number: {data.get('international_format', phone_number)}",
                f"Country: {data.get('country_name', country or 'N/A')}",
                f"Carrier: {data.get('carrier', carrier_name or 'N/A')}",
                f"Line Type: {data.get('line_type', 'N/A')}",
                f"Location: {data.get('location', 'N/A')}",
                f"Country Code: {data.get('country_code', 'N/A')}",
                f"Valid: {'Yes' if data.get('valid', False) else 'No'}",
            ]
            if latitude != "N/A" and longitude != "N/A":
                map_file = self.generate_map_html(latitude, longitude, f"Phone Location: {phone_number}", f"phone_map_{phone_number.replace('+', '')}_{uuid.uuid4().hex}.html")
                info.append(f"Map: file:///{os.path.abspath(map_file)}")
            return "\n".join([f"\nPhone Lookup Results for: {phone_number}\n{'-' * 40}"] + info)

        result = get_phone_info(phone)
        self.phone_cache[phone] = result
        return result

    async def discord_lookup(self, discord_id: str) -> str:
        if not DISCORD_BOT_TOKEN or DISCORD_BOT_TOKEN == "your_discord_bot_token":
            return "Discord bot token is not configured. Please contact the bot admin."
        if not discord_id:
            return "Please provide a Discord user ID."
        if not discord_id.isdigit():
            return "Please provide a valid Discord user ID (numeric)."
        if discord_id in self.discord_cache:
            return self.discord_cache[discord_id]

        async def get_discord_info(d_id):
            try:
                user = await self.discord_client.fetch_user(int(d_id))
                info = [
                    f"Discord ID: {user.id}",
                    f"Username: {user.name}",
                    f"Discriminator: #{user.discriminator}",
                    f"Display Name: {user.display_name}",
                    f"Created At: {user.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    f"Bot: {'Yes' if user.bot else 'No'}",
                ]
                return "\n".join([f"\nDiscord Lookup Results for ID: {d_id}\n{'-' * 40}"] + info)
            except discord.errors.NotFound:
                return f"No Discord user found for ID: {d_id}"
            except discord.errors.HTTPException:
                return "Discord API request failed"

        result = await get_discord_info(discord_id)
        self.discord_cache[discord_id] = result
        return result

    async def steam_lookup(self, steam_id: str) -> str:
        if not steam_id:
            return "Please provide a SteamID64."
        if not steam_id.isdigit() or len(steam_id) != 17:
            return "Please provide a valid SteamID64 (17-digit numeric ID)."
        if steam_id in self.steam_cache:
            return self.steam_cache[steam_id]

        def get_steam_info(s_id):
            url = f"http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key={STEAM_API_KEY}&steamids={s_id}"
            response = requests.get(url, timeout=5)
            data = response.json()
            if not data.get("response", {}).get("players"):
                return f"No Steam user found for SteamID64: {s_id}"
            player = data["response"]["players"][0]
            info = [
                f"SteamID64: {player.get('steamid', 'N/A')}",
                f"Persona Name: {player.get('personaname', 'N/A')}",
                f"Profile URL: {player.get('profileurl', 'N/A')}",
                f"Account Created: {player.get('timecreated', 'N/A')}",
                f"Last Logoff: {player.get('lastlogoff', 'N/A')}",
                f"Profile State: {'Public' if player.get('communityvisibilitystate') == 3 else 'Private or Friends-Only'}",
                f"Country: {player.get('loccountrycode', 'N/A')}",
                f"Real Name: {player.get('realname', 'N/A')}",
                f"Avatar URL: {player.get('avatarfull', 'N/A')}"
            ]
            if player.get('timecreated'):
                info[3] = f"Account Created: {datetime.datetime.fromtimestamp(player['timecreated']).strftime('%Y-%m-%d %H:%M:%S UTC')}"
            if player.get('lastlogoff'):
                info[4] = f"Last Logoff: {datetime.datetime.fromtimestamp(player['lastlogoff']).strftime('%Y-%m-%d %H:%M:%S UTC')}"
            return "\n".join([f"\nSteam Lookup Results for ID: {s_id}\n{'-' * 40}"] + info)

        result = get_steam_info(steam_id)
        self.steam_cache[steam_id] = result
        return result

    async def email_verify(self, email: str) -> str:
        if not email:
            return "Please provide an email address."
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_regex, email):
            return "Invalid email format."
        if email in self.email_verify_cache:
            return self.email_verify_cache[email]

        def verify_email(e):
            url = f"https://api.hunter.io/v2/email-verifier?email={e}&api_key={HUNTER_API_KEY}"
            response = requests.get(url, timeout=5)
            data = response.json()
            if response.status_code != 200 or 'errors' in data:
                return "Error verifying email"
            result = data.get('data', {})
            info = [
                f"Email: {result.get('email', e)}",
                f"Status: {result.get('status', 'N/A')}",
                f"Result: {result.get('result', 'N/A')}",
                f"Score: {result.get('score', 'N/A')}/100",
                f"Disposable: {'Yes' if result.get('disposable', False) else 'No'}",
                f"Webmail: {'Yes' if result.get('webmail', False) else 'No'}",
                f"MX Records: {'Present' if result.get('mx_records', False) else 'Not Found'}",
                f"SMTP Server: {'Present' if result.get('smtp_server', False) else 'Not Found'}",
                f"SMTP Check: {'Valid' if result.get('smtp_check', False) else 'Invalid'}",
                f"Accept All: {'Yes' if result.get('accept_all', False) else 'No'}",
                f"Block: {'Yes' if result.get('block', False) else 'No'}",
            ]
            if result.get('regexp', False):
                info.append("Warning: Email format is invalid (regexp check failed)")
            if result.get('gibberish', False):
                info.append("Warning: Email appears to be gibberish")
            return "\n".join([f"\nEmail Verification Results for: {e}\n{'-' * 40}"] + info)

        result = verify_email(email)
        self.email_verify_cache[email] = result
        return result

    async def domain_lookup(self, domain: str) -> str:
        if not domain:
            return "Please provide a valid domain."
        domain_regex = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(domain_regex, domain):
            return "Invalid domain format."
        if domain in self.domain_cache:
            return self.domain_cache[domain]

        def get_domain_info(d):
            try:
                url = f"https://api.whoisxmlapi.com/v2/who-is/{d}?apiKey={WHOIS_API_KEY}"
                response = requests.get(url, timeout=5)
                data = response.json()
                if "error" in data:
                    return f"Error: {data.get('message', 'Unknown error')}"
                whois = data.get("WhoisRecord", {})
                info = [
                    f"Domain: {whois.get('domainName', 'N/A')}",
                    f"Status: {whois.get('registryData', {}).get('status', 'N/A')}",
                    f"Created: {whois.get('createdDate', 'N/A')}",
                    f"Updated: {whois.get('updatedDate', 'N/A')}",
                    f"Expires: {whois.get('expiresDate', 'N/A')}",
                    f"Registrar: {whois.get('registrarName', 'N/A')}",
                    f"Registrant: {whois.get('registrant', {}).get('organization', 'N/A')}",
                    f"Name Servers: {', '.join(whois.get('nameServers', []) or ['N/A'])}",
                ]
                return "\n".join([f"\nDomain Lookup Results for: {d}\n{'-' * 40}"] + info)
            except requests.RequestException:
                return "Request failed"

        result = get_domain_info(domain)
        self.domain_cache[domain] = result
        return result

    async def url_scanner(self, url: str) -> str:
        if not url:
            return "Please provide a URL."
        if not re.match(r"^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", url):
            return "Invalid URL format."
        if url in self.url_cache:
            return self.url_cache[url]

        try:
            scan_url = f"https://www.virustotal.com/api/v3/urls"
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            data = {"url": url}
            response = requests.post(scan_url, headers=headers, json=data, timeout=5)
            scan_id = response.json().get("data", {}).get("id")
            if not scan_id:
                return "Error initiating URL scan."

            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
            response = requests.get(analysis_url, headers=headers, timeout=5)
            data = response.json().get("data", {}).get("attributes", {})
            
            info = [
                f"URL: {url}",
                f"Malicious: {data.get('stats', {}).get('malicious', 0)}",
                f"Suspicious: {data.get('stats', {}).get('suspicious', 0)}",
                f"Harmless: {data.get('stats', {}).get('harmless', 0)}",
                f"Undetected: {data.get('stats', {}).get('undetected', 0)}",
                f"Last Analysis Date: {datetime.datetime.fromtimestamp(data.get('last_analysis_date', 0)).strftime('%Y-%m-%d %H:%M:%S UTC') if data.get('last_analysis_date') else 'N/A'}",
            ]
            result = "\n".join([f"\nURL Scanner Results for: {url}\n{'-' * 40}"] + info)
            self.url_cache[url] = result
            return result
        except requests.RequestException:
            return "Error scanning URL."

    async def email_domain_check(self, email: str) -> str:
        if not email:
            return "Please provide an email address."
        email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_regex, email):
            return "Invalid email format."
        if email in self.email_domain_cache:
            return self.email_domain_cache[email]

        domain = email.split('@')[1]
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_info = [str(record.exchange) for record in mx_records]
            info = [
                f"Email: {email}",
                f"Domain: {domain}",
                f"MX Records: {', '.join(mx_info) if mx_info else 'None found'}",
            ]
            result = "\n".join([f"\nEmail Domain Check Results for: {email}\n{'-' * 40}"] + info)
            self.email_domain_cache[email] = result
            return result
        except Exception as e:
            return f"Error checking email domain: {str(e)}"

    async def social_media_lookup(self, username: str) -> str:
        if not username:
            return "Please provide a valid username."
        if username in self.social_media_cache:
            return self.social_media_cache[username]
        
        result = await self.username_lookup(username)
        self.social_media_cache[username] = result
        return result

    async def bitcoin_address_lookup(self, address: str) -> str:
        if not address:
            return "Please provide a Bitcoin address."
        try:
            wallet = Wallet(address)
            if not wallet.address:
                return "Invalid Bitcoin address format."
        except:
            return "Invalid Bitcoin address format."
        if address in self.bitcoin_cache:
            return self.bitcoin_cache[address]

        try:
            url = f"https://blockchain.info/rawaddr/{address}"
            response = requests.get(url, timeout=5)
            data = response.json()
            info = [
                f"Bitcoin Address: {address}",
                f"Total Received: {data.get('total_received', 0) / 1e8} BTC",
                f"Total Sent: {data.get('total_sent', 0) / 1e8} BTC",
                f"Final Balance: {data.get('final_balance', 0) / 1e8} BTC",
                f"Number of Transactions: {data.get('n_tx', 0)}",
            ]
            result = "\n".join([f"\nBitcoin Address Lookup Results for: {address}\n{'-' * 40}"] + info)
            self.bitcoin_cache[address] = result
            return result
        except requests.RequestException:
            return "Error fetching Bitcoin address info."

    async def mac_address_lookup(self, mac: str) -> str:
        if not mac:
            return "Please provide a MAC address."
        try:
            macaddress.MAC(mac)
        except ValueError:
            return "Invalid MAC address format."
        if mac in self.mac_cache:
            return self.mac_cache[mac]

        try:
            url = f"https://api.macaddress.io/v1?apiKey={MAC_API_KEY}&output=json&search={mac}"
            response = requests.get(url, timeout=5)
            data = response.json()
            info = [
                f"MAC Address: {mac}",
                f"Vendor: {data.get('vendorDetails', {}).get('companyName', 'N/A')}",
                f"Block Type: {data.get('blockDetails', {}).get('blockType', 'N/A')}",
                f"Country: {data.get('vendorDetails', {}).get('countryCode', 'N/A')}",
            ]
            result = "\n".join([f"\nMAC Address Lookup Results for: {mac}\n{'-' * 40}"] + info)
            self.mac_cache[mac] = result
            return result
        except requests.RequestException:
            return "Error fetching MAC address info."

    async def port_scanner(self, ip: str) -> str:
        if not ip:
            return "Please provide an IP address or domain."
        if ip in self.port_cache:
            return self.port_cache[ip]

        try:
            def scan_port(port):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                return port if result == 0 else None

            common_ports = [21, 22, 23, 25, 80, 110, 143, 443, 3389]
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                results = executor.map(scan_port, common_ports)
                open_ports = [port for port in results if port]

            info = [
                f"IP/Domain: {ip}",
                f"Open Ports: {', '.join(f'Port {p}/tcp' for p in open_ports) if open_ports else 'None found'}",
            ]
            result = "\n".join([f"\nPort Scanner Results for: {ip}\n{'-' * 40}"] + info)
            self.port_cache[ip] = result
            return result
        except Exception as e:
            return f"Error scanning ports: {str(e)}"

    async def credit_card_validator(self, card: str) -> str:
        if not card:
            return "Please provide a credit card number."
        card = card.replace(" ", "").replace("-", "")
        if not card.isdigit() or len(card) < 13 or len(card) > 19:
            return "Invalid credit card number format."
        if card in self.credit_card_cache:
            return self.credit_card_cache[card]

        try:
            is_valid = verify(card)
            card_type = "Unknown"
            if card.startswith("4"):
                card_type = "Visa"
            elif card.startswith(("51", "52", "53", "54", "55")):
                card_type = "MasterCard"
            elif card.startswith("34") or card.startswith("37"):
                card_type = "American Express"
            elif card.startswith("6"):
                card_type = "Discover"
            info = [
                f"Card Number: {'*' * (len(card) - 4)}{card[-4:]}",
                f"Valid: {'Yes' if is_valid else 'No'}",
                f"Card Type: {card_type}",
            ]
            result = "\n".join([f"\nCredit Card Validator Results\n{'-' * 40}"] + info)
            self.credit_card_cache[card] = result
            return result
        except Exception as e:
            return f"Error validating credit card: {str(e)}"

    async def zip_code_lookup(self, zip_code: str) -> str:
        if not zip_code:
            return "Please provide a ZIP code."
        if not re.match(r"^\d{5}(-\d{4})?$", zip_code):
            return "Invalid ZIP code format."
        if zip_code in self.zip_code_cache:
            return self.zip_code_cache[zip_code]

        try:
            url = f"https://nominatim.openstreetmap.org/search?postalcode={zip_code}&format=json&limit=1"
            response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
            data = response.json()
            if not data:
                return f"No data found for ZIP code: {zip_code}"
            place = data[0]
            info = [
                f"ZIP Code: {zip_code}",
                f"City: {place.get('display_name', 'N/A').split(',')[0]}",
                f"State: {place.get('address', {}).get('state', 'N/A')}",
                f"Country: {place.get('address', {}).get('country', 'N/A')}",
                f"Latitude: {place.get('lat', 'N/A')}",
                f"Longitude: {place.get('lon', 'N/A')}",
            ]
            if place.get('lat') and place.get('lon'):
                map_file = self.generate_map_html(place['lat'], place['lon'], f"ZIP Code Location: {zip_code}", f"zip_map_{zip_code}_{uuid.uuid4().hex}.html")
                info.append(f"Map: file:///{os.path.abspath(map_file)}")
            result = "\n".join([f"\nZIP Code Lookup Results for: {zip_code}\n{'-' * 40}"] + info)
            self.zip_code_cache[zip_code] = result
            return result
        except requests.RequestException:
            return "Error fetching ZIP code info."

    async def isbn_lookup(self, isbn: str) -> str:
        if not isbn:
            return "Please provide an ISBN."
        isbn = isbn.replace("-", "").replace(" ", "")
        if not (re.match(r"^\d{10}$", isbn) or re.match(r"^\d{13}$", isbn)):
            return "Invalid ISBN format (must be 10 or 13 digits)."
        if isbn in self.isbn_cache:
            return self.isbn_cache[isbn]

        try:
            url = f"https://openlibrary.org/api/books?bibkeys=ISBN:{isbn}&format=json&jscmd=data"
            response = requests.get(url, timeout=5)
            data = response.json()
            book = data.get(f"ISBN:{isbn}", {})
            if not book:
                return f"No book found for ISBN: {isbn}"
            info = [
                f"ISBN: {isbn}",
                f"Title: {book.get('title', 'N/A')}",
                f"Authors: {', '.join(author['name'] for author in book.get('authors', [])) or 'N/A'}",
                f"Publisher: {book.get('publishers', [{}])[0].get('name', 'N/A')}",
                f"Publish Date: {book.get('publish_date', 'N/A')}",
                f"Number of Pages: {book.get('number_of_pages', 'N/A')}",
            ]
            result = "\n".join([f"\nISBN Lookup Results for: {isbn}\n{'-' * 40}"] + info)
            self.isbn_cache[isbn] = result
            return result
        except requests.RequestException:
            return "Error fetching ISBN info."

    async def vehicle_vin_lookup(self, vin: str) -> str:
        if not vin:
            return "Please provide a VIN."
        if not re.match(r"^[A-HJ-NPR-Z0-9]{17}$", vin):
            return "Invalid VIN format (must be 17 alphanumeric characters)."
        if vin in self.vin_cache:
            return self.vin_cache[vin]

        try:
            url = f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVin/{vin}?format=json"
            response = requests.get(url, timeout=5)
            data = response.json()
            results = data.get('Results', [])
            if not results:
                return f"No vehicle found for VIN: {vin}"
            info = [
                f"VIN: {vin}",
                f"Make: {next((r['Value'] for r in results if r['Variable'] == 'Make'), 'N/A')}",
                f"Model: {next((r['Value'] for r in results if r['Variable'] == 'Model'), 'N/A')}",
                f"Year: {next((r['Value'] for r in results if r['Variable'] == 'Model Year'), 'N/A')}",
                f"Manufacturer: {next((r['Value'] for r in results if r['Variable'] == 'Manufacturer Name'), 'N/A')}",
                f"Vehicle Type: {next((r['Value'] for r in results if r['Variable'] == 'Vehicle Type'), 'N/A')}",
            ]
            result = "\n".join([f"\nVehicle VIN Lookup Results for: {vin}\n{'-' * 40}"] + info)
            self.vin_cache[vin] = result
            return result
        except requests.RequestException:
            return "Error fetching VIN info."

    async def hash_checker(self, hash_value: str) -> str:
        if not hash_value:
            return "Please provide a hash value."
        if hash_value in self.hash_cache:
            return self.hash_cache[hash_value]

        try:
            hash_type = None
            if re.match(r"^[a-fA-F0-9]{32}$", hash_value):
                hash_type = "MD5"
            elif re.match(r"^[a-fA-F0-9]{40}$", hash_value):
                hash_type = "SHA1"
            elif re.match(r"^[a-fA-F0-9]{64}$", hash_value):
                hash_type = "SHA256"
            else:
                return "Invalid or unsupported hash format (MD5, SHA1, SHA256 supported)."
            info = [
                f"Hash: {hash_value}",
                f"Type: {hash_type}",
            ]
            result = "\n".join([f"\nHash Checker Results\n{'-' * 40}"] + info)
            self.hash_cache[hash_value] = result
            return result
        except Exception as e:
            return f"Error checking hash: {str(e)}"

    async def ssn_validator(self, ssn: str) -> str:
        if not ssn:
            return "Please provide an SSN."
        if not re.match(r"^\d{3}-\d{2}-\d{4}$", ssn):
            return "Invalid SSN format (use XXX-XX-XXXX)."
        if ssn in self.ssn_cache:
            return self.ssn_cache[ssn]

        area, group, serial = ssn.split('-')
        if area == "000" or area == "666" or int(area) > 899:
            return "Invalid SSN: Area number is invalid."
        if group == "00":
            return "Invalid SSN: Group number is invalid."
        if serial == "0000":
            return "Invalid SSN: Serial number is invalid."
        info = [
            f"SSN: {'*' * 5}{ssn[-4:]}",
            f"Valid Format: Yes",
            f"Note: This is a basic format check. No sensitive data is stored or verified against official databases.",
        ]
        result = "\n".join([f"\nSSN Validator Results\n{'-' * 40}"] + info)
        self.ssn_cache[ssn] = result
        return result

    async def airport_code_lookup(self, code: str) -> str:
        if not code:
            return "Please provide an airport code."
        if not re.match(r"^[A-Z]{3}$", code):
            return "Invalid airport code format (must be 3 letters)."
        if code in self.airport_cache:
            return self.airport_cache[code]

        try:
            url = f"http://api.aviationstack.com/v1/airports?access_key={AVIATIONSTACK_API_KEY}&iata_code={code}"
            response = requests.get(url, timeout=5)
            data = response.json()
            print(f"DEBUG: AviationStack response for {code}: {data}")  # Temporary debug output
            if 'error' in data:
                return f"Error: {data['error'].get('message', 'Unknown error')}"
            airports = data.get('data', [])
            airport = next((a for a in airports if a.get('iata_code') == code), None)
            if not airport:
                return f"No airport found for code: {code}"
            info = [
                f"Airport Code: {code}",
                f"Name: {airport.get('airport_name', 'N/A')}",
                f"City: {airport.get('city', 'N/A')}",
                f"Country: {airport.get('country_name', 'N/A')}",
                f"Latitude: {airport.get('latitude', 'N/A')}",
                f"Longitude: {airport.get('longitude', 'N/A')}",
            ]
            if airport.get('latitude') and airport.get('longitude'):
                map_file = self.generate_map_html(airport['latitude'], airport['longitude'], f"Airport Location: {code}", f"airport_map_{code}_{uuid.uuid4().hex}.html")
                info.append(f"Map: file:///{os.path.abspath(map_file)}")
            result = "\n".join([f"\nAirport Code Lookup Results for: {code}\n{'-' * 40}"] + info)
            self.airport_cache[code] = result
            return result
        except requests.RequestException as e:
            return f"Error fetching airport info: {str(e)}"

    async def time_zone_lookup(self, location: str) -> str:
        if not location:
            return "Please provide a city or coordinates."
        if location in self.timezone_cache:
            return self.timezone_cache[location]

        try:
            if re.match(r"^-?\d+\.?\d*,-?\d+\.?\d*$", location):
                lat, lon = map(float, location.split(','))
            else:
                url = f"https://nominatim.openstreetmap.org/search?q={location}&format=json&limit=1"
                response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
                data = response.json()
                if not data:
                    return f"No location found for: {location}"
                lat, lon = float(data[0]['lat']), float(data[0]['lon'])

            url = f"http://api.timezonedb.com/v2.1/get-time-zone?key={TIMEZONEDB_API_KEY}&format=json&by=position&lat={lat}&lng={lon}"
            response = requests.get(url, timeout=5)
            data = response.json()
            if data.get('status') != 'OK':
                return f"Error: {data.get('message', 'Unknown error')}"
            info = [
                f"Location: {location}",
                f"Time Zone: {data.get('zoneName', 'N/A')}",
                f"GMT Offset: {data.get('gmtOffset', 0) / 3600:.1f} hours",
                f"Current Time: {datetime.datetime.fromtimestamp(data.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')}",
            ]
            result = "\n".join([f"\nTime Zone Lookup Results for: {location}\n{'-' * 40}"] + info)
            self.timezone_cache[location] = result
            return result
        except requests.RequestException:
            return "Error fetching time zone info."

    async def file_hash_validator(self, file_path: str) -> str:
        if not file_path:
            return "Please provide a file path."
        if not os.path.exists(file_path):
            return "File not found."
        if file_path in self.file_hash_cache:
            return self.file_hash_cache[file_path]

        try:
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            info = [
                f"File: {file_path}",
                f"MD5: {md5_hash.hexdigest()}",
                f"SHA1: {sha1_hash.hexdigest()}",
                f"SHA256: {sha256_hash.hexdigest()}",
            ]
            result = "\n".join([f"\nFile Hash Validator Results for: {file_path}\n{'-' * 40}"] + info)
            self.file_hash_cache[file_path] = result
            return result
        except Exception as e:
            return f"Error calculating file hashes: {str(e)}"

# [Previous imports and unchanged code remain the same until the base_options list]

base_options = [
    "Username Lookup",
    "Phone Lookup",
    "Discord Lookup",
    "Steam Lookup",
    "IP Lookup",
    "Email Verify",
    "Domain Lookup",
    "URL Scanner",
    "Email Domain Check",
    "Social Media Lookup",
    "Bitcoin Address Lookup",
    "MAC Address Lookup",
    "Port Scanner",
    "Credit Card Validator",
    "ZIP Code Lookup",
    "ISBN Lookup",
    "Vehicle VIN Lookup",
    "Hash Checker",
    "SSN Validator",
    "Airport Code Lookup",
    "Time Zone Lookup",
    "File Hash Validator"
]

def set_window_size(width=120, height=32):
    """Set the terminal window size to the specified width and height."""
    try:
        if platform.system() == "Windows":
            os.system(f'mode con: cols={width} lines={height}')
        else:
            print(f'\033[8;{height};{width}t', end='')
            os.system(f'resize -s {height} {width} >/dev/null 2>&1')
    except Exception as e:
        print(f"Warning: Could not set window size: {str(e)}")

def get_gradient_color(index, total_lines):
    """Select a color from gradient_colors based on the index and total lines."""
    gradient_length = len(gradient_colors)
    color_index = int((index / total_lines) * (gradient_length - 1))
    r, g, b = gradient_colors[color_index]
    return f"\033[38;2;{r};{g};{b}m"

def display_main_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    try:
        terminal_width = 120 
    except OSError:
        terminal_width = 120

    banner = r"""

 ▄█       ███    █▄  ███▄▄▄▄      ▄████████    ▄████████  ▄██████▄     ▄████████  ▄█  ███▄▄▄▄       ███     
███       ███    ███ ███▀▀▀██▄   ███    ███   ███    ███ ███    ███   ███    ███ ███  ███▀▀▀██▄ ▀█████████▄ 
███       ███    ███ ███   ███   ███    ███   ███    ███ ███    ███   ███    █▀  ███▌ ███   ███    ▀███▀▀██ 
███       ███    ███ ███   ███   ███    ███  ▄███▄▄▄▄██▀ ███    ███   ███        ███▌ ███   ███     ███   ▀ 
███       ███    ███ ███   ███ ▀███████████ ▀▀███▀▀▀▀▀   ███    ███ ▀███████████ ███▌ ███   ███     ███     
███       ███    ███ ███   ███   ███    ███ ▀███████████ ███    ███          ███ ███  ███   ███     ███     
███▌    ▄ ███    ███ ███   ███   ███    ███   ███    ███ ███    ███    ▄█    ███ ███  ███   ███     ███     
█████▄▄██ ████████▀   ▀█   █▀    ███    █▀    ███    ███  ▀██████▀   ▄████████▀  █▀    ▀█   █▀     ▄████▀   
▀                                             ███    ███                                                    

"""
    RESET = "\033[0m"
    WHITE = "\033[38;2;255;255;255m"

    banner_lines = banner.count('\n')
    num_options = len(base_options)
    options_per_column = (num_options + 2) // 3 
    total_lines = banner_lines + 1 + 1 + options_per_column + 1 

    print()
    for line in banner.splitlines():
        print(f"{WHITE}{line.center(terminal_width)}{RESET}")

    color = get_gradient_color(banner_lines, total_lines)
    print(f"\n{color}{'Lookup Options'.center(terminal_width)}{RESET}")
    color = get_gradient_color(banner_lines + 1, total_lines)
    print(f"{color}{'-' * terminal_width}{RESET}")

    col1 = base_options[:options_per_column]
    col2 = base_options[options_per_column:2*options_per_column]
    col3 = base_options[2*options_per_column:]

    max_len = max(len(col1), len(col2), len(col3))
    col1.extend([''] * (max_len - len(col1)))
    col2.extend([''] * (max_len - len(col2)))
    col3.extend([''] * (max_len - len(col3)))

    column_width = terminal_width // 3  
    for i in range(max_len):
        color = get_gradient_color(banner_lines + 2 + i, total_lines)
        opt1 = f"{i+1}. {col1[i]}" if i < len(col1) and col1[i] else ""
        opt2 = f"{i+len(col1)+1}. {col2[i]}" if i < len(col2) and col2[i] else ""
        opt3 = f"{i+len(col1)+len(col2)+1}. {col3[i]}" if i < len(col3) and col3[i] else ""
        line = (
            f"{color}{opt1.ljust(column_width)}{opt2.ljust(column_width)}{opt3.ljust(column_width)}{RESET}"
        )
        print(line.rstrip())

    color = get_gradient_color(banner_lines + 2 + max_len, total_lines)
    print(f"{color}{'-' * terminal_width}{RESET}")
    color = get_gradient_color(banner_lines + 3 + max_len, total_lines)
    print(f"{color}{'0. Exit'.center(terminal_width)}{RESET}")

bot = LookupBot()
def run_async(coro):
    return asyncio.run(coro)

set_window_size(width=120, height=32)  
display_main_menu()
while True:
    print("\nEnter your choice (0-{}): ".format(len(base_options)), end="")
    choice = input().strip()
    if choice == '0':
        print("Exiting...")
        break
    elif choice.isdigit() and 1 <= int(choice) <= len(base_options):
        option_index = int(choice) - 1
        option_name = base_options[option_index]
        os.system('cls' if os.name == 'nt' else 'clear')
        try:
            if option_name == "Username Lookup":
                username = input("Enter username: ").strip()
                print(run_async(bot.username_lookup(username)))
            elif option_name == "Phone Lookup":
                phone = input("Enter phone number (e.g., +12025550123): ").strip()
                print(run_async(bot.phone_lookup(phone)))
            elif option_name == "Discord Lookup":
                discord_id = input("Enter Discord user ID: ").strip()
                print(run_async(bot.discord_lookup(discord_id)))
            elif option_name == "Steam Lookup":
                steam_id = input("Enter SteamID64: ").strip()
                print(run_async(bot.steam_lookup(steam_id)))
            elif option_name == "IP Lookup":
                ip = input("Enter IP address: ").strip()
                print(run_async(bot.ip_lookup(ip)))
            elif option_name == "Email Verify":
                email = input("Enter email address: ").strip()
                print(run_async(bot.email_verify(email)))
            elif option_name == "Domain Lookup":
                domain = input("Enter domain (e.g., example.com): ").strip()
                print(run_async(bot.domain_lookup(domain)))
            elif option_name == "URL Scanner":
                url = input("Enter URL: ").strip()
                print(run_async(bot.url_scanner(url)))
            elif option_name == "Email Domain Check":
                email = input("Enter email address: ").strip()
                print(run_async(bot.email_domain_check(email)))
            elif option_name == "Social Media Lookup":
                username = input("Enter username: ").strip()
                print(run_async(bot.social_media_lookup(username)))
            elif option_name == "Bitcoin Address Lookup":
                address = input("Enter Bitcoin address: ").strip()
                print(run_async(bot.bitcoin_address_lookup(address)))
            elif option_name == "MAC Address Lookup":
                mac = input("Enter MAC address: ").strip()
                print(run_async(bot.mac_address_lookup(mac)))
            elif option_name == "Port Scanner":
                ip = input("Enter IP or domain: ").strip()
                print(run_async(bot.port_scanner(ip)))
            elif option_name == "Credit Card Validator":
                card = input("Enter credit card number: ").strip()
                print(run_async(bot.credit_card_validator(card)))
            elif option_name == "ZIP Code Lookup":
                zip_code = input("Enter ZIP code: ").strip()
                print(run_async(bot.zip_code_lookup(zip_code)))
            elif option_name == "ISBN Lookup":
                isbn = input("Enter ISBN: ").strip()
                print(run_async(bot.isbn_lookup(isbn)))
            elif option_name == "Vehicle VIN Lookup":
                vin = input("Enter VIN: ").strip()
                print(run_async(bot.vehicle_vin_lookup(vin)))
            elif option_name == "Hash Checker":
                hash_value = input("Enter hash: ").strip()
                print(run_async(bot.hash_checker(hash_value)))
            elif option_name == "SSN Validator":
                ssn = input("Enter SSN: ").strip()
                print(run_async(bot.ssn_validator(ssn)))
            elif option_name == "Airport Code Lookup":
                code = input("Enter airport code: ").strip()
                print(run_async(bot.airport_code_lookup(code)))
            elif option_name == "Time Zone Lookup":
                location = input("Enter city or coordinates: ").strip()
                print(run_async(bot.time_zone_lookup(location)))
            elif option_name == "File Hash Validator":
                file_path = input("Enter file path: ").strip()
                print(run_async(bot.file_hash_validator(file_path)))
        except Exception as e:
            print(f"An error occurred: {str(e)}")
        input("\nPress Enter to return to the main menu...")
        display_main_menu()
    else:
        print(f"Invalid choice, please enter a number between 0 and {len(base_options)}.")
