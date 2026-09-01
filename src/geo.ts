import net from "node:net";

export interface GeoLocation {
  status: "success" | "private" | "fail" | "unknown";
  ip?: string;
  country?: string;
  countryCode?: string;
  region?: string;
  regionName?: string;
  city?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  isp?: string;
  org?: string;
  note?: string;
  error?: string;
}

const geoCache = new Map<string, GeoLocation>();

function isPrivateIp(ip: string): boolean {
  if (!ip || !net.isIP(ip)) return false;
  if (ip === "127.0.0.1" || ip === "::1" || ip === "localhost") return true;

  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
  }
  return false;
}

export async function geolocate(ip: string): Promise<GeoLocation> {
  if (!ip) {
    return { status: "unknown", error: "No IP address provided" };
  }

  if (isPrivateIp(ip)) {
    return { status: "private", ip, note: "Private / local network address (RFC 1918)" };
  }

  if (geoCache.has(ip)) {
    return geoCache.get(ip)!;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);

    const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`;
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "mailMeta/2.0 (email-forensics)" },
    });
    clearTimeout(timeout);

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = (await res.json()) as Record<string, any>;
    if (data.status === "success") {
      const geoResult: GeoLocation = {
        status: "success",
        ip: data.query || ip,
        country: data.country,
        countryCode: data.countryCode,
        region: data.region,
        regionName: data.regionName,
        city: data.city,
        lat: data.lat,
        lon: data.lon,
        timezone: data.timezone,
        isp: data.isp,
        org: data.org,
      };
      geoCache.set(ip, geoResult);
      return geoResult;
    } else {
      const failResult: GeoLocation = {
        status: "fail",
        ip,
        note: data.message || "Location lookup failed",
      };
      geoCache.set(ip, failResult);
      return failResult;
    }
  } catch (err: any) {
    // Return gracefully if rate-limited or offline
    const fallback: GeoLocation = {
      status: "unknown",
      ip,
      note: "Location service temporarily unavailable",
    };
    return fallback;
  }
}
