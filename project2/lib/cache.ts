export type StoredScanKey =
  | "cyberregis_integrated"
  | "cyberregis_ips"
  | "cyberregis_logs"
  | "cyberregis_ports"
  | "cyberregis_vuln"
  | "cyberregis_headers"
  | "cyberregis_email";

export interface StoredScan {
  input: string;
  result: any;
  timestamp: string;
}

export const SCHEDULE_STORAGE_KEY = "cyberregis_schedules";

export const loadStoredScans = (key: StoredScanKey): StoredScan[] => {
  if (typeof window === "undefined") {
    return [];
  }

  try {
    const raw = localStorage.getItem(key);
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed as StoredScan[];
    }
    return [];
  } catch (error) {
    console.error("Failed to load stored scans", key, error);
    return [];
  }
};

export const upsertStoredScan = (key: StoredScanKey, entry: StoredScan): StoredScan[] => {
  if (typeof window === "undefined") {
    return [];
  }

  try {
    const stored = loadStoredScans(key);
    const index = stored.findIndex((scan) => scan.input === entry.input);
    if (index >= 0) {
      stored[index] = entry;
    } else {
      stored.push(entry);
    }
    localStorage.setItem(key, JSON.stringify(stored));
    return stored;
  } catch (error) {
    console.error("Failed to persist stored scan", key, error);
    return [];
  }
};

